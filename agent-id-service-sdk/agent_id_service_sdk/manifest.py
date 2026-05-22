"""Hub manifest discovery client.

Fetches and verifies hub manifests from
``<service_id>/.well-known/agent-id-manifest``. Mirrors the
JWKS-fetcher pattern in :class:`Verifier`: lazy fetch on first use,
cached by ``service_id`` with TTL, JWS signature verified against the
hub's own JWKS (also cached, also lazy).

Used by ``aip-activity``'s ingest path to resolve which Tier-2
namespaces a given hub is allowed to emit, and to validate Tier-2
event payloads against the hub-published JSON Schemas.

This module is the **client** side of the activity-discovery protocol
defined in
``agent-identity/design/2026-05-04-activity-discovery.en.md``. The
**server** side (hub publishing the manifest) lives in
:mod:`agent_id_service_sdk.manifest_signing`.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import httpx
import jwt
from jwt import PyJWK

# Path on the hub's domain where the manifest lives. This is the
# protocol's spelling — same kind of stable convention as
# ``/.well-known/agent-id-jwks``.
WELL_KNOWN_MANIFEST_PATH = "/.well-known/agent-id-manifest"
WELL_KNOWN_JWKS_PATH = "/.well-known/agent-id-jwks"

# Algorithms accepted for manifest signing. Same set the IdP uses for
# token signing; deliberately small.
_ACCEPTED_JWS_ALGS = ["EdDSA", "ES256"]


class HubManifestError(Exception):
    """Base for manifest fetch / verification failures."""


class HubManifestFetchError(HubManifestError):
    """Network failure or non-2xx HTTP response while fetching."""


class HubManifestInvalidError(HubManifestError):
    """Manifest was fetched but failed structural validation."""


class HubManifestSignatureError(HubManifestError):
    """JWS verification failed (bad signature, unknown kid, alg mismatch)."""


@dataclass(frozen=True)
class HubManifest:
    """Verified hub manifest.

    The activity service uses ``service_id`` and ``namespace`` for
    namespace ownership (§6 of the design doc), ``categories_url`` to
    resolve schemas, and ``jwks_url`` to verify subsequent fetches
    cached against the same hub.
    """

    service_id: str
    namespace: str
    categories_url: str
    jwks_url: str
    attested_by: str | None
    aip_version: str
    raw_claims: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CategoryEntry:
    """One ``(category, schema_version)`` entry in a hub's categories doc.

    Multiple versions of the same category coexist for migration
    windows: the catalog lists each one separately. Consumers join on
    ``category`` and pick by ``schema_version`` (or take the latest
    non-deprecated when no specific version is requested).
    """

    category: str
    schema_version: str
    schema_url: str
    schema_format: str = "json-schema"
    deprecated: bool = False
    introduced_at: str | None = None  # ISO-8601
    deprecated_at: str | None = None  # ISO-8601
    sunset_at: str | None = None  # ISO-8601
    sensitive_fields: tuple[str, ...] = ()


@dataclass(frozen=True)
class CategoriesDoc:
    """Parsed catalog from ``manifest.categories_url``.

    Shape matches §3.2 of the activity-discovery design doc. Use
    :meth:`find` to look up a specific ``(category, version)`` tuple.
    """

    service_id: str
    namespace: str
    categories: tuple[CategoryEntry, ...]
    served_at: str | None = None

    def find(self, category: str, version: str | None = None) -> CategoryEntry | None:
        """Return the entry matching ``category`` and (optional) ``version``.

        When ``version`` is ``None`` returns the latest non-deprecated
        entry for the category (or the only entry if all are
        deprecated). Returns ``None`` if the category is unknown.
        """
        candidates = [c for c in self.categories if c.category == category]
        if not candidates:
            return None
        if version is None:
            non_deprecated = [c for c in candidates if not c.deprecated]
            pool = non_deprecated or candidates
            # Return the first; hubs SHOULD list latest-first but the
            # spec doesn't require ordering. v0.4 may add semver sort.
            return pool[0]
        for c in candidates:
            if c.schema_version == version:
                return c
        return None


class HubManifestFetcher:
    """Lazy-fetch, JWS-verify, and cache hub manifests.

    Two caches share TTL semantics:

    - **Manifests** keyed by ``service_id``. Refreshed on miss / TTL
      expiry. Force-refresh available on demand (e.g., when an unknown
      ``schema_version`` shows up and we suspect the hub published a
      new one).
    - **Hub JWKS** keyed by ``service_id``. Same shape as
      :class:`Verifier`'s IdP-JWKS cache; used to verify the manifest
      signature.

    Best-effort by design: callers wrap fetch attempts in try/except
    and decide their own fallback (typically reject the event with 503
    if the hub manifest can't be resolved).
    """

    def __init__(
        self,
        cache_ttl_seconds: int = 3600,
        schema_cache_ttl_seconds: int = 86400,
    ):
        self._cache_ttl = cache_ttl_seconds
        # Pinned ``(category, schema_version)`` URLs are immutable by
        # spec, so the schema cache TTL is much longer than the
        # manifest/categories TTL. Force-refresh available on demand.
        self._schema_cache_ttl = schema_cache_ttl_seconds
        # service_id -> (HubManifest, fetched_at)
        self._manifest_cache: dict[str, tuple[HubManifest, float]] = {}
        # service_id -> ({kid: public_key}, fetched_at)
        self._jwks_cache: dict[str, tuple[dict[str, Any], float]] = {}
        # service_id -> (CategoriesDoc, fetched_at)
        self._categories_cache: dict[str, tuple[CategoriesDoc, float]] = {}
        # (service_id, category, schema_version) -> (schema_dict, fetched_at)
        self._schema_cache: dict[
            tuple[str, str, str], tuple[dict[str, Any], float]
        ] = {}

    # -- public API -----------------------------------------------------------

    async def fetch(
        self,
        service_id: str,
        *,
        force_refresh: bool = False,
    ) -> HubManifest:
        """Return the verified manifest for ``service_id``.

        Args:
            service_id: Hub's public origin (e.g., ``https://api.dojozero.live``).
                Trailing slashes are tolerated; we normalise.
            force_refresh: If True, bypass cache. Used after a hub key
                rotation or when an unexpected ``kid`` shows up.

        Raises:
            HubManifestFetchError: network failure or non-2xx response.
            HubManifestInvalidError: required fields missing or
                ``service_id`` mismatch.
            HubManifestSignatureError: JWS signature didn't verify.
        """
        sid = service_id.rstrip("/")
        now = time.time()
        if not force_refresh:
            cached = self._manifest_cache.get(sid)
            if cached is not None:
                manifest, fetched_at = cached
                if now - fetched_at < self._cache_ttl:
                    return manifest

        manifest = await self._fetch_and_verify_manifest(sid)
        self._manifest_cache[sid] = (manifest, now)
        return manifest

    def cached_manifest(self, service_id: str) -> HubManifest | None:
        """Return the cached manifest if any, ignoring TTL.

        Useful for diagnostics / introspection endpoints. Does not
        trigger a fetch.
        """
        sid = service_id.rstrip("/")
        cached = self._manifest_cache.get(sid)
        return cached[0] if cached is not None else None

    def invalidate(self, service_id: str) -> None:
        """Drop all cached state (manifest, JWKS, categories, schemas) for ``service_id``.

        Forces the next fetch. Useful when an operator has rotated the
        hub's keys out-of-band and wants the activity service to pick
        up the change immediately, or when a hub publishes a manifest
        revision and we want to invalidate any derived caches in one
        shot.
        """
        sid = service_id.rstrip("/")
        self._manifest_cache.pop(sid, None)
        self._jwks_cache.pop(sid, None)
        self._categories_cache.pop(sid, None)
        # Drop every schema entry whose first cache-key element matches
        # this service_id. Linear scan; schema cache is small per hub.
        keys_to_drop = [k for k in self._schema_cache if k[0] == sid]
        for k in keys_to_drop:
            self._schema_cache.pop(k, None)

    async def fetch_categories(
        self,
        service_id: str,
        *,
        force_refresh: bool = False,
    ) -> CategoriesDoc:
        """Return the parsed categories catalog for ``service_id``.

        Calls :meth:`fetch` first to resolve the manifest (and verify
        the hub), then GETs ``manifest.categories_url`` and parses the
        catalog. Cached separately from the manifest with the same TTL
        — `served_at` lets consumers see when the hub regenerated it.

        The activity service uses this to look up the schema URL +
        version for an incoming Tier-2 event before fetching the
        actual JSON Schema.

        Raises:
            HubManifestFetchError: network failure on either fetch.
            HubManifestInvalidError: catalog has wrong shape, or its
                ``namespace`` doesn't match the manifest's namespace.
        """
        sid = service_id.rstrip("/")
        now = time.time()
        if not force_refresh:
            cached = self._categories_cache.get(sid)
            if cached is not None:
                doc, fetched_at = cached
                if now - fetched_at < self._cache_ttl:
                    return doc

        manifest = await self.fetch(service_id)

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(manifest.categories_url)
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPError as exc:
            raise HubManifestFetchError(
                f"failed to fetch categories from {manifest.categories_url}: {exc}"
            ) from exc

        doc = _parse_categories(data, manifest.categories_url)

        # Defence-in-depth: a hub's categories doc must claim the same
        # namespace its manifest claimed. Otherwise a misconfiguration
        # could let a hub serve catalog entries under the wrong prefix.
        if doc.namespace != manifest.namespace:
            raise HubManifestInvalidError(
                f"categories namespace {doc.namespace!r} at "
                f"{manifest.categories_url} does not match manifest namespace "
                f"{manifest.namespace!r}"
            )
        if doc.service_id.rstrip("/") != sid:
            raise HubManifestInvalidError(
                f"categories service_id {doc.service_id!r} does not match "
                f"manifest service_id {sid!r}"
            )

        self._categories_cache[sid] = (doc, now)
        return doc

    async def fetch_schema(
        self,
        service_id: str,
        category: str,
        schema_version: str,
        *,
        force_refresh: bool = False,
    ) -> dict[str, Any]:
        """Return the JSON Schema dict for ``(category, schema_version)``.

        Resolves via the categories catalog: looks up the matching
        :class:`CategoryEntry`, GETs its ``schema_url``, parses as
        JSON. Cached with a longer TTL than the manifest because
        pinned ``(category, version)`` URLs are immutable by spec.

        Raises:
            HubManifestFetchError: network failure.
            HubManifestInvalidError: category/version not in the hub's
                catalog, or the response isn't valid JSON.
        """
        sid = service_id.rstrip("/")
        cache_key = (sid, category, schema_version)
        now = time.time()
        if not force_refresh:
            cached = self._schema_cache.get(cache_key)
            if cached is not None:
                schema, fetched_at = cached
                if now - fetched_at < self._schema_cache_ttl:
                    return schema

        doc = await self.fetch_categories(service_id)
        entry = doc.find(category, schema_version)
        if entry is None:
            raise HubManifestInvalidError(
                f"category {category}@{schema_version!r} not found in hub's "
                f"catalog at {service_id}"
            )

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(entry.schema_url)
                resp.raise_for_status()
                schema = resp.json()
        except httpx.HTTPError as exc:
            raise HubManifestFetchError(
                f"failed to fetch schema from {entry.schema_url}: {exc}"
            ) from exc
        except ValueError as exc:
            raise HubManifestInvalidError(
                f"schema at {entry.schema_url} is not valid JSON: {exc}"
            ) from exc

        if not isinstance(schema, dict):
            raise HubManifestInvalidError(
                f"schema at {entry.schema_url} must be a JSON object "
                f"(got {type(schema).__name__})"
            )

        self._schema_cache[cache_key] = (schema, now)
        return schema

    # -- internals ------------------------------------------------------------

    async def _fetch_and_verify_manifest(self, service_id: str) -> HubManifest:
        manifest_url = f"{service_id}{WELL_KNOWN_MANIFEST_PATH}"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(manifest_url)
                resp.raise_for_status()
                jws = resp.text.strip()
        except httpx.HTTPError as exc:
            raise HubManifestFetchError(
                f"failed to fetch manifest from {manifest_url}: {exc}"
            ) from exc

        # The manifest is served as a JWS Compact Serialization string —
        # same wire shape as a JWT. We need the unverified header to
        # find which key to verify against.
        try:
            unverified_header = jwt.get_unverified_header(jws)
        except jwt.exceptions.DecodeError as exc:
            raise HubManifestInvalidError(
                f"manifest at {manifest_url} is not a valid JWS: {exc}"
            ) from exc

        kid = unverified_header.get("kid")
        if not kid:
            raise HubManifestInvalidError(
                f"manifest at {manifest_url} JWS header missing 'kid'"
            )

        # Get the hub's JWKS so we can verify. Note we don't trust
        # anything in the manifest until after signature verification —
        # so jwks_url comes from the *unverified* manifest payload, but
        # that's fine: even if it lies, we'd just fail to verify.
        try:
            unverified_payload = jwt.decode(jws, options={"verify_signature": False})
        except jwt.exceptions.DecodeError as exc:
            raise HubManifestInvalidError(
                f"manifest at {manifest_url} payload not decodable: {exc}"
            ) from exc

        jwks_url = unverified_payload.get("jwks_url")
        if not isinstance(jwks_url, str) or not jwks_url:
            raise HubManifestInvalidError(
                f"manifest at {manifest_url} missing 'jwks_url'"
            )

        keys = await self._fetch_jwks(jwks_url, service_id)
        public_key = keys.get(kid)
        if public_key is None:
            # Try a force refresh in case the hub rotated keys since we
            # last cached. Mirrors verifier's kid-miss recovery path.
            keys = await self._fetch_jwks(jwks_url, service_id, force_refresh=True)
            public_key = keys.get(kid)
        if public_key is None:
            raise HubManifestSignatureError(
                f"manifest signing key {kid!r} not found in hub JWKS at {jwks_url}"
            )

        # Verify the JWS signature against the resolved public key.
        try:
            verified_payload = jwt.decode(
                jws,
                public_key,
                algorithms=_ACCEPTED_JWS_ALGS,
                options={"verify_aud": False, "verify_exp": False},
            )
        except jwt.PyJWTError as exc:
            raise HubManifestSignatureError(
                f"manifest at {manifest_url} JWS verification failed: {exc}"
            ) from exc

        # Now that we trust the payload, validate the required fields.
        manifest = _parse_manifest(verified_payload, manifest_url)

        # Defence-in-depth: the verified manifest's service_id MUST
        # match the URL we fetched from. Otherwise a hub at evil.com
        # could publish a manifest claiming to be at api.dojozero.live.
        if manifest.service_id.rstrip("/") != service_id:
            raise HubManifestInvalidError(
                f"manifest service_id {manifest.service_id!r} does not match "
                f"fetch origin {service_id!r}"
            )
        return manifest

    async def _fetch_jwks(
        self,
        jwks_url: str,
        service_id: str,
        *,
        force_refresh: bool = False,
    ) -> dict[str, Any]:
        """Fetch and cache the hub's JWKS, keyed by ``service_id``.

        We key by ``service_id`` rather than ``jwks_url`` so cache
        invalidation aligns with hub identity (one hub = one cache
        entry). Multiple manifests pointing at the same JWKS URL would
        share keys naturally because they'd share the same
        ``service_id``.
        """
        now = time.time()
        if not force_refresh:
            cached = self._jwks_cache.get(service_id)
            if cached is not None:
                keys, fetched_at = cached
                if now - fetched_at < self._cache_ttl:
                    return keys

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(jwks_url)
                resp.raise_for_status()
                jwks_data = resp.json()
        except httpx.HTTPError as exc:
            raise HubManifestFetchError(
                f"failed to fetch hub JWKS from {jwks_url}: {exc}"
            ) from exc

        keys: dict[str, Any] = {}
        for key_data in jwks_data.get("keys", []):
            kty = key_data.get("kty")
            kid = key_data.get("kid")
            if not kid:
                continue
            if kty == "EC" and key_data.get("crv") == "P-256":
                keys[kid] = PyJWK(key_data).key
            elif kty == "OKP" and key_data.get("crv") == "Ed25519":
                keys[kid] = PyJWK(key_data).key

        self._jwks_cache[service_id] = (keys, now)
        return keys


def _parse_categories(payload: dict[str, Any], source_url: str) -> CategoriesDoc:
    """Validate categories doc shape and construct a CategoriesDoc.

    Tolerant: unknown fields on entries are silently dropped (forward
    compat). Required fields per entry: ``category``, ``schema_version``,
    ``schema_url``. Doc-level required: ``service_id``, ``namespace``,
    ``categories``.
    """
    if not isinstance(payload, dict):
        raise HubManifestInvalidError(
            f"categories doc at {source_url} must be a JSON object"
        )

    def _required_str(key: str) -> str:
        v = payload.get(key)
        if not isinstance(v, str) or not v:
            raise HubManifestInvalidError(
                f"categories doc at {source_url} missing or non-string {key!r}"
            )
        return v

    raw_entries = payload.get("categories")
    if not isinstance(raw_entries, list):
        raise HubManifestInvalidError(
            f"categories doc at {source_url} missing or non-list 'categories'"
        )

    entries: list[CategoryEntry] = []
    for i, raw in enumerate(raw_entries):
        if not isinstance(raw, dict):
            raise HubManifestInvalidError(
                f"categories doc at {source_url} entry {i} is not an object"
            )
        for required in ("category", "schema_version", "schema_url"):
            v = raw.get(required)
            if not isinstance(v, str) or not v:
                raise HubManifestInvalidError(
                    f"categories doc at {source_url} entry {i} missing "
                    f"or non-string {required!r}"
                )
        sensitive = raw.get("sensitive_fields", [])
        if not isinstance(sensitive, list):
            sensitive = []
        entries.append(
            CategoryEntry(
                category=raw["category"],
                schema_version=raw["schema_version"],
                schema_url=raw["schema_url"],
                schema_format=raw.get("schema_format") or "json-schema",
                deprecated=bool(raw.get("deprecated", False)),
                introduced_at=raw.get("introduced_at")
                if isinstance(raw.get("introduced_at"), str)
                else None,
                deprecated_at=raw.get("deprecated_at")
                if isinstance(raw.get("deprecated_at"), str)
                else None,
                sunset_at=raw.get("sunset_at")
                if isinstance(raw.get("sunset_at"), str)
                else None,
                sensitive_fields=tuple(s for s in sensitive if isinstance(s, str)),
            )
        )

    return CategoriesDoc(
        service_id=_required_str("service_id"),
        namespace=_required_str("namespace"),
        categories=tuple(entries),
        served_at=payload.get("served_at")
        if isinstance(payload.get("served_at"), str)
        else None,
    )


def _parse_manifest(payload: dict[str, Any], source_url: str) -> HubManifest:
    """Validate required fields and construct a HubManifest.

    Raises HubManifestInvalidError if any required field is missing or
    has the wrong type.
    """

    def _required(key: str) -> str:
        v = payload.get(key)
        if not isinstance(v, str) or not v:
            raise HubManifestInvalidError(
                f"manifest at {source_url} missing or non-string {key!r}"
            )
        return v

    return HubManifest(
        service_id=_required("service_id"),
        namespace=_required("namespace"),
        categories_url=_required("categories_url"),
        jwks_url=_required("jwks_url"),
        attested_by=(
            payload.get("attested_by")
            if isinstance(payload.get("attested_by"), str)
            else None
        ),
        aip_version=_required("aip_version"),
        raw_claims=dict(payload),
    )


__all__ = [
    "CategoryEntry",
    "CategoriesDoc",
    "HubManifest",
    "HubManifestError",
    "HubManifestFetchError",
    "HubManifestFetcher",
    "HubManifestInvalidError",
    "HubManifestSignatureError",
    "WELL_KNOWN_JWKS_PATH",
    "WELL_KNOWN_MANIFEST_PATH",
]
