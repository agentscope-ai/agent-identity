"""Tests for HubManifestFetcher.

End-to-end-ish: we build a real JWS-signed manifest with a real
Ed25519 keypair, mock the HTTP layer, and run the fetcher's verify
path. Cache hit/miss semantics are tested by manipulating the cache
dicts directly (mirrors test_verifier.py's pattern).
"""

from __future__ import annotations

import json
import time
from base64 import urlsafe_b64encode
from unittest.mock import AsyncMock, patch

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_id_service_sdk.manifest import (
    CategoriesDoc,
    CategoryEntry,
    HubManifest,
    HubManifestFetcher,
    HubManifestInvalidError,
    HubManifestSignatureError,
)


SERVICE_ID = "https://api.dojozero.live"
NAMESPACE = "dojozero"
JWKS_URL = f"{SERVICE_ID}/.well-known/agent-id-jwks"
CATEGORIES_URL = f"{SERVICE_ID}/.well-known/agent-id-activity-categories"
KID = "hub-key-1"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_keypair():
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def _public_key_to_jwk(public_key, kid: str = KID) -> dict:
    """Encode an Ed25519 public key as an OKP JWK (matches what the hub serves)."""
    raw = public_key.public_bytes_raw()
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "kid": kid,
        "x": urlsafe_b64encode(raw).rstrip(b"=").decode("ascii"),
    }


def _sign_manifest(private_key, manifest_dict: dict, kid: str = KID) -> str:
    """JWS-encode a manifest dict (Ed25519 / EdDSA)."""
    return pyjwt.encode(
        manifest_dict,
        private_key,
        algorithm="EdDSA",
        headers={"kid": kid},
    )


def _valid_manifest_dict(**overrides) -> dict:
    base = {
        "service_id": SERVICE_ID,
        "namespace": NAMESPACE,
        "categories_url": CATEGORIES_URL,
        "jwks_url": JWKS_URL,
        "aip_version": "0.1",
    }
    base.update(overrides)
    return base


def _http_response(status: int = 200, text: str = "", json_body=None):
    """Build a minimal stub response matching httpx.Response's surface used by the fetcher."""
    resp = AsyncMock()
    resp.status_code = status
    resp.text = text
    resp.raise_for_status = lambda: None if 200 <= status < 300 else _raise_http(status)
    if json_body is not None:
        resp.json = lambda: json_body
    return resp


def _raise_http(status: int):
    import httpx

    req = httpx.Request("GET", "http://test")
    raise httpx.HTTPStatusError(
        f"HTTP {status}",
        request=req,
        response=httpx.Response(status, request=req),
    )


def _patch_http(jws: str, jwks_dict: dict):
    """Patch httpx.AsyncClient so manifest GET returns the JWS, JWKS GET returns the keys."""

    def _build_client(*args, **kwargs):
        client = AsyncMock()

        async def _aenter(*_a, **_kw):
            return client

        async def _aexit(*_a, **_kw):
            return None

        client.__aenter__ = _aenter
        client.__aexit__ = _aexit

        async def _get(url, *_a, **_kw):
            if url.endswith("/agent-id-manifest"):
                return _http_response(200, text=jws)
            if url.endswith("/agent-id-jwks"):
                return _http_response(200, json_body=jwks_dict)
            return _http_response(404, text="not found")

        client.get = _get
        return client

    return patch("httpx.AsyncClient", side_effect=_build_client)


# ---------------------------------------------------------------------------
# Tests — happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fetch_verifies_signature_and_caches():
    private_key, public_key = _make_keypair()
    jws = _sign_manifest(private_key, _valid_manifest_dict())
    jwks = {"keys": [_public_key_to_jwk(public_key)]}

    fetcher = HubManifestFetcher()
    with _patch_http(jws, jwks):
        manifest = await fetcher.fetch(SERVICE_ID)

    assert isinstance(manifest, HubManifest)
    assert manifest.service_id == SERVICE_ID
    assert manifest.namespace == NAMESPACE
    assert manifest.categories_url == CATEGORIES_URL
    assert manifest.jwks_url == JWKS_URL
    assert manifest.aip_version == "0.1"
    assert manifest.attested_by is None

    # Cache hit returns the same object without re-fetching.
    second = await fetcher.fetch(SERVICE_ID)
    assert second is manifest


@pytest.mark.asyncio
async def test_force_refresh_bypasses_cache():
    private_key, public_key = _make_keypair()
    jws = _sign_manifest(private_key, _valid_manifest_dict())
    jwks = {"keys": [_public_key_to_jwk(public_key)]}

    fetcher = HubManifestFetcher()
    with _patch_http(jws, jwks):
        first = await fetcher.fetch(SERVICE_ID)
        # Mutate the cache to a sentinel; force_refresh should overwrite.
        sentinel = HubManifest(
            service_id="https://stale.example",
            namespace="stale",
            categories_url="",
            jwks_url="",
            attested_by=None,
            aip_version="0",
        )
        fetcher._manifest_cache[SERVICE_ID] = (sentinel, time.time())
        second = await fetcher.fetch(SERVICE_ID, force_refresh=True)

    assert second.service_id == SERVICE_ID
    assert second is not sentinel
    assert second is not first  # came from network, not the original cache


@pytest.mark.asyncio
async def test_attested_by_optional_field_carried_through():
    private_key, public_key = _make_keypair()
    jws = _sign_manifest(
        private_key,
        _valid_manifest_dict(attested_by="agentid:pre.agent-id.live:org_xyz"),
    )
    jwks = {"keys": [_public_key_to_jwk(public_key)]}

    fetcher = HubManifestFetcher()
    with _patch_http(jws, jwks):
        manifest = await fetcher.fetch(SERVICE_ID)
    assert manifest.attested_by == "agentid:pre.agent-id.live:org_xyz"


# ---------------------------------------------------------------------------
# Tests — sad paths
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_signature_invalid_raises_signature_error():
    private_key, public_key = _make_keypair()
    other_private_key, _ = _make_keypair()  # signed by the wrong key
    jws = _sign_manifest(other_private_key, _valid_manifest_dict())
    jwks = {"keys": [_public_key_to_jwk(public_key)]}

    fetcher = HubManifestFetcher()
    with _patch_http(jws, jwks):
        with pytest.raises(HubManifestSignatureError):
            await fetcher.fetch(SERVICE_ID)


@pytest.mark.asyncio
async def test_unknown_kid_in_manifest_raises_signature_error():
    private_key, public_key = _make_keypair()
    jws = _sign_manifest(private_key, _valid_manifest_dict(), kid="unknown-kid")
    jwks = {"keys": [_public_key_to_jwk(public_key)]}  # only KID="hub-key-1"

    fetcher = HubManifestFetcher()
    with _patch_http(jws, jwks):
        with pytest.raises(HubManifestSignatureError):
            await fetcher.fetch(SERVICE_ID)


@pytest.mark.asyncio
async def test_service_id_mismatch_rejects():
    """Hub claiming a different service_id than the URL we fetched from is bad."""
    private_key, public_key = _make_keypair()
    jws = _sign_manifest(
        private_key,
        _valid_manifest_dict(service_id="https://evil.example.com"),
    )
    jwks = {"keys": [_public_key_to_jwk(public_key)]}

    fetcher = HubManifestFetcher()
    with _patch_http(jws, jwks):
        with pytest.raises(HubManifestInvalidError):
            await fetcher.fetch(SERVICE_ID)


@pytest.mark.asyncio
async def test_missing_required_field_rejects():
    private_key, public_key = _make_keypair()
    bad_manifest = _valid_manifest_dict()
    del bad_manifest["namespace"]
    jws = _sign_manifest(private_key, bad_manifest)
    jwks = {"keys": [_public_key_to_jwk(public_key)]}

    fetcher = HubManifestFetcher()
    with _patch_http(jws, jwks):
        with pytest.raises(HubManifestInvalidError, match="namespace"):
            await fetcher.fetch(SERVICE_ID)


@pytest.mark.asyncio
async def test_manifest_not_a_jws_rejects():
    """Hub serving raw JSON instead of JWS at the well-known URL."""
    fetcher = HubManifestFetcher()
    raw_json = json.dumps(_valid_manifest_dict())
    with _patch_http(raw_json, {"keys": []}):
        with pytest.raises(HubManifestInvalidError):
            await fetcher.fetch(SERVICE_ID)


@pytest.mark.asyncio
async def test_jwks_url_missing_in_payload_rejects():
    private_key, _ = _make_keypair()
    bad = _valid_manifest_dict()
    del bad["jwks_url"]
    jws = _sign_manifest(private_key, bad)

    fetcher = HubManifestFetcher()
    with _patch_http(jws, {"keys": []}):
        with pytest.raises(HubManifestInvalidError, match="jwks_url"):
            await fetcher.fetch(SERVICE_ID)


# ---------------------------------------------------------------------------
# Cache utilities
# ---------------------------------------------------------------------------


def test_cached_manifest_returns_none_when_no_cache():
    fetcher = HubManifestFetcher()
    assert fetcher.cached_manifest(SERVICE_ID) is None


def test_invalidate_drops_caches():
    fetcher = HubManifestFetcher()
    sentinel = HubManifest(
        service_id=SERVICE_ID,
        namespace="x",
        categories_url="",
        jwks_url="",
        attested_by=None,
        aip_version="0",
    )
    fetcher._manifest_cache[SERVICE_ID] = (sentinel, time.time())
    fetcher._jwks_cache[SERVICE_ID] = ({"k": object()}, time.time())

    fetcher.invalidate(SERVICE_ID)

    assert SERVICE_ID not in fetcher._manifest_cache
    assert SERVICE_ID not in fetcher._jwks_cache


def test_trailing_slash_normalised():
    fetcher = HubManifestFetcher()
    sentinel = HubManifest(
        service_id=SERVICE_ID,
        namespace="x",
        categories_url="",
        jwks_url="",
        attested_by=None,
        aip_version="0",
    )
    fetcher._manifest_cache[SERVICE_ID] = (sentinel, time.time())
    # Caller that includes a trailing slash should hit the same cache entry.
    assert fetcher.cached_manifest(SERVICE_ID + "/") is sentinel


# ---------------------------------------------------------------------------
# CategoriesDoc + categories/schema fetching
# ---------------------------------------------------------------------------


_BET_DECISION_SCHEMA = {
    "type": "object",
    "properties": {
        "decision": {"type": "string"},
        "confidence": {"type": "number"},
        "market_hash": {"type": "string"},
    },
    "required": ["decision", "confidence"],
}


def _categories_doc_dict(**overrides) -> dict:
    base = {
        "service_id": SERVICE_ID,
        "namespace": NAMESPACE,
        "categories": [
            {
                "category": "dojozero.bet_decision",
                "schema_version": "1.0.0",
                "schema_url": f"{SERVICE_ID}/.well-known/agent-id-activity-schemas/bet_decision/1.0.0",
                "schema_format": "json-schema",
                "deprecated": False,
                "introduced_at": "2026-05-04T00:00:00Z",
                "sensitive_fields": ["market_hash"],
            },
        ],
        "served_at": "2026-05-04T12:00:00Z",
    }
    base.update(overrides)
    return base


def _patch_full_chain(
    jws: str, jwks: dict, categories: dict, schemas: dict | None = None
):
    """Patch httpx.AsyncClient to serve manifest, JWKS, categories doc, and any schemas.

    ``schemas`` maps a path-suffix (e.g. ``"bet_decision/1.0.0"``) to a JSON
    Schema dict; the mock matches by URL endswith.
    """
    schemas = schemas or {}

    def _build_client(*_args, **_kwargs):
        client = AsyncMock()

        async def _aenter(*_a, **_kw):
            return client

        async def _aexit(*_a, **_kw):
            return None

        client.__aenter__ = _aenter
        client.__aexit__ = _aexit

        async def _get(url, *_a, **_kw):
            resp = AsyncMock()
            resp.status_code = 200
            resp.raise_for_status = lambda: None
            if url.endswith("/agent-id-manifest"):
                resp.text = jws
            elif url.endswith("/agent-id-jwks"):
                resp.json = lambda: jwks
            elif url.endswith("/agent-id-activity-categories"):
                resp.json = lambda: categories
            else:
                # Schema URL match: look up by path suffix.
                for suffix, schema in schemas.items():
                    if url.endswith(suffix):
                        resp.json = lambda s=schema: s
                        break
                else:
                    resp.status_code = 404
                    resp.json = lambda: {}
            return resp

        client.get = _get
        return client

    return patch("httpx.AsyncClient", side_effect=_build_client)


# ---- CategoriesDoc.find ---------------------------------------------------


class TestCategoriesDocFind:
    def test_find_specific_version(self):
        doc = CategoriesDoc(
            service_id=SERVICE_ID,
            namespace=NAMESPACE,
            categories=(
                CategoryEntry(category="x.y", schema_version="1.0.0", schema_url="u1"),
                CategoryEntry(category="x.y", schema_version="2.0.0", schema_url="u2"),
            ),
        )
        entry = doc.find("x.y", "2.0.0")
        assert entry is not None and entry.schema_url == "u2"

    def test_find_no_version_picks_non_deprecated(self):
        doc = CategoriesDoc(
            service_id=SERVICE_ID,
            namespace=NAMESPACE,
            categories=(
                CategoryEntry(
                    category="x.y",
                    schema_version="1.0.0",
                    schema_url="u1",
                    deprecated=True,
                ),
                CategoryEntry(
                    category="x.y",
                    schema_version="2.0.0",
                    schema_url="u2",
                    deprecated=False,
                ),
            ),
        )
        entry = doc.find("x.y")
        assert entry is not None and entry.schema_version == "2.0.0"

    def test_find_returns_none_for_unknown_category(self):
        doc = CategoriesDoc(service_id=SERVICE_ID, namespace=NAMESPACE, categories=())
        assert doc.find("missing") is None


# ---- fetch_categories -----------------------------------------------------


@pytest.mark.asyncio
async def test_fetch_categories_happy_path():
    private_key, public_key = _make_keypair()
    jws = _sign_manifest(private_key, _valid_manifest_dict())
    jwks = {"keys": [_public_key_to_jwk(public_key)]}
    categories = _categories_doc_dict()

    fetcher = HubManifestFetcher()
    with _patch_full_chain(jws, jwks, categories):
        doc = await fetcher.fetch_categories(SERVICE_ID)

    assert doc.namespace == NAMESPACE
    assert doc.service_id == SERVICE_ID
    assert len(doc.categories) == 1
    entry = doc.categories[0]
    assert entry.category == "dojozero.bet_decision"
    assert entry.schema_version == "1.0.0"
    assert entry.schema_format == "json-schema"
    assert entry.deprecated is False
    assert entry.sensitive_fields == ("market_hash",)


@pytest.mark.asyncio
async def test_fetch_categories_namespace_mismatch_rejected():
    """Catalog can't claim a different namespace from the manifest."""
    private_key, public_key = _make_keypair()
    jws = _sign_manifest(private_key, _valid_manifest_dict())
    jwks = {"keys": [_public_key_to_jwk(public_key)]}
    bad_categories = _categories_doc_dict(namespace="not-dojozero")

    fetcher = HubManifestFetcher()
    with _patch_full_chain(jws, jwks, bad_categories):
        with pytest.raises(HubManifestInvalidError, match="namespace"):
            await fetcher.fetch_categories(SERVICE_ID)


@pytest.mark.asyncio
async def test_fetch_categories_cached():
    private_key, public_key = _make_keypair()
    jws = _sign_manifest(private_key, _valid_manifest_dict())
    jwks = {"keys": [_public_key_to_jwk(public_key)]}
    categories = _categories_doc_dict()

    fetcher = HubManifestFetcher()
    with _patch_full_chain(jws, jwks, categories):
        first = await fetcher.fetch_categories(SERVICE_ID)
        second = await fetcher.fetch_categories(SERVICE_ID)
    assert first is second  # cache hit, no re-fetch


@pytest.mark.asyncio
async def test_fetch_categories_rejects_missing_required_field():
    private_key, public_key = _make_keypair()
    jws = _sign_manifest(private_key, _valid_manifest_dict())
    jwks = {"keys": [_public_key_to_jwk(public_key)]}
    bad = _categories_doc_dict()
    del bad["categories"][0]["schema_url"]

    fetcher = HubManifestFetcher()
    with _patch_full_chain(jws, jwks, bad):
        with pytest.raises(HubManifestInvalidError, match="schema_url"):
            await fetcher.fetch_categories(SERVICE_ID)


# ---- fetch_schema ---------------------------------------------------------


@pytest.mark.asyncio
async def test_fetch_schema_happy_path():
    private_key, public_key = _make_keypair()
    jws = _sign_manifest(private_key, _valid_manifest_dict())
    jwks = {"keys": [_public_key_to_jwk(public_key)]}
    categories = _categories_doc_dict()
    schemas = {"bet_decision/1.0.0": _BET_DECISION_SCHEMA}

    fetcher = HubManifestFetcher()
    with _patch_full_chain(jws, jwks, categories, schemas):
        schema = await fetcher.fetch_schema(
            SERVICE_ID, "dojozero.bet_decision", "1.0.0"
        )
    assert schema == _BET_DECISION_SCHEMA


@pytest.mark.asyncio
async def test_fetch_schema_unknown_category_rejects():
    private_key, public_key = _make_keypair()
    jws = _sign_manifest(private_key, _valid_manifest_dict())
    jwks = {"keys": [_public_key_to_jwk(public_key)]}
    categories = _categories_doc_dict()

    fetcher = HubManifestFetcher()
    with _patch_full_chain(jws, jwks, categories):
        with pytest.raises(HubManifestInvalidError, match="not found"):
            await fetcher.fetch_schema(SERVICE_ID, "dojozero.unknown", "1.0.0")


@pytest.mark.asyncio
async def test_fetch_schema_unknown_version_rejects():
    private_key, public_key = _make_keypair()
    jws = _sign_manifest(private_key, _valid_manifest_dict())
    jwks = {"keys": [_public_key_to_jwk(public_key)]}
    categories = _categories_doc_dict()

    fetcher = HubManifestFetcher()
    with _patch_full_chain(jws, jwks, categories):
        with pytest.raises(HubManifestInvalidError, match="not found"):
            await fetcher.fetch_schema(SERVICE_ID, "dojozero.bet_decision", "9.9.9")


@pytest.mark.asyncio
async def test_fetch_schema_caches_pinned_version():
    """Schemas have their own (longer) cache TTL because pinned versions are immutable."""
    private_key, public_key = _make_keypair()
    jws = _sign_manifest(private_key, _valid_manifest_dict())
    jwks = {"keys": [_public_key_to_jwk(public_key)]}
    categories = _categories_doc_dict()
    schemas = {"bet_decision/1.0.0": _BET_DECISION_SCHEMA}

    fetcher = HubManifestFetcher()
    with _patch_full_chain(jws, jwks, categories, schemas):
        first = await fetcher.fetch_schema(SERVICE_ID, "dojozero.bet_decision", "1.0.0")
        second = await fetcher.fetch_schema(
            SERVICE_ID, "dojozero.bet_decision", "1.0.0"
        )
    # Same dict object on second call — cache hit.
    assert first is second


@pytest.mark.asyncio
async def test_invalidate_clears_categories_and_schemas():
    fetcher = HubManifestFetcher()
    sentinel_cats = CategoriesDoc(
        service_id=SERVICE_ID, namespace=NAMESPACE, categories=()
    )
    fetcher._categories_cache[SERVICE_ID] = (sentinel_cats, time.time())
    fetcher._schema_cache[(SERVICE_ID, "x.y", "1.0.0")] = (
        {"a": 1},
        time.time(),
    )

    fetcher.invalidate(SERVICE_ID)

    assert SERVICE_ID not in fetcher._categories_cache
    assert (SERVICE_ID, "x.y", "1.0.0") not in fetcher._schema_cache
