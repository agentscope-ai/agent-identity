"""Hub-side signing helpers for activity-discovery manifests.

A hub serves three artifacts at its own ``.well-known/`` endpoints:

- ``/.well-known/agent-id-activity-manifest`` — the signed manifest.
- ``/.well-known/agent-id-activity-categories`` — the (unsigned) catalog.
- ``/.well-known/agent-id-activity-schemas/<category>/<version>`` — schemas.

The manifest is JWS-signed in compact serialization (same wire shape as
a JWT) so the activity service can verify it after caching, without
re-fetching. This module is the symmetric counterpart of
:class:`HubManifestFetcher`'s verification path: builds a manifest dict,
validates required fields, signs with the hub's Ed25519 / ES256 key.

Signing alone — the hub still has to build and serve the categories
doc and schemas. Those don't need signing because they're pinned by the
manifest's ``categories_url`` and individual ``schema_url`` fields, and
the manifest itself is signed.
"""

from __future__ import annotations

from typing import Any, Literal

import jwt as pyjwt

# Algorithms accepted for manifest signing. Same set the IdP uses for
# token signing — kept deliberately small.
_ACCEPTED_ALGS: tuple[Literal["EdDSA", "ES256"], ...] = ("EdDSA", "ES256")


_REQUIRED_FIELDS = ("service_id", "namespace", "categories_url", "jwks_url")


class ManifestSigningError(Exception):
    """Raised when the input manifest is missing required fields or
    the signing algorithm is unsupported."""


def build_manifest(
    *,
    service_id: str,
    namespace: str,
    categories_url: str,
    jwks_url: str,
    attested_by: str | None = None,
    aip_version: str = "0.1",
    extra_claims: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Construct an activity-discovery manifest dict in the canonical shape.

    Convenience builder that gets the field set right; signers pass the
    result to :func:`sign_manifest` to produce the wire-form JWS.

    ``extra_claims`` are merged in for forward-compat (e.g., a future
    spec rev adds an optional field). Reserved field names from the
    canonical set cannot be overridden via this kwarg.
    """
    manifest: dict[str, Any] = {
        "service_id": service_id,
        "namespace": namespace,
        "categories_url": categories_url,
        "jwks_url": jwks_url,
        "aip_version": aip_version,
    }
    if attested_by is not None:
        manifest["attested_by"] = attested_by
    if extra_claims:
        for k, v in extra_claims.items():
            if k in manifest:
                raise ManifestSigningError(
                    f"extra_claims may not override canonical field {k!r}"
                )
            manifest[k] = v
    return manifest


def sign_manifest(
    manifest: dict[str, Any],
    *,
    private_key: Any,
    kid: str,
    algorithm: Literal["EdDSA", "ES256"] = "EdDSA",
) -> str:
    """Sign a manifest dict and return the JWS compact serialization.

    Args:
        manifest: Dict with at minimum ``service_id``, ``namespace``,
            ``categories_url``, ``jwks_url``. Use :func:`build_manifest`
            to construct one with the right shape.
        private_key: Ed25519 or ECDSA P-256 private key. Accepts the
            same key types ``pyjwt.encode`` accepts (cryptography lib
            objects or PEM-encoded bytes).
        kid: Key id; MUST match a ``kid`` published in the hub's JWKS.
            The activity service uses this to look up the verification
            key.
        algorithm: ``EdDSA`` (Ed25519) or ``ES256`` (ECDSA P-256).
            Default ``EdDSA`` matches the AIP team's preferred algo.

    Returns:
        The JWS compact serialization string. The hub serves this
        verbatim at ``/.well-known/agent-id-activity-manifest`` with
        ``Content-Type: application/jose``.
    """
    if algorithm not in _ACCEPTED_ALGS:
        raise ManifestSigningError(
            f"algorithm must be one of {_ACCEPTED_ALGS} (got {algorithm!r})"
        )
    missing = [f for f in _REQUIRED_FIELDS if not manifest.get(f)]
    if missing:
        raise ManifestSigningError(
            f"manifest missing required fields: {', '.join(missing)}"
        )
    return pyjwt.encode(
        manifest,
        private_key,
        algorithm=algorithm,
        headers={"kid": kid},
    )


__all__ = [
    "ManifestSigningError",
    "build_manifest",
    "sign_manifest",
]
