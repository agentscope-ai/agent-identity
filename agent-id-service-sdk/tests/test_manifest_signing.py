"""Tests for manifest signing helpers + round-trip with HubManifestFetcher.

The most valuable test here is the end-to-end round trip: build → sign
→ fetch (verify) → parsed manifest matches the input. If that works,
the wire format is consistent across the hub-side and verifier-side
SDKs.
"""

from __future__ import annotations

from base64 import urlsafe_b64encode
from unittest.mock import AsyncMock, patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_id_service_sdk.manifest import HubManifestFetcher
from agent_id_service_sdk.manifest_signing import (
    ManifestSigningError,
    build_manifest,
    generate_signing_keypair,
    public_key_to_jwk,
    sign_manifest,
)


SERVICE_ID = "https://api.dojozero.live"
NAMESPACE = "dojozero"
JWKS_URL = f"{SERVICE_ID}/.well-known/agent-id-jwks"
CATEGORIES_URL = f"{SERVICE_ID}/.well-known/agent-id-activity-categories"
KID = "hub-key-1"


def _public_key_to_jwk(public_key, kid: str = KID) -> dict:
    raw = public_key.public_bytes_raw()
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "kid": kid,
        "x": urlsafe_b64encode(raw).rstrip(b"=").decode("ascii"),
    }


# ---------------------------------------------------------------------------
# build_manifest
# ---------------------------------------------------------------------------


class TestBuildManifest:
    def test_minimal_manifest(self):
        m = build_manifest(
            service_id=SERVICE_ID,
            namespace=NAMESPACE,
            categories_url=CATEGORIES_URL,
            jwks_url=JWKS_URL,
        )
        assert m == {
            "service_id": SERVICE_ID,
            "namespace": NAMESPACE,
            "categories_url": CATEGORIES_URL,
            "jwks_url": JWKS_URL,
            "aip_version": "0.1",
        }

    def test_attested_by_included_when_set(self):
        m = build_manifest(
            service_id=SERVICE_ID,
            namespace=NAMESPACE,
            categories_url=CATEGORIES_URL,
            jwks_url=JWKS_URL,
            attested_by="agentid:pre.agent-id.live:org_xyz",
        )
        assert m["attested_by"] == "agentid:pre.agent-id.live:org_xyz"

    def test_extra_claims_merged(self):
        m = build_manifest(
            service_id=SERVICE_ID,
            namespace=NAMESPACE,
            categories_url=CATEGORIES_URL,
            jwks_url=JWKS_URL,
            extra_claims={"future_field": "value"},
        )
        assert m["future_field"] == "value"

    def test_extra_claims_cannot_override_canonical(self):
        with pytest.raises(ManifestSigningError, match="canonical field"):
            build_manifest(
                service_id=SERVICE_ID,
                namespace=NAMESPACE,
                categories_url=CATEGORIES_URL,
                jwks_url=JWKS_URL,
                extra_claims={"namespace": "evil"},
            )


# ---------------------------------------------------------------------------
# sign_manifest
# ---------------------------------------------------------------------------


class TestSignManifest:
    def test_signs_with_eddsa(self):
        private_key = Ed25519PrivateKey.generate()
        m = build_manifest(
            service_id=SERVICE_ID,
            namespace=NAMESPACE,
            categories_url=CATEGORIES_URL,
            jwks_url=JWKS_URL,
        )
        jws = sign_manifest(m, private_key=private_key, kid=KID)
        # Compact JWS: <header>.<payload>.<signature>
        assert jws.count(".") == 2

    def test_unknown_algorithm_rejected(self):
        private_key = Ed25519PrivateKey.generate()
        m = build_manifest(
            service_id=SERVICE_ID,
            namespace=NAMESPACE,
            categories_url=CATEGORIES_URL,
            jwks_url=JWKS_URL,
        )
        with pytest.raises(ManifestSigningError, match="algorithm must be"):
            sign_manifest(m, private_key=private_key, kid=KID, algorithm="HS256")  # type: ignore[arg-type]

    def test_missing_required_field_rejected_before_signing(self):
        private_key = Ed25519PrivateKey.generate()
        with pytest.raises(ManifestSigningError, match="missing required fields"):
            sign_manifest(
                {"service_id": SERVICE_ID},  # everything else missing
                private_key=private_key,
                kid=KID,
            )


# ---------------------------------------------------------------------------
# Round trip — sign + fetch + verify
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_round_trip_sign_then_verify_via_fetcher():
    """The most important test: a manifest built + signed by these
    helpers must verify cleanly via HubManifestFetcher with no field
    drift."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    manifest_dict = build_manifest(
        service_id=SERVICE_ID,
        namespace=NAMESPACE,
        categories_url=CATEGORIES_URL,
        jwks_url=JWKS_URL,
        attested_by="agentid:pre.agent-id.live:org_dojozero",
    )
    jws = sign_manifest(manifest_dict, private_key=private_key, kid=KID)
    jwks = {"keys": [_public_key_to_jwk(public_key)]}

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
            return resp

        client.get = _get
        return client

    fetcher = HubManifestFetcher()
    with patch("httpx.AsyncClient", side_effect=_build_client):
        verified = await fetcher.fetch(SERVICE_ID)

    assert verified.service_id == SERVICE_ID
    assert verified.namespace == NAMESPACE
    assert verified.categories_url == CATEGORIES_URL
    assert verified.jwks_url == JWKS_URL
    assert verified.attested_by == "agentid:pre.agent-id.live:org_dojozero"
    assert verified.aip_version == "0.1"


# ---------------------------------------------------------------------------
# public_key_to_jwk + generate_signing_keypair
# ---------------------------------------------------------------------------


class TestPublicKeyToJwk:
    def test_canonical_jwk_shape(self):
        private_key = Ed25519PrivateKey.generate()
        jwk = public_key_to_jwk(private_key.public_key(), "my-kid")
        assert jwk["kty"] == "OKP"
        assert jwk["crv"] == "Ed25519"
        assert jwk["kid"] == "my-kid"
        # base64url-no-pad of 32 bytes raw key → 43 chars
        assert len(jwk["x"]) == 43
        assert "=" not in jwk["x"]


class TestGenerateSigningKeypair:
    def test_default_kid(self):
        private_key, jwk, pem = generate_signing_keypair()
        assert isinstance(private_key, Ed25519PrivateKey)
        assert jwk["kid"] == "hub-key-1"
        assert "BEGIN PRIVATE KEY" in pem
        assert "END PRIVATE KEY" in pem

    def test_jwk_matches_private_key(self):
        private_key, jwk, _ = generate_signing_keypair(kid="x")
        # The JWK we hand back must encode the *same* public key the
        # private key produces — otherwise hubs serve a JWKS that
        # doesn't verify their own signatures.
        derived = public_key_to_jwk(private_key.public_key(), "x")
        assert derived == jwk

    def test_keypair_can_sign_and_verify_via_fetcher(self):
        """Capstone: keypair → sign manifest → JWKS round-trip works.
        If this passes, an adopter using only the SDK helpers can
        publish a manifest that ``HubManifestFetcher`` will accept."""
        private_key, jwk, _ = generate_signing_keypair(kid="adopter-key")
        manifest = build_manifest(
            service_id=SERVICE_ID,
            namespace=NAMESPACE,
            categories_url=CATEGORIES_URL,
            jwks_url=JWKS_URL,
        )
        jws = sign_manifest(manifest, private_key=private_key, kid="adopter-key")
        assert jws.count(".") == 2
        # The published JWKS doc consumes the same encoding.
        assert jwk["kid"] == "adopter-key"
        assert jwk["kty"] == "OKP"

    def test_each_call_produces_distinct_keys(self):
        _, _, pem_a = generate_signing_keypair()
        _, _, pem_b = generate_signing_keypair()
        assert pem_a != pem_b
