from __future__ import annotations

import time

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_id_service_sdk.errors import (
    TokenExpiredError,
    TokenInvalidError,
    ProviderUntrustedError,
)
from agent_id_service_sdk.verifier import Verifier


# ---------------------------------------------------------------------------
# Fixtures & helpers
# ---------------------------------------------------------------------------

PROVIDER_DOMAIN = "idp.example.com"
AUDIENCE = "https://hub.example.com"
KID = "test-key-1"


def _make_keypair():
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def _encode_jwt(private_key, claims: dict, kid: str = KID) -> str:
    return pyjwt.encode(
        claims,
        private_key,
        algorithm="EdDSA",
        headers={"kid": kid},
    )


def _build_verifier(public_key, *, trusted=True):
    """Build a verifier with a pre-populated JWKS cache (no HTTP needed)."""
    providers = [PROVIDER_DOMAIN] if trusted else ["other.example.com"]
    verifier = Verifier(trusted_providers=providers, audience=AUDIENCE)
    # Inject the public key directly into cache so we don't need HTTP.
    verifier._jwks_cache[PROVIDER_DOMAIN] = (
        {KID: public_key},
        time.time(),
    )
    return verifier


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_missing_authorization_header():
    verifier = Verifier(trusted_providers=[PROVIDER_DOMAIN], audience=AUDIENCE)
    with pytest.raises(TokenInvalidError):
        await verifier.verify("")


@pytest.mark.asyncio
async def test_malformed_authorization_header():
    verifier = Verifier(trusted_providers=[PROVIDER_DOMAIN], audience=AUDIENCE)
    with pytest.raises(TokenInvalidError):
        await verifier.verify("AIP some-token")  # legacy scheme — no longer accepted


@pytest.mark.asyncio
async def test_expired_token():
    private_key, public_key = _make_keypair()
    verifier = _build_verifier(public_key)

    token = _encode_jwt(
        private_key,
        {
            "sub": "agent-001",
            "iss": f"https://{PROVIDER_DOMAIN}",
            "aud": AUDIENCE,
            "exp": int(time.time()) - 3600,  # expired 1 hour ago
        },
    )

    with pytest.raises(TokenExpiredError):
        await verifier.verify(f"Bearer {token}")


@pytest.mark.asyncio
async def test_wrong_audience():
    private_key, public_key = _make_keypair()
    verifier = _build_verifier(public_key)

    token = _encode_jwt(
        private_key,
        {
            "sub": "agent-001",
            "iss": f"https://{PROVIDER_DOMAIN}",
            "aud": "https://wrong-audience.example.com",
            "exp": int(time.time()) + 3600,
        },
    )

    with pytest.raises(TokenInvalidError, match="[Aa]udience"):
        await verifier.verify(f"Bearer {token}")


@pytest.mark.asyncio
async def test_untrusted_provider():
    private_key, public_key = _make_keypair()
    verifier = _build_verifier(public_key, trusted=False)

    token = _encode_jwt(
        private_key,
        {
            "sub": "agent-001",
            "iss": f"https://{PROVIDER_DOMAIN}",
            "aud": AUDIENCE,
            "exp": int(time.time()) + 3600,
        },
    )

    with pytest.raises(ProviderUntrustedError):
        await verifier.verify(f"Bearer {token}")


@pytest.mark.asyncio
async def test_valid_token():
    private_key, public_key = _make_keypair()
    verifier = _build_verifier(public_key)

    token = _encode_jwt(
        private_key,
        {
            "sub": "agent-001",
            "agent_name": "TestAgent",
            "iss": f"https://{PROVIDER_DOMAIN}",
            "aud": AUDIENCE,
            "exp": int(time.time()) + 3600,
            "principal": {"type": "user", "id": "user-1", "name": "Alice"},
            "capabilities": ["read", "write"],
            "scopes": {"data": "full"},
        },
    )

    agent = await verifier.verify(f"Bearer {token}")
    assert agent.agent_id == "agent-001"
    assert agent.agent_name == "TestAgent"
    assert agent.issuer == f"https://{PROVIDER_DOMAIN}"
    assert agent.capabilities == ["read", "write"]
