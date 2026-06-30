from __future__ import annotations

import base64
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


def _okp_jwk(public_key, kid: str = KID) -> dict:
    raw = public_key.public_bytes_raw()
    x = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "kid": kid,
        "x": x,
        "use": "sig",
        "alg": "EdDSA",
    }


@pytest.mark.asyncio
async def test_jwks_urls_bypasses_discovery(monkeypatch):
    """ModelScope path: explicit jwks_urls, minimal claims, client_id audience.

    Verifies a ModelScope-shaped token (issuer with a path, audience = hub
    client_id, no principal/scopes/capabilities) and asserts the verifier
    fetched ONLY the configured JWKS URL — no OIDC discovery call.
    """
    private_key, public_key = _make_keypair()

    ms_domain = "pre.modelscope.cn"
    jwks_url = "https://pre.modelscope.cn/openapi/v1/agent_id/.well-known/agentid-jwks"
    fetched_urls: list[str] = []

    class _FakeResp:
        def __init__(self, data):
            self._data = data

        def raise_for_status(self):
            return None

        def json(self):
            return self._data

    class _FakeAsyncClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url):
            fetched_urls.append(url)
            return _FakeResp({"keys": [_okp_jwk(public_key)]})

    monkeypatch.setattr(
        "agent_id_service_sdk.verifier.httpx.AsyncClient", _FakeAsyncClient
    )

    verifier = Verifier(
        trusted_providers=[ms_domain],
        audience="hub_4abb08",
        jwks_urls={ms_domain: jwks_url},
    )

    token = _encode_jwt(
        private_key,
        {
            "sub": "aip:identity.modelscope.cn:agent_x",
            "iss": "https://pre.modelscope.cn/openapi/v1",
            "aud": "hub_4abb08",
            "iat": int(time.time()),
            "exp": int(time.time()) + 600,
            "jti": "jti-1",
        },
    )

    agent = await verifier.verify(f"Bearer {token}")
    assert agent.agent_id == "aip:identity.modelscope.cn:agent_x"
    # Minimal ModelScope JWT — absent claims degrade to clean defaults.
    assert agent.agent_name == ""
    assert agent.principal == {}
    assert agent.capabilities == []
    # Only the configured JWKS URL was fetched; discovery was skipped.
    assert fetched_urls == [jwks_url]
