"""End-to-end test of the AgentID IdP flow.

1. Register a principal
2. Create an agent with a public key
3. Request a token with a valid signature
4. Decode the token and verify claims
"""

import base64
import time
from unittest.mock import patch

import httpx as httpx_lib
import jwt as pyjwt
import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from httpx import ASGITransport, AsyncClient

from ref_idp.crypto.keys import compute_kid


@pytest_asyncio.fixture
async def client(tmp_path):
    """Create a test client with a fresh database and signing key."""
    # Override settings before importing app
    from ref_idp.config import settings

    settings.database_url = f"sqlite+aiosqlite:///{tmp_path}/test.db"
    settings.idp_signing_key_path = str(tmp_path / "test_signing_key.pem")
    settings.idp_domain = "test.aip.example"
    # idp_base_url is derived from idp_domain in __post_init__ at import time
    # and not re-derived on mutation; set it explicitly so the discovery doc
    # matches what this test expects.
    settings.idp_base_url = "https://test.aip.example"

    # Re-create the engine with the new URL
    from ref_idp.models import database as db_module
    from sqlalchemy.ext.asyncio import (
        AsyncSession,
        async_sessionmaker,
        create_async_engine,
    )

    db_module.engine = create_async_engine(settings.database_url, echo=False)
    db_module.async_session = async_sessionmaker(
        db_module.engine, class_=AsyncSession, expire_on_commit=False
    )

    from ref_idp.main import app

    # Trigger startup manually
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(
            transport=transport, base_url="https://test.aip.example"
        ) as ac:
            yield ac


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _jwk(public_bytes: bytes, kid: str) -> dict:
    return {"kty": "OKP", "crv": "Ed25519", "x": _b64u(public_bytes), "kid": kid}


async def _register_agent(client, name: str = "agent"):
    """Register an agent the ModelScope way: dev AccessToken + public JWK."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    kid = "key-" + compute_kid(pub)
    resp = await client.post(
        "/openapi/v1/agent_ids",
        json={"agent_name": name, "public_key": _jwk(pub, kid)},
        headers={"Authorization": "Bearer dev-access-token"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()["data"]
    return data["agent_id"], data["kid"], priv


@pytest.mark.asyncio
async def test_full_flow(client):
    """ModelScope flow: register (JWK + AccessToken) → token → minimal claims."""
    agent_id, kid, priv = await _register_agent(client, "alice-assistant")
    assert agent_id.startswith("aip:test.aip.example:agent_")

    audience = "hub_abc123"  # a hub client_id, not a URL
    timestamp = int(time.time())
    message = f"{agent_id}|{kid}|{audience}|{timestamp}"
    signature = _b64u(priv.sign(message.encode("utf-8")))

    resp = await client.post(
        "/openapi/v1/agent_id/token",
        json={
            "agent_id": agent_id,
            "kid": kid,
            "audience": audience,
            "timestamp": timestamp,
            "signature": signature,
        },
    )
    assert resp.status_code == 200, resp.text
    env = resp.json()
    assert env["success"] is True
    data = env["data"]
    assert data["token_type"] == "Bearer"
    assert data["expires_in"] > 0
    assert data["jti"]

    claims = pyjwt.decode(
        data["access_token"], options={"verify_signature": False}, algorithms=["EdDSA"]
    )
    assert claims["iss"] == "https://test.aip.example"
    assert claims["sub"] == agent_id
    assert claims["aud"] == audience
    assert claims["exp"] > claims["iat"]
    assert "jti" in claims
    # Minimal ModelScope token — no principal / cnf / agent_token_version.
    assert "principal" not in claims
    assert "cnf" not in claims
    assert "agent_token_version" not in claims


@pytest.mark.asyncio
async def test_dpop_switch_adds_cnf(client):
    """With REF_AGENT_IDP_DPOP_ENABLED on, the JWT carries cnf.jkt (RFC 9449).

    cnf.jkt binds to the agent's holder key. Off by default (test_full_flow
    asserts no cnf); here we flip app.state for this request.
    """
    from ref_idp.crypto.keys import rfc7638_thumbprint
    from ref_idp.main import app

    app.state.dpop_enabled = True
    agent_id, kid, priv = await _register_agent(client, "dave")

    audience = "hub_abc123"
    timestamp = int(time.time())
    message = f"{agent_id}|{kid}|{audience}|{timestamp}"
    signature = _b64u(priv.sign(message.encode("utf-8")))
    resp = await client.post(
        "/openapi/v1/agent_id/token",
        json={
            "agent_id": agent_id,
            "kid": kid,
            "audience": audience,
            "timestamp": timestamp,
            "signature": signature,
        },
    )
    assert resp.status_code == 200, resp.text
    claims = pyjwt.decode(
        resp.json()["data"]["access_token"],
        options={"verify_signature": False},
        algorithms=["EdDSA"],
    )
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    assert claims["cnf"]["jkt"] == rfc7638_thumbprint(pub)

    app.state.dpop_enabled = False  # reset so it doesn't leak to other tests


@pytest.mark.asyncio
async def test_invalid_signature_rejected(client):
    """A signature from the wrong key is rejected with 401."""
    agent_id, kid, _priv = await _register_agent(client, "bob")

    audience = "hub_abc123"
    timestamp = int(time.time())
    wrong_key = Ed25519PrivateKey.generate()
    message = f"{agent_id}|{kid}|{audience}|{timestamp}"
    bad_signature = _b64u(wrong_key.sign(message.encode("utf-8")))

    resp = await client.post(
        "/openapi/v1/agent_id/token",
        json={
            "agent_id": agent_id,
            "kid": kid,
            "audience": audience,
            "timestamp": timestamp,
            "signature": bad_signature,
        },
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_timestamp_out_of_window(client):
    """A timestamp beyond the ±60s window is rejected with 400."""
    agent_id, kid, priv = await _register_agent(client, "carol")

    audience = "hub_abc123"
    timestamp = int(time.time()) - 3600  # an hour old
    message = f"{agent_id}|{kid}|{audience}|{timestamp}"
    signature = _b64u(priv.sign(message.encode("utf-8")))

    resp = await client.post(
        "/openapi/v1/agent_id/token",
        json={
            "agent_id": agent_id,
            "kid": kid,
            "audience": audience,
            "timestamp": timestamp,
            "signature": signature,
        },
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_discovery_endpoints(client):
    """Well-known endpoints return the ModelScope-shaped config + JWKS."""
    resp = await client.get("/openapi/v1/agent_id/.well-known/agentid-configuration")
    assert resp.status_code == 200
    config = resp.json()
    assert config["issuer"] == "https://test.aip.example"
    assert config["id_token_signing_alg_values_supported"] == "EdDSA"
    assert config["token_endpoint"].endswith("/openapi/v1/agent_id/token")
    assert config["jwks_uri"].endswith("/openapi/v1/agent_id/.well-known/agentid-jwks")

    resp = await client.get("/openapi/v1/agent_id/.well-known/agentid-jwks")
    assert resp.status_code == 200
    jwks = resp.json()
    assert len(jwks["keys"]) == 1
    assert jwks["keys"][0]["kty"] == "OKP"
    assert jwks["keys"][0]["crv"] == "Ed25519"
    assert jwks["keys"][0]["alg"] == "EdDSA"


# ---------------------------------------------------------------------------
# GitHub OAuth Device Flow tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_device_flow(client):
    """Test GitHub OAuth Device Flow: start, poll (pending), poll (success)."""
    from ref_idp.config import settings

    settings.github_client_id = "test_client_id"

    poll_count = 0

    async def mock_gh_post(url, **kwargs):
        nonlocal poll_count
        if "device/code" in url:
            return httpx_lib.Response(
                200,
                json={
                    "device_code": "test_device_code_123",
                    "user_code": "ABCD-1234",
                    "verification_uri": "https://github.com/login/device",
                    "expires_in": 900,
                    "interval": 5,
                },
            )
        elif "access_token" in url:
            poll_count += 1
            if poll_count <= 1:
                return httpx_lib.Response(200, json={"error": "authorization_pending"})
            return httpx_lib.Response(
                200,
                json={
                    "access_token": "gho_test_token_abc",
                    "token_type": "bearer",
                    "scope": "read:user",
                },
            )
        return httpx_lib.Response(404)

    async def mock_gh_get(url, **kwargs):
        if "api.github.com/user" in url:
            return httpx_lib.Response(
                200,
                json={
                    "login": "deviceflow_alice",
                    "name": "Alice Smith",
                    "id": 12345,
                },
            )
        return httpx_lib.Response(404)

    with (
        patch("ref_idp.routes.auth._github_post", side_effect=mock_gh_post),
        patch("ref_idp.routes.auth._github_get", side_effect=mock_gh_get),
    ):
        # Step 1: Start device flow
        resp = await client.post("/agentid/auth/device")
        assert resp.status_code == 200
        data = resp.json()
        assert data["user_code"] == "ABCD-1234"
        assert data["verification_uri"] == "https://github.com/login/device"
        device_code = data["device_code"]

        # Step 2: First poll — authorization pending
        resp = await client.post(
            "/agentid/auth/device/token",
            json={"device_code": device_code},
        )
        assert resp.status_code == 200
        assert resp.json()["error"] == "authorization_pending"

        # Step 3: Second poll — user authorized, get principal
        resp = await client.post(
            "/agentid/auth/device/token",
            json={"device_code": device_code},
        )
        assert resp.status_code == 200
        result = resp.json()
        assert "error" not in result
        assert result["external_id"] == "github:deviceflow_alice"
        assert result["name"] == "Alice Smith"
        assert result["principal_id"]
        assert result["management_token"]

    # Verify the principal was persisted by logging in via direct endpoint
    resp = await client.post(
        "/agentid/auth/login",
        json={"external_id": "github:deviceflow_alice"},
    )
    assert resp.status_code == 200
    assert resp.json()["principal_id"] == result["principal_id"]


@pytest.mark.asyncio
async def test_device_flow_existing_principal(client):
    """Device flow with an already-registered GitHub user logs them in."""
    from ref_idp.config import settings

    settings.github_client_id = "test_client_id"

    # Pre-register the principal via direct endpoint
    resp = await client.post(
        "/agentid/auth/register",
        json={
            "type": "human",
            "name": "Bob (original)",
            "external_id": "github:deviceflow_bob",
        },
    )
    assert resp.status_code == 200
    original_principal_id = resp.json()["principal_id"]

    async def mock_gh_post(url, **kwargs):
        if "device/code" in url:
            return httpx_lib.Response(
                200,
                json={
                    "device_code": "test_dc_2",
                    "user_code": "EFGH-5678",
                    "verification_uri": "https://github.com/login/device",
                    "expires_in": 900,
                    "interval": 5,
                },
            )
        elif "access_token" in url:
            return httpx_lib.Response(
                200,
                json={
                    "access_token": "gho_test_2",
                    "token_type": "bearer",
                    "scope": "read:user",
                },
            )
        return httpx_lib.Response(404)

    async def mock_gh_get(url, **kwargs):
        if "api.github.com/user" in url:
            return httpx_lib.Response(
                200,
                json={
                    "login": "deviceflow_bob",
                    "name": "Bob",
                    "id": 67890,
                },
            )
        return httpx_lib.Response(404)

    with (
        patch("ref_idp.routes.auth._github_post", side_effect=mock_gh_post),
        patch("ref_idp.routes.auth._github_get", side_effect=mock_gh_get),
    ):
        resp = await client.post("/agentid/auth/device")
        assert resp.status_code == 200
        device_code = resp.json()["device_code"]

        resp = await client.post(
            "/agentid/auth/device/token",
            json={"device_code": device_code},
        )
        assert resp.status_code == 200
        result = resp.json()
        assert result["principal_id"] == original_principal_id
        assert result["external_id"] == "github:deviceflow_bob"


@pytest.mark.asyncio
async def test_device_flow_not_configured(client):
    """Device flow returns 501 when github_client_id is not set."""
    from ref_idp.config import settings

    settings.github_client_id = ""

    resp = await client.post("/agentid/auth/device")
    assert resp.status_code == 501


# ---------------------------------------------------------------------------
# GitHub OAuth Authorization Code + PKCE (web portal) tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_web_oauth_flow(client):
    """Test Authorization Code + PKCE flow: start, callback, principal created."""
    from ref_idp.config import settings

    settings.github_client_id = "test_client_id"
    settings.github_client_secret = "test_secret"

    # Step 1: Start the flow — get the GitHub authorize URL
    resp = await client.post(
        "/agentid/auth/login/github",
        json={"redirect_uri": "https://portal.example.com/auth/done"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "authorize_url" in data
    assert "github.com/login/oauth/authorize" in data["authorize_url"]
    assert "code_challenge=" in data["authorize_url"]
    assert "S256" in data["authorize_url"]
    state = data["state"]

    # Step 2: Simulate GitHub callback with an authorization code
    async def mock_gh_post(url, **kwargs):
        if "access_token" in url:
            return httpx_lib.Response(
                200,
                json={
                    "access_token": "gho_web_token",
                    "token_type": "bearer",
                    "scope": "read:user",
                },
            )
        return httpx_lib.Response(404)

    async def mock_gh_get(url, **kwargs):
        if "api.github.com/user" in url:
            return httpx_lib.Response(
                200,
                json={
                    "login": "web_carol",
                    "name": "Carol Web",
                    "id": 99999,
                },
            )
        return httpx_lib.Response(404)

    with (
        patch("ref_idp.routes.auth._github_post", side_effect=mock_gh_post),
        patch("ref_idp.routes.auth._github_get", side_effect=mock_gh_get),
    ):
        resp = await client.get(
            f"/agentid/auth/callback/github?code=test_authz_code&state={state}",
            follow_redirects=False,
        )
        assert resp.status_code == 302
        location = resp.headers["location"]
        assert location.startswith("https://portal.example.com/auth/done")
        assert "principal_id=" in location
        assert "management_token=" in location
        assert (
            "external_id=github%3Aweb_carol" in location
            or "external_id=github:web_carol" in location
        )

    # Verify the principal was persisted
    resp = await client.post(
        "/agentid/auth/login",
        json={"external_id": "github:web_carol"},
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_web_oauth_invalid_state(client):
    """Callback with unknown state should fail."""
    from ref_idp.config import settings

    settings.github_client_id = "test_client_id"

    resp = await client.get(
        "/agentid/auth/callback/github?code=test_code&state=bogus_state",
    )
    assert resp.status_code == 400
