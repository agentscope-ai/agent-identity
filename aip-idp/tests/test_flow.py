"""End-to-end test of the AIP IdP flow.

1. Register a principal
2. Create an agent with a public key
3. Request a token with a valid signature
4. Decode the token and verify claims
"""

import time
from unittest.mock import AsyncMock, patch

import httpx as httpx_lib
import jwt as pyjwt
import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from httpx import ASGITransport, AsyncClient

from aip_idp.crypto.keys import compute_kid


@pytest_asyncio.fixture
async def client(tmp_path):
    """Create a test client with a fresh database and signing key."""
    # Override settings before importing app
    from aip_idp.config import settings

    settings.database_url = f"sqlite+aiosqlite:///{tmp_path}/test.db"
    settings.idp_signing_key_path = str(tmp_path / "test_signing_key.pem")
    settings.idp_domain = "test.aip.example"

    # Re-create the engine with the new URL
    from aip_idp.models import database as db_module
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

    db_module.engine = create_async_engine(settings.database_url, echo=False)
    db_module.async_session = async_sessionmaker(
        db_module.engine, class_=AsyncSession, expire_on_commit=False
    )

    from aip_idp.main import app

    # Trigger startup manually
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="https://test.aip.example") as ac:
            yield ac


@pytest.mark.asyncio
async def test_full_flow(client):
    """Test the complete AIP flow: register principal, create agent, get token."""

    # --- Step 1: Register a principal ---
    resp = await client.post("/aip/auth/register", json={
        "type": "human",
        "name": "Alice",
        "external_id": "github:alice",
    })
    assert resp.status_code == 200, resp.text
    principal_data = resp.json()
    principal_id = principal_data["principal_id"]
    mgmt_token = principal_data["management_token"]
    assert principal_id
    assert mgmt_token

    # --- Step 2: Generate an agent keypair and register agent ---
    agent_private_key = Ed25519PrivateKey.generate()
    agent_public_bytes = agent_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    agent_public_hex = agent_public_bytes.hex()

    resp = await client.post("/aip/agents", json={
        "name": "alice-assistant",
        "public_key": agent_public_hex,
        "principal_id": principal_id,
    }, headers={"Authorization": f"Bearer {mgmt_token}"})
    assert resp.status_code == 200, resp.text
    agent_data = resp.json()
    agent_id = agent_data["agent_id"]
    kid = agent_data["kid"]
    assert agent_id.startswith("aip:test.aip.example:agent_")
    assert kid == compute_kid(agent_public_bytes)

    # --- Step 2b: Verify agent lookup works ---
    resp = await client.get(f"/aip/agents/{agent_id}")
    assert resp.status_code == 200, resp.text
    info = resp.json()
    assert info["name"] == "alice-assistant"
    assert info["principal_type"] == "human"
    assert len(info["public_keys"]) == 1
    assert info["public_keys"][0]["kid"] == kid

    # --- Step 3: Request a token ---
    audience = "https://api.example.com"
    timestamp = str(int(time.time()))
    message = f"{agent_id}|{kid}|{audience}|{timestamp}"
    signature = agent_private_key.sign(message.encode("utf-8"))
    signature_hex = signature.hex()

    resp = await client.post("/aip/token", json={
        "agent_id": agent_id,
        "kid": kid,
        "audience": audience,
        "timestamp": timestamp,
        "signature": signature_hex,
    })
    assert resp.status_code == 200, resp.text
    token_data = resp.json()
    token = token_data["token"]
    assert token_data["expires_at"] > int(time.time())

    # --- Step 4: Decode and verify claims ---
    claims = pyjwt.decode(token, options={"verify_signature": False}, algorithms=["EdDSA"])
    assert claims["iss"] == "https://test.aip.example"
    assert claims["sub"] == agent_id
    assert claims["aud"] == audience
    assert claims["aip_version"] == "0.1"
    assert claims["agent_name"] == "alice-assistant"
    assert claims["principal"]["type"] == "human"
    assert claims["principal"]["name"] == "Alice"
    assert claims["exp"] > claims["iat"]


@pytest.mark.asyncio
async def test_invalid_signature_rejected(client):
    """Token request with wrong signature should be rejected."""

    # Register principal
    resp = await client.post("/aip/auth/register", json={
        "type": "human",
        "name": "Bob",
        "external_id": "github:bob",
    })
    principal_data = resp.json()
    principal_id = principal_data["principal_id"]
    mgmt_token = principal_data["management_token"]

    # Register agent
    agent_private_key = Ed25519PrivateKey.generate()
    agent_public_bytes = agent_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    resp = await client.post("/aip/agents", json={
        "name": "bob-agent",
        "public_key": agent_public_bytes.hex(),
        "principal_id": principal_id,
    }, headers={"Authorization": f"Bearer {mgmt_token}"})
    agent_data = resp.json()
    agent_id = agent_data["agent_id"]
    kid = agent_data["kid"]

    # Sign with a DIFFERENT key (wrong key)
    wrong_key = Ed25519PrivateKey.generate()
    audience = "https://api.example.com"
    timestamp = str(int(time.time()))
    message = f"{agent_id}|{kid}|{audience}|{timestamp}"
    bad_signature = wrong_key.sign(message.encode("utf-8")).hex()

    resp = await client.post("/aip/token", json={
        "agent_id": agent_id,
        "kid": kid,
        "audience": audience,
        "timestamp": timestamp,
        "signature": bad_signature,
    })
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_key_revocation(client):
    """Revoking a key should prevent token issuance."""

    # Register principal + agent
    resp = await client.post("/aip/auth/register", json={
        "type": "org",
        "name": "Acme Corp",
        "external_id": "github:acme-org",
    })
    principal_data = resp.json()
    principal_id = principal_data["principal_id"]
    mgmt_token = principal_data["management_token"]

    agent_private_key = Ed25519PrivateKey.generate()
    agent_public_bytes = agent_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    resp = await client.post("/aip/agents", json={
        "name": "acme-bot",
        "public_key": agent_public_bytes.hex(),
        "principal_id": principal_id,
    }, headers={"Authorization": f"Bearer {mgmt_token}"})
    agent_data = resp.json()
    agent_id = agent_data["agent_id"]
    kid = agent_data["kid"]

    # Revoke the key
    resp = await client.delete(
        f"/aip/agents/{agent_id}/keys/{kid}",
        headers={"Authorization": f"Bearer {mgmt_token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "revoked"

    # Attempt token exchange - should fail
    audience = "https://api.example.com"
    timestamp = str(int(time.time()))
    message = f"{agent_id}|{kid}|{audience}|{timestamp}"
    signature = agent_private_key.sign(message.encode("utf-8")).hex()

    resp = await client.post("/aip/token", json={
        "agent_id": agent_id,
        "kid": kid,
        "audience": audience,
        "timestamp": timestamp,
        "signature": signature,
    })
    assert resp.status_code == 404  # key no longer active


@pytest.mark.asyncio
async def test_discovery_endpoints(client):
    """Well-known endpoints should return proper configuration."""

    resp = await client.get("/.well-known/aip-configuration")
    assert resp.status_code == 200
    config = resp.json()
    assert config["issuer"] == "https://test.aip.example"
    assert config["aip_version"] == "0.1"
    assert "EdDSA" in config["supported_algorithms"]

    resp = await client.get("/.well-known/aip-jwks")
    assert resp.status_code == 200
    jwks = resp.json()
    assert len(jwks["keys"]) == 1
    assert jwks["keys"][0]["kty"] == "OKP"
    assert jwks["keys"][0]["crv"] == "Ed25519"


# ---------------------------------------------------------------------------
# GitHub OAuth Device Flow tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_device_flow(client):
    """Test GitHub OAuth Device Flow: start, poll (pending), poll (success)."""
    from aip_idp.config import settings
    settings.github_client_id = "test_client_id"

    poll_count = 0

    async def mock_gh_post(url, **kwargs):
        nonlocal poll_count
        if "device/code" in url:
            return httpx_lib.Response(200, json={
                "device_code": "test_device_code_123",
                "user_code": "ABCD-1234",
                "verification_uri": "https://github.com/login/device",
                "expires_in": 900,
                "interval": 5,
            })
        elif "access_token" in url:
            poll_count += 1
            if poll_count <= 1:
                return httpx_lib.Response(200, json={"error": "authorization_pending"})
            return httpx_lib.Response(200, json={
                "access_token": "gho_test_token_abc",
                "token_type": "bearer",
                "scope": "read:user",
            })
        return httpx_lib.Response(404)

    async def mock_gh_get(url, **kwargs):
        if "api.github.com/user" in url:
            return httpx_lib.Response(200, json={
                "login": "deviceflow_alice",
                "name": "Alice Smith",
                "id": 12345,
            })
        return httpx_lib.Response(404)

    with (
        patch("aip_idp.routes.auth._github_post", side_effect=mock_gh_post),
        patch("aip_idp.routes.auth._github_get", side_effect=mock_gh_get),
    ):
        # Step 1: Start device flow
        resp = await client.post("/aip/auth/device")
        assert resp.status_code == 200
        data = resp.json()
        assert data["user_code"] == "ABCD-1234"
        assert data["verification_uri"] == "https://github.com/login/device"
        device_code = data["device_code"]

        # Step 2: First poll — authorization pending
        resp = await client.post(
            "/aip/auth/device/token",
            json={"device_code": device_code},
        )
        assert resp.status_code == 200
        assert resp.json()["error"] == "authorization_pending"

        # Step 3: Second poll — user authorized, get principal
        resp = await client.post(
            "/aip/auth/device/token",
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
        "/aip/auth/login",
        json={"external_id": "github:deviceflow_alice"},
    )
    assert resp.status_code == 200
    assert resp.json()["principal_id"] == result["principal_id"]


@pytest.mark.asyncio
async def test_device_flow_existing_principal(client):
    """Device flow with an already-registered GitHub user logs them in."""
    from aip_idp.config import settings
    settings.github_client_id = "test_client_id"

    # Pre-register the principal via direct endpoint
    resp = await client.post("/aip/auth/register", json={
        "type": "human",
        "name": "Bob (original)",
        "external_id": "github:deviceflow_bob",
    })
    assert resp.status_code == 200
    original_principal_id = resp.json()["principal_id"]

    async def mock_gh_post(url, **kwargs):
        if "device/code" in url:
            return httpx_lib.Response(200, json={
                "device_code": "test_dc_2",
                "user_code": "EFGH-5678",
                "verification_uri": "https://github.com/login/device",
                "expires_in": 900,
                "interval": 5,
            })
        elif "access_token" in url:
            return httpx_lib.Response(200, json={
                "access_token": "gho_test_2",
                "token_type": "bearer",
                "scope": "read:user",
            })
        return httpx_lib.Response(404)

    async def mock_gh_get(url, **kwargs):
        if "api.github.com/user" in url:
            return httpx_lib.Response(200, json={
                "login": "deviceflow_bob",
                "name": "Bob",
                "id": 67890,
            })
        return httpx_lib.Response(404)

    with (
        patch("aip_idp.routes.auth._github_post", side_effect=mock_gh_post),
        patch("aip_idp.routes.auth._github_get", side_effect=mock_gh_get),
    ):
        resp = await client.post("/aip/auth/device")
        assert resp.status_code == 200
        device_code = resp.json()["device_code"]

        resp = await client.post(
            "/aip/auth/device/token",
            json={"device_code": device_code},
        )
        assert resp.status_code == 200
        result = resp.json()
        assert result["principal_id"] == original_principal_id
        assert result["external_id"] == "github:deviceflow_bob"


@pytest.mark.asyncio
async def test_device_flow_not_configured(client):
    """Device flow returns 501 when github_client_id is not set."""
    from aip_idp.config import settings
    settings.github_client_id = ""

    resp = await client.post("/aip/auth/device")
    assert resp.status_code == 501


# ---------------------------------------------------------------------------
# GitHub OAuth Authorization Code + PKCE (web portal) tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_web_oauth_flow(client):
    """Test Authorization Code + PKCE flow: start, callback, principal created."""
    from aip_idp.config import settings
    settings.github_client_id = "test_client_id"
    settings.github_client_secret = "test_secret"

    # Step 1: Start the flow — get the GitHub authorize URL
    resp = await client.post(
        "/aip/auth/login/github",
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
            return httpx_lib.Response(200, json={
                "access_token": "gho_web_token",
                "token_type": "bearer",
                "scope": "read:user",
            })
        return httpx_lib.Response(404)

    async def mock_gh_get(url, **kwargs):
        if "api.github.com/user" in url:
            return httpx_lib.Response(200, json={
                "login": "web_carol",
                "name": "Carol Web",
                "id": 99999,
            })
        return httpx_lib.Response(404)

    with (
        patch("aip_idp.routes.auth._github_post", side_effect=mock_gh_post),
        patch("aip_idp.routes.auth._github_get", side_effect=mock_gh_get),
    ):
        resp = await client.get(
            f"/aip/auth/callback/github?code=test_authz_code&state={state}",
            follow_redirects=False,
        )
        assert resp.status_code == 302
        location = resp.headers["location"]
        assert location.startswith("https://portal.example.com/auth/done")
        assert "principal_id=" in location
        assert "management_token=" in location
        assert "external_id=github%3Aweb_carol" in location or "external_id=github:web_carol" in location

    # Verify the principal was persisted
    resp = await client.post(
        "/aip/auth/login",
        json={"external_id": "github:web_carol"},
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_web_oauth_invalid_state(client):
    """Callback with unknown state should fail."""
    from aip_idp.config import settings
    settings.github_client_id = "test_client_id"

    resp = await client.get(
        "/aip/auth/callback/github?code=test_code&state=bogus_state",
    )
    assert resp.status_code == 400
