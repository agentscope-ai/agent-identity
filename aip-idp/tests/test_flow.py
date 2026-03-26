"""End-to-end test of the AIP IdP flow.

1. Register a principal
2. Create an agent with a public key
3. Request a token with a valid signature
4. Decode the token and verify claims
"""

import time

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
