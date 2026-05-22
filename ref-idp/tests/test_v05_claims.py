"""Tests for v0.5 JWT-level claims on ref-idp:
- cnf.jkt (RFC 7638 thumbprint) on every issued JWT
- agent_token_version always present, defaulting to 0
- agent_token_version bumped on key revocation
"""

from __future__ import annotations

import base64
import hashlib
import json
import time

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from httpx import ASGITransport, AsyncClient

from ref_idp.crypto.keys import compute_kid, rfc7638_thumbprint


# ---------------------------------------------------------------------------
# Unit: rfc7638_thumbprint
# ---------------------------------------------------------------------------


def test_thumbprint_deterministic():
    pub = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    assert rfc7638_thumbprint(pub) == rfc7638_thumbprint(pub)


def test_thumbprint_format_is_base64url_no_padding():
    pub = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    tp = rfc7638_thumbprint(pub)
    assert len(tp) == 43  # SHA-256 → 32 bytes → base64url no pad → 43 chars
    assert "=" not in tp
    assert "+" not in tp
    assert "/" not in tp


def test_thumbprint_matches_independent_construction():
    """Sanity check against a hand-built canonical form. If our impl
    drifts from RFC 7638 (member set, ordering, encoding) this breaks."""
    pub = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    x = base64.urlsafe_b64encode(pub).rstrip(b"=").decode()
    expected_canonical = ('{"crv":"Ed25519","kty":"OKP","x":"' + x + '"}').encode()
    expected = (
        base64.urlsafe_b64encode(hashlib.sha256(expected_canonical).digest())
        .rstrip(b"=")
        .decode()
    )
    assert rfc7638_thumbprint(pub) == expected


def test_thumbprint_distinct_from_legacy_compute_kid():
    pub = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    assert compute_kid(pub) != rfc7638_thumbprint(pub)
    assert len(compute_kid(pub)) == 16
    assert len(rfc7638_thumbprint(pub)) == 43


# ---------------------------------------------------------------------------
# End-to-end: cnf.jkt and agent_token_version travel through /agentid/token
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def client(tmp_path):
    from sqlalchemy.ext.asyncio import (
        AsyncSession,
        async_sessionmaker,
        create_async_engine,
    )

    from ref_idp.config import settings

    settings.database_url = f"sqlite+aiosqlite:///{tmp_path}/test.db"
    settings.idp_signing_key_path = str(tmp_path / "test_signing_key.pem")
    settings.idp_domain = "test.aip.example"
    settings.idp_base_url = "https://test.aip.example"

    from ref_idp.models import database as db_module

    db_module.engine = create_async_engine(settings.database_url, echo=False)
    db_module.async_session = async_sessionmaker(
        db_module.engine, class_=AsyncSession, expire_on_commit=False
    )

    from ref_idp.main import app

    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(
        transport=transport, base_url="https://test.aip.example"
    ) as ac:
        async with app.router.lifespan_context(app):
            yield ac


def _decode_unverified(token: str) -> dict:
    parts = token.split(".")
    pad = lambda s: s + "=" * (-len(s) % 4)  # noqa: E731
    return json.loads(base64.urlsafe_b64decode(pad(parts[1])))


async def _bootstrap_agent(client) -> tuple[str, str, Ed25519PrivateKey, str]:
    """Register principal + agent. Return (agent_id, kid, priv, mgmt_token).

    Uses a per-call unique external_id because the fixture's engine override
    can't fully isolate the singleton ``async_session`` (it's import-time
    bound in routes), so principals accumulate across tests in a session.
    """
    unique = str(time.time_ns())
    # Register principal (dev path)
    resp = await client.post(
        "/agentid/auth/register",
        json={
            "type": "human",
            "name": f"Alice-{unique}",
            "external_id": f"dev:alice-{unique}",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    mgmt = body["management_token"]
    principal_id = body["principal_id"]

    # Create agent
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    resp = await client.post(
        "/agentid/agents",
        json={
            "name": "bot",
            "public_key": pub.hex(),
            "principal_id": principal_id,
        },
        headers={"Authorization": f"Bearer {mgmt}"},
    )
    assert resp.status_code == 200, resp.text
    agent_id = resp.json()["agent_id"]
    kid = resp.json()["kid"]
    return agent_id, kid, priv, mgmt


async def _request_token(
    client, agent_id: str, kid: str, priv: Ed25519PrivateKey
) -> dict:
    audience = "https://hub.example.com"
    timestamp = str(int(time.time()))
    message = f"{agent_id}|{kid}|{audience}|{timestamp}"
    signature = priv.sign(message.encode()).hex()
    resp = await client.post(
        "/agentid/token",
        json={
            "agent_id": agent_id,
            "kid": kid,
            "audience": audience,
            "timestamp": timestamp,
            "signature": signature,
        },
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


@pytest.mark.asyncio
async def test_issued_jwt_carries_cnf_jkt(client):
    agent_id, kid, priv, _ = await _bootstrap_agent(client)
    resp = await _request_token(client, agent_id, kid, priv)
    claims = _decode_unverified(resp["token"])
    assert "cnf" in claims
    assert "jkt" in claims["cnf"]
    # Thumbprint = RFC 7638 of the agent's pubkey we just registered.
    pub_bytes = priv.public_key().public_bytes_raw()
    assert claims["cnf"]["jkt"] == rfc7638_thumbprint(pub_bytes)


@pytest.mark.asyncio
async def test_issued_jwt_defaults_token_version_zero(client):
    agent_id, kid, priv, _ = await _bootstrap_agent(client)
    resp = await _request_token(client, agent_id, kid, priv)
    claims = _decode_unverified(resp["token"])
    assert claims["agent_token_version"] == 0


@pytest.mark.asyncio
async def test_revoke_key_bumps_token_version(client):
    agent_id, kid, priv, mgmt = await _bootstrap_agent(client)
    # First token: version=0
    resp = await _request_token(client, agent_id, kid, priv)
    assert _decode_unverified(resp["token"])["agent_token_version"] == 0

    # Mint a fresh second key so the agent still has one after revocation
    priv2 = Ed25519PrivateKey.generate()
    pub2 = priv2.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    resp = await client.post(
        f"/agentid/agents/{agent_id}/keys",
        json={"public_key": pub2.hex()},
        headers={"Authorization": f"Bearer {mgmt}"},
    )
    assert resp.status_code == 200, resp.text
    kid2 = resp.json()["kid"]

    # Revoke the first key
    resp = await client.delete(
        f"/agentid/agents/{agent_id}/keys/{kid}",
        headers={"Authorization": f"Bearer {mgmt}"},
    )
    assert resp.status_code == 200, resp.text

    # New token via key 2 must now carry version=1
    resp = await _request_token(client, agent_id, kid2, priv2)
    claims = _decode_unverified(resp["token"])
    assert claims["agent_token_version"] == 1
