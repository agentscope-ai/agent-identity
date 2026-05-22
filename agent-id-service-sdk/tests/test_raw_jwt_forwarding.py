"""Tests for VerifiedAgent.raw_jwt + X-AgentID-Token forwarding.

Covers the §5.0 enforcement-gap closure on the SDK side:
  - verify_token() captures the raw JWT string on VerifiedAgent.
  - report_event() flows the raw_jwt through the queue to the drainer.
  - The HTTP POST attaches X-AgentID-Token when raw_jwt is non-empty.
  - Legacy callers (raw_jwt="" via direct VerifiedAgent construction)
    still work; X-AgentID-Token is omitted.

We patch the Verifier's JWKS fetch and the emitter's httpx client so
no real network is touched.
"""

from __future__ import annotations

import asyncio
import base64
import time
from typing import Any

import httpx
import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_id_service_sdk import Verifier, VerifiedAgent


IDP_DOMAIN = "idp.example.com"
HUB_SERVICE_ID = "https://hub.example.com"
HUB_KID = "hub-key-1"
IDP_KID = "idp-key-1"


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _mint_idp_jwt(
    *,
    idp_priv: Ed25519PrivateKey,
    agent_id: str,
    audience: str,
    privacy: dict[str, Any] | None = None,
) -> str:
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": f"https://{IDP_DOMAIN}",
        "sub": agent_id,
        "aud": audience,
        "iat": now,
        "exp": now + 600,
        "agentid_version": "0.1",
        "agent_name": "test",
        "principal": {"type": "human", "id": "p1", "name": "Alice"},
    }
    if privacy is not None:
        claims["privacy"] = privacy
    return pyjwt.encode(claims, idp_priv, algorithm="EdDSA", headers={"kid": IDP_KID})


def _patch_jwks(monkeypatch, verifier: Verifier, idp_priv: Ed25519PrivateKey) -> None:
    pub_key = idp_priv.public_key()

    async def _fake_fetch(provider_domain, *, force_refresh=False):
        return {IDP_KID: pub_key}

    monkeypatch.setattr(verifier, "_fetch_jwks", _fake_fetch)


# ---------------------------------------------------------------------------
# VerifiedAgent.raw_jwt is populated during verify_token
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_token_captures_raw_jwt(monkeypatch):
    idp_priv = Ed25519PrivateKey.generate()
    token = _mint_idp_jwt(
        idp_priv=idp_priv,
        agent_id="agentid:test:a",
        audience=HUB_SERVICE_ID,
        privacy={"level": "existence"},
    )
    verifier = Verifier(
        trusted_providers=[IDP_DOMAIN],
        audience=HUB_SERVICE_ID,
    )
    _patch_jwks(monkeypatch, verifier, idp_priv)

    agent = await verifier.verify_token(token)
    assert agent.raw_jwt == token
    assert agent.raw_claims["privacy"] == {"level": "existence"}


def test_verified_agent_raw_jwt_defaults_empty():
    """Direct construction (legacy callers, tests) defaults to empty.
    Emitter then skips X-AgentID-Token header."""
    agent = VerifiedAgent(
        agent_id="a",
        agent_name="n",
        principal={},
        capabilities=[],
        scopes={},
        delegation=None,
        model_info=None,
        issuer="https://idp",
        expires_at=__import__("datetime").datetime.now(),
        raw_claims={},
    )
    assert agent.raw_jwt == ""


# ---------------------------------------------------------------------------
# X-AgentID-Token attached on emit when raw_jwt present
# ---------------------------------------------------------------------------


def _hub_keypair():
    priv = Ed25519PrivateKey.generate()
    return priv, _b64u(priv.public_key().public_bytes_raw())


@pytest.mark.asyncio
async def test_emit_attaches_x_agentid_token_when_raw_jwt_present(monkeypatch):
    """End-to-end: build a Verifier with hub signing wired, call report_event
    with a VerifiedAgent that has raw_jwt set, intercept the emitter's POST,
    confirm X-AgentID-Token header carries the JWT verbatim."""
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["headers"] = dict(request.headers)
        captured["body"] = request.content
        return httpx.Response(202, json={"accepted": 1})

    mock_transport = httpx.MockTransport(handler)

    hub_priv, _ = _hub_keypair()
    verifier = Verifier(
        trusted_providers=[IDP_DOMAIN],
        audience=HUB_SERVICE_ID,
        activity_endpoint="https://activity.example.com/agentid/activity",
        service_name="hub",
        hub_signing_key=hub_priv,
        hub_signing_kid=HUB_KID,
        hub_service_id=HUB_SERVICE_ID,
    )
    # Inject our mock transport into the lazily-initialised httpx client.
    await verifier._ensure_emitter()
    assert verifier._emit_client is not None
    await verifier._emit_client.aclose()
    verifier._emit_client = httpx.AsyncClient(transport=mock_transport, timeout=5.0)

    raw_jwt = "header.payload.signature"
    agent = VerifiedAgent(
        agent_id="agentid:test:a",
        agent_name="test",
        principal={"id": "p1"},
        capabilities=[],
        scopes={},
        delegation=None,
        model_info=None,
        issuer=f"https://{IDP_DOMAIN}",
        expires_at=__import__("datetime").datetime.now(),
        raw_claims={"sub": "agentid:test:a"},
        raw_jwt=raw_jwt,
    )

    await verifier.report_event(
        category="auth.verify",
        agent=agent,
        payload={"route": "/x"},
    )
    # Give the drainer a tick to pull from queue and POST.
    for _ in range(20):
        if "headers" in captured:
            break
        await asyncio.sleep(0.05)

    assert "headers" in captured, "emitter did not POST"
    assert captured["headers"].get("x-agentid-token") == raw_jwt
    # Envelope auth still present.
    assert captured["headers"].get("authorization", "").startswith("HubJWS ")

    # Cleanup
    if verifier._emit_drain_task:
        verifier._emit_drain_task.cancel()
    await verifier._emit_client.aclose()


@pytest.mark.asyncio
async def test_emit_omits_header_when_raw_jwt_empty(monkeypatch):
    """Legacy path: agent.raw_jwt is empty → no X-AgentID-Token sent."""
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["headers"] = dict(request.headers)
        return httpx.Response(202, json={"accepted": 1})

    hub_priv, _ = _hub_keypair()
    verifier = Verifier(
        trusted_providers=[IDP_DOMAIN],
        audience=HUB_SERVICE_ID,
        activity_endpoint="https://activity.example.com/agentid/activity",
        service_name="hub",
        hub_signing_key=hub_priv,
        hub_signing_kid=HUB_KID,
        hub_service_id=HUB_SERVICE_ID,
    )
    await verifier._ensure_emitter()
    assert verifier._emit_client is not None
    await verifier._emit_client.aclose()
    verifier._emit_client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), timeout=5.0
    )

    agent = VerifiedAgent(
        agent_id="agentid:test:a",
        agent_name="test",
        principal={"id": "p1"},
        capabilities=[],
        scopes={},
        delegation=None,
        model_info=None,
        issuer=f"https://{IDP_DOMAIN}",
        expires_at=__import__("datetime").datetime.now(),
        raw_claims={"sub": "agentid:test:a"},
        # raw_jwt left as default ""
    )

    await verifier.report_event(
        category="auth.verify", agent=agent, payload={"route": "/x"}
    )
    for _ in range(20):
        if "headers" in captured:
            break
        await asyncio.sleep(0.05)

    assert "x-agentid-token" not in captured["headers"]

    if verifier._emit_drain_task:
        verifier._emit_drain_task.cancel()
    await verifier._emit_client.aclose()
