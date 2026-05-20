"""Tests for agent_token_version stash + enforcement on the verifier.

Covers:
- Claim stashed on VerifiedAgent.agent_token_version
- min_agent_token_version sync lookup: rejects below-minimum, allows at/above
- min_agent_token_version async lookup
- Lookup returning None → no enforcement
- Lookup raising → enforcement skipped (logged warning)
- Claim missing → defaults to 0
"""

from __future__ import annotations

import time
from typing import Any

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_id_service_sdk import Verifier
from agent_id_service_sdk.errors import TokenInvalidError


IDP_DOMAIN = "idp.example.com"
HUB_AUDIENCE = "https://hub.example.com"
IDP_KID = "idp-key-1"


def _mint(
    *,
    priv: Ed25519PrivateKey,
    agent_id: str = "agentid:test:a1",
    token_version: int | None = 0,
) -> str:
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": f"https://{IDP_DOMAIN}",
        "sub": agent_id,
        "aud": HUB_AUDIENCE,
        "iat": now,
        "exp": now + 600,
        "agentid_version": "0.1",
        "agent_name": "test",
        "principal": {"type": "human", "id": "p1", "name": "Alice"},
    }
    if token_version is not None:
        claims["agent_token_version"] = token_version
    return pyjwt.encode(claims, priv, algorithm="EdDSA", headers={"kid": IDP_KID})


def _patch_jwks(monkeypatch, verifier: Verifier, priv: Ed25519PrivateKey) -> None:
    pub = priv.public_key()

    async def _fetch(provider_domain, *, force_refresh=False):
        return {IDP_KID: pub}

    monkeypatch.setattr(verifier, "_fetch_jwks", _fetch)


# ---------------------------------------------------------------------------
# Stashing
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_claim_stashed_on_verified_agent(monkeypatch):
    priv = Ed25519PrivateKey.generate()
    verifier = Verifier(trusted_providers=[IDP_DOMAIN], audience=HUB_AUDIENCE)
    _patch_jwks(monkeypatch, verifier, priv)
    token = _mint(priv=priv, token_version=3)
    agent = await verifier.verify_token(token)
    assert agent.agent_token_version == 3


@pytest.mark.asyncio
async def test_missing_claim_defaults_to_zero(monkeypatch):
    priv = Ed25519PrivateKey.generate()
    verifier = Verifier(trusted_providers=[IDP_DOMAIN], audience=HUB_AUDIENCE)
    _patch_jwks(monkeypatch, verifier, priv)
    # Mint a JWT without agent_token_version (legacy IdP).
    token = _mint(priv=priv, token_version=None)
    agent = await verifier.verify_token(token)
    assert agent.agent_token_version == 0


@pytest.mark.asyncio
async def test_non_int_claim_defaults_to_zero(monkeypatch):
    """Defense: a stringified version slips through → treat as 0 (not crash,
    not honor a possibly-tampered value)."""
    priv = Ed25519PrivateKey.generate()
    now = int(time.time())
    claims = {
        "iss": f"https://{IDP_DOMAIN}",
        "sub": "agentid:test:a1",
        "aud": HUB_AUDIENCE,
        "iat": now,
        "exp": now + 600,
        "agent_token_version": "five",  # wrong type
    }
    token = pyjwt.encode(claims, priv, algorithm="EdDSA", headers={"kid": IDP_KID})

    verifier = Verifier(trusted_providers=[IDP_DOMAIN], audience=HUB_AUDIENCE)
    _patch_jwks(monkeypatch, verifier, priv)
    agent = await verifier.verify_token(token)
    assert agent.agent_token_version == 0


# ---------------------------------------------------------------------------
# Enforcement
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_enforcement_allows_at_or_above_minimum(monkeypatch):
    priv = Ed25519PrivateKey.generate()

    def lookup(agent_id: str) -> int:
        return 2

    verifier = Verifier(
        trusted_providers=[IDP_DOMAIN],
        audience=HUB_AUDIENCE,
        min_agent_token_version=lookup,
    )
    _patch_jwks(monkeypatch, verifier, priv)
    # Equal → ok
    await verifier.verify_token(_mint(priv=priv, token_version=2))
    # Above → ok
    await verifier.verify_token(_mint(priv=priv, token_version=5))


@pytest.mark.asyncio
async def test_enforcement_refuses_below_minimum(monkeypatch):
    priv = Ed25519PrivateKey.generate()

    def lookup(agent_id: str) -> int:
        return 3

    verifier = Verifier(
        trusted_providers=[IDP_DOMAIN],
        audience=HUB_AUDIENCE,
        min_agent_token_version=lookup,
    )
    _patch_jwks(monkeypatch, verifier, priv)

    # Stale token (below minimum) → reject.
    with pytest.raises(TokenInvalidError, match="agent_token_version"):
        await verifier.verify_token(_mint(priv=priv, token_version=1))


@pytest.mark.asyncio
async def test_enforcement_async_lookup(monkeypatch):
    priv = Ed25519PrivateKey.generate()

    async def lookup(agent_id: str) -> int:
        return 5

    verifier = Verifier(
        trusted_providers=[IDP_DOMAIN],
        audience=HUB_AUDIENCE,
        min_agent_token_version=lookup,
    )
    _patch_jwks(monkeypatch, verifier, priv)

    with pytest.raises(TokenInvalidError):
        await verifier.verify_token(_mint(priv=priv, token_version=4))
    # Equal → ok
    await verifier.verify_token(_mint(priv=priv, token_version=5))


@pytest.mark.asyncio
async def test_lookup_returning_none_skips_enforcement(monkeypatch):
    """Lookup says 'no minimum known' → don't refuse. Use case: hub
    hasn't synced yet for this agent_id."""
    priv = Ed25519PrivateKey.generate()

    def lookup(agent_id: str) -> int | None:
        return None

    verifier = Verifier(
        trusted_providers=[IDP_DOMAIN],
        audience=HUB_AUDIENCE,
        min_agent_token_version=lookup,
    )
    _patch_jwks(monkeypatch, verifier, priv)
    # Old token_version=0 still accepted.
    agent = await verifier.verify_token(_mint(priv=priv, token_version=0))
    assert agent.agent_token_version == 0


@pytest.mark.asyncio
async def test_lookup_raising_does_not_break_verification(monkeypatch):
    """If the deployment's lookup fails (IdP unreachable, etc.), we
    log + proceed rather than block legitimate traffic on a hub-side
    sync hiccup. Strict mode is a deployment-level concern."""
    priv = Ed25519PrivateKey.generate()

    def broken(agent_id: str) -> int:
        raise RuntimeError("sync source unreachable")

    verifier = Verifier(
        trusted_providers=[IDP_DOMAIN],
        audience=HUB_AUDIENCE,
        min_agent_token_version=broken,
    )
    _patch_jwks(monkeypatch, verifier, priv)
    # Verification still succeeds despite lookup failure.
    await verifier.verify_token(_mint(priv=priv, token_version=0))


@pytest.mark.asyncio
async def test_no_lookup_no_enforcement(monkeypatch):
    """Default behaviour: lookup unset → enforcement off."""
    priv = Ed25519PrivateKey.generate()
    verifier = Verifier(trusted_providers=[IDP_DOMAIN], audience=HUB_AUDIENCE)
    _patch_jwks(monkeypatch, verifier, priv)
    # Even old token_version=0 against future-bumped agents passes.
    await verifier.verify_token(_mint(priv=priv, token_version=0))
