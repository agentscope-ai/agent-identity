"""End-to-end DPoP loop: client SDK signs, service SDK verifies.

These tests exercise the Verifier from the resource-server angle. We
substitute the real IdP JWKS resolution with a stubbed fetcher so the
test doesn't require running a full IdP — the goal here is to confirm
the client-sdk's sign_dpop_proof + Authorization-scheme switch round-
trips through the service-sdk's Verifier.verify() integration.

What we're not testing here (lives elsewhere):
- DPoP proof shape (test_dpop.py)
- JWS signature math (covered by pyjwt's own tests)
- IdP-side cnf claim emission (aip-idp test_thumbprint_and_cnf.py)
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from typing import Any

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_id_client_sdk.identity import Identity
from agent_id_service_sdk import Verifier
from agent_id_service_sdk.errors import TokenInvalidError


HUB_AUDIENCE = "https://hub.example.com"
IDP_DOMAIN = "idp.example.com"


# ---------------------------------------------------------------------------
# Stub IdP — issues JWTs with cnf.jkt and serves a matching JWKS
# ---------------------------------------------------------------------------


class _StubIdP:
    """In-memory IdP that signs JWTs with its own key and emits cnf.jkt.

    Lets us avoid spinning up a real ref-idp HTTP server: the Verifier's
    JWKS-fetch is stubbed below to return this IdP's public key, and the
    Verifier's verify_token can validate JWTs we mint here."""

    KID = "idp-key-1"

    def __init__(self):
        self.priv = Ed25519PrivateKey.generate()
        pub = self.priv.public_key().public_bytes_raw()
        self.public_jwk = {
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": self.KID,
            "x": base64.urlsafe_b64encode(pub).rstrip(b"=").decode("ascii"),
        }

    def issue_token(
        self,
        *,
        agent_id: str,
        agent_pubkey_bytes: bytes,
        audience: str = HUB_AUDIENCE,
        with_cnf: bool = True,
        ttl_seconds: int = 600,
    ) -> str:
        """Mint a JWT for the given agent. RFC 7638 thumbprint computed
        from the agent's pubkey lands in cnf.jkt when with_cnf=True."""
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": f"https://{IDP_DOMAIN}",
            "sub": agent_id,
            "aud": audience,
            "iat": now,
            "exp": now + ttl_seconds,
            "agentid_version": "0.1",
            "agent_name": "test-agent",
            "principal": {"type": "human", "id": "p1", "name": "Alice"},
        }
        if with_cnf:
            claims["cnf"] = {"jkt": _rfc7638_thumbprint(agent_pubkey_bytes)}
        return pyjwt.encode(
            claims,
            self.priv,
            algorithm="EdDSA",
            headers={"kid": self.KID},
        )


def _rfc7638_thumbprint(pubkey_bytes: bytes) -> str:
    x = base64.urlsafe_b64encode(pubkey_bytes).rstrip(b"=").decode("ascii")
    canonical = json.dumps(
        {"crv": "Ed25519", "kty": "OKP", "x": x},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    digest = hashlib.sha256(canonical).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _patch_verifier_jwks(monkeypatch, verifier: Verifier, idp: _StubIdP) -> None:
    """Replace the Verifier's JWKS fetch with one that returns the stub IdP's
    key. We patch the method directly because the real impl wants HTTP."""

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    pub_bytes = base64.urlsafe_b64decode(
        idp.public_jwk["x"] + "=" * (-len(idp.public_jwk["x"]) % 4)
    )
    pub_key = Ed25519PublicKey.from_public_bytes(pub_bytes)

    async def _fake_fetch(provider_domain, *, force_refresh=False):
        del provider_domain, force_refresh  # mock — args unused
        return {idp.KID: pub_key}

    monkeypatch.setattr(verifier, "_fetch_jwks", _fake_fetch)


def _make_agent_identity() -> Identity:
    priv = Ed25519PrivateKey.generate()
    seed = priv.private_bytes_raw()
    return Identity(
        agent_id=f"agentid:{IDP_DOMAIN}:agent_test",
        kid="dummy-kid",
        private_key_bytes=seed,
        idp_url=f"https://{IDP_DOMAIN}",
    )


# ---------------------------------------------------------------------------
# End-to-end happy paths
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dpop_optional_accepts_bearer_when_no_proof(monkeypatch):
    """A hub running dpop_mode=optional should accept legacy Bearer requests
    even when the token carries a cnf.jkt claim."""
    idp = _StubIdP()
    ident = _make_agent_identity()
    agent_pub = ident._private_key.public_key().public_bytes_raw()
    token = idp.issue_token(agent_id=ident.agent_id, agent_pubkey_bytes=agent_pub)

    verifier = Verifier(
        trusted_providers=[IDP_DOMAIN],
        audience=HUB_AUDIENCE,
        dpop_mode="optional",
    )
    _patch_verifier_jwks(monkeypatch, verifier, idp)

    agent = await verifier.verify(f"Bearer {token}")
    assert agent.agent_id == ident.agent_id


@pytest.mark.asyncio
async def test_dpop_optional_accepts_dpop_when_proof_present(monkeypatch):
    """When the client uses the DPoP scheme + supplies a proof, the verifier
    runs the binding check and accepts."""
    idp = _StubIdP()
    ident = _make_agent_identity()
    agent_pub = ident._private_key.public_key().public_bytes_raw()
    token = idp.issue_token(agent_id=ident.agent_id, agent_pubkey_bytes=agent_pub)

    proof = ident.sign_dpop_proof(
        htm="POST",
        htu=f"{HUB_AUDIENCE}/api/foo",
        access_token=token,
    )

    verifier = Verifier(
        trusted_providers=[IDP_DOMAIN],
        audience=HUB_AUDIENCE,
        dpop_mode="optional",
    )
    _patch_verifier_jwks(monkeypatch, verifier, idp)

    agent = await verifier.verify(
        f"DPoP {token}",
        request_context={
            "method": "POST",
            "url": f"{HUB_AUDIENCE}/api/foo",
            "dpop_header": proof,
        },
    )
    assert agent.agent_id == ident.agent_id


@pytest.mark.asyncio
async def test_dpop_required_rejects_bearer(monkeypatch):
    """When the hub mandates DPoP, the legacy Bearer scheme is refused
    even if the token itself is otherwise valid."""
    idp = _StubIdP()
    ident = _make_agent_identity()
    agent_pub = ident._private_key.public_key().public_bytes_raw()
    token = idp.issue_token(agent_id=ident.agent_id, agent_pubkey_bytes=agent_pub)

    verifier = Verifier(
        trusted_providers=[IDP_DOMAIN],
        audience=HUB_AUDIENCE,
        dpop_mode="required",
    )
    _patch_verifier_jwks(monkeypatch, verifier, idp)

    with pytest.raises(TokenInvalidError, match="Bearer.*DPoP"):
        await verifier.verify(f"Bearer {token}")


@pytest.mark.asyncio
async def test_dpop_required_accepts_dpop_with_proof(monkeypatch):
    """Happy path for dpop_mode='required'."""
    idp = _StubIdP()
    ident = _make_agent_identity()
    agent_pub = ident._private_key.public_key().public_bytes_raw()
    token = idp.issue_token(agent_id=ident.agent_id, agent_pubkey_bytes=agent_pub)

    proof = ident.sign_dpop_proof(
        htm="POST",
        htu=f"{HUB_AUDIENCE}/api/foo",
        access_token=token,
    )

    verifier = Verifier(
        trusted_providers=[IDP_DOMAIN],
        audience=HUB_AUDIENCE,
        dpop_mode="required",
    )
    _patch_verifier_jwks(monkeypatch, verifier, idp)

    agent = await verifier.verify(
        f"DPoP {token}",
        request_context={
            "method": "POST",
            "url": f"{HUB_AUDIENCE}/api/foo",
            "dpop_header": proof,
        },
    )
    assert agent.agent_id == ident.agent_id


# ---------------------------------------------------------------------------
# End-to-end attack rejection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_thief_with_stolen_token_cannot_use_it(monkeypatch):
    """The canonical scenario from the design discussion:

    - Agent A obtains a real DPoP-bound JWT from the IdP.
    - Hub B / Agent B steals the JWT (via log scraping, MITM, etc.).
    - Thief tries to replay it at Hub A with their own signing key.

    Their DPoP proof's embedded jwk's thumbprint won't match the token's
    cnf.jkt, so Verifier rejects.
    """
    idp = _StubIdP()
    legitimate = _make_agent_identity()
    legit_pub = legitimate._private_key.public_key().public_bytes_raw()
    token = idp.issue_token(agent_id=legitimate.agent_id, agent_pubkey_bytes=legit_pub)

    # Attacker has the token but not the legitimate key.
    attacker = _make_agent_identity()  # different keypair
    attacker_proof = attacker.sign_dpop_proof(
        htm="POST",
        htu=f"{HUB_AUDIENCE}/api/foo",
        access_token=token,
    )

    verifier = Verifier(
        trusted_providers=[IDP_DOMAIN],
        audience=HUB_AUDIENCE,
        dpop_mode="required",
    )
    _patch_verifier_jwks(monkeypatch, verifier, idp)

    with pytest.raises(TokenInvalidError, match="DPoP"):
        await verifier.verify(
            f"DPoP {token}",
            request_context={
                "method": "POST",
                "url": f"{HUB_AUDIENCE}/api/foo",
                "dpop_header": attacker_proof,
            },
        )


@pytest.mark.asyncio
async def test_dpop_replay_at_same_endpoint_rejected(monkeypatch):
    """Even with the legitimate key, the same proof presented twice is
    rejected by the jti replay cache."""
    idp = _StubIdP()
    ident = _make_agent_identity()
    agent_pub = ident._private_key.public_key().public_bytes_raw()
    token = idp.issue_token(agent_id=ident.agent_id, agent_pubkey_bytes=agent_pub)

    proof = ident.sign_dpop_proof(
        htm="POST",
        htu=f"{HUB_AUDIENCE}/api/foo",
        access_token=token,
    )

    verifier = Verifier(
        trusted_providers=[IDP_DOMAIN],
        audience=HUB_AUDIENCE,
        dpop_mode="required",
    )
    _patch_verifier_jwks(monkeypatch, verifier, idp)

    # First use succeeds.
    await verifier.verify(
        f"DPoP {token}",
        request_context={
            "method": "POST",
            "url": f"{HUB_AUDIENCE}/api/foo",
            "dpop_header": proof,
        },
    )
    # Replay → rejected.
    with pytest.raises(TokenInvalidError, match="DPoP"):
        await verifier.verify(
            f"DPoP {token}",
            request_context={
                "method": "POST",
                "url": f"{HUB_AUDIENCE}/api/foo",
                "dpop_header": proof,
            },
        )


@pytest.mark.asyncio
async def test_dpop_required_with_no_cnf_in_token_rejected(monkeypatch):
    """Token issued without cnf.jkt (legacy / non-DPoP issuer). Hub in
    dpop_mode='required' must refuse — there's nothing to bind to."""
    idp = _StubIdP()
    ident = _make_agent_identity()
    agent_pub = ident._private_key.public_key().public_bytes_raw()
    token = idp.issue_token(
        agent_id=ident.agent_id,
        agent_pubkey_bytes=agent_pub,
        with_cnf=False,  # no cnf.jkt
    )

    proof = ident.sign_dpop_proof(
        htm="POST",
        htu=f"{HUB_AUDIENCE}/api/foo",
        access_token=token,
    )

    verifier = Verifier(
        trusted_providers=[IDP_DOMAIN],
        audience=HUB_AUDIENCE,
        dpop_mode="required",
    )
    _patch_verifier_jwks(monkeypatch, verifier, idp)

    with pytest.raises(TokenInvalidError, match="cnf"):
        await verifier.verify(
            f"DPoP {token}",
            request_context={
                "method": "POST",
                "url": f"{HUB_AUDIENCE}/api/foo",
                "dpop_header": proof,
            },
        )


@pytest.mark.asyncio
async def test_dpop_method_mismatch_rejected(monkeypatch):
    """Proof signed for POST, presented on GET → rejected."""
    idp = _StubIdP()
    ident = _make_agent_identity()
    agent_pub = ident._private_key.public_key().public_bytes_raw()
    token = idp.issue_token(agent_id=ident.agent_id, agent_pubkey_bytes=agent_pub)

    proof = ident.sign_dpop_proof(
        htm="POST",  # claims POST
        htu=f"{HUB_AUDIENCE}/api/foo",
        access_token=token,
    )

    verifier = Verifier(
        trusted_providers=[IDP_DOMAIN],
        audience=HUB_AUDIENCE,
        dpop_mode="required",
    )
    _patch_verifier_jwks(monkeypatch, verifier, idp)

    with pytest.raises(TokenInvalidError, match="DPoP"):
        await verifier.verify(
            f"DPoP {token}",
            request_context={
                "method": "GET",  # actual method differs
                "url": f"{HUB_AUDIENCE}/api/foo",
                "dpop_header": proof,
            },
        )


@pytest.mark.asyncio
async def test_dpop_disabled_ignores_dpop_scheme(monkeypatch):
    """Verifier with dpop_mode='disabled' should reject 'DPoP' as an unknown
    scheme — no DPoP support means clients SHOULD send Bearer."""
    idp = _StubIdP()
    ident = _make_agent_identity()
    agent_pub = ident._private_key.public_key().public_bytes_raw()
    token = idp.issue_token(agent_id=ident.agent_id, agent_pubkey_bytes=agent_pub)

    verifier = Verifier(
        trusted_providers=[IDP_DOMAIN],
        audience=HUB_AUDIENCE,
        dpop_mode="disabled",  # opt out of v0.6's "optional" default
    )
    _patch_verifier_jwks(monkeypatch, verifier, idp)

    with pytest.raises(TokenInvalidError, match="DPoP"):
        await verifier.verify(f"DPoP {token}")


# ---------------------------------------------------------------------------
# v0.6: bearer-deprecation warning under dpop_mode=optional
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_optional_bearer_with_cnf_logs_deprecation_warning(monkeypatch, caplog):
    """Under dpop_mode='optional', a Bearer request whose JWT carries cnf.jkt
    should emit a one-time deprecation warning per agent_id."""
    import logging

    idp = _StubIdP()
    ident = _make_agent_identity()
    agent_pub = ident._private_key.public_key().public_bytes_raw()
    token = idp.issue_token(agent_id=ident.agent_id, agent_pubkey_bytes=agent_pub)

    verifier = Verifier(
        trusted_providers=[IDP_DOMAIN],
        audience=HUB_AUDIENCE,
        dpop_mode="optional",
    )
    _patch_verifier_jwks(monkeypatch, verifier, idp)

    with caplog.at_level(logging.WARNING, logger="agent_id_service_sdk.verifier"):
        await verifier.verify(f"Bearer {token}")
        # Same agent again: should NOT emit a second warning (dedup).
        await verifier.verify(f"Bearer {token}")

    deprecation_msgs = [
        r for r in caplog.records if "Bearer" in r.message and "DPoP" in r.message
    ]
    assert len(deprecation_msgs) == 1, (
        f"expected exactly one deprecation warning, got {len(deprecation_msgs)}: "
        f"{[r.message for r in deprecation_msgs]}"
    )
    assert ident.agent_id in deprecation_msgs[0].getMessage()


@pytest.mark.asyncio
async def test_optional_bearer_without_cnf_does_not_warn(monkeypatch, caplog):
    """If the IdP didn't bind the token (no cnf.jkt), don't pester the caller
    to upgrade — there's nothing to upgrade to."""
    import logging

    idp = _StubIdP()
    ident = _make_agent_identity()
    agent_pub = ident._private_key.public_key().public_bytes_raw()
    token = idp.issue_token(
        agent_id=ident.agent_id, agent_pubkey_bytes=agent_pub, with_cnf=False
    )

    verifier = Verifier(
        trusted_providers=[IDP_DOMAIN],
        audience=HUB_AUDIENCE,
        dpop_mode="optional",
    )
    _patch_verifier_jwks(monkeypatch, verifier, idp)

    with caplog.at_level(logging.WARNING, logger="agent_id_service_sdk.verifier"):
        await verifier.verify(f"Bearer {token}")

    deprecation_msgs = [
        r for r in caplog.records if "Bearer" in r.message and "DPoP" in r.message
    ]
    assert deprecation_msgs == []


@pytest.mark.asyncio
async def test_disabled_bearer_with_cnf_does_not_warn(monkeypatch, caplog):
    """Operators who pinned dpop_mode='disabled' have already made the choice;
    no need to nag them in logs."""
    import logging

    idp = _StubIdP()
    ident = _make_agent_identity()
    agent_pub = ident._private_key.public_key().public_bytes_raw()
    token = idp.issue_token(agent_id=ident.agent_id, agent_pubkey_bytes=agent_pub)

    verifier = Verifier(
        trusted_providers=[IDP_DOMAIN],
        audience=HUB_AUDIENCE,
        dpop_mode="disabled",
    )
    _patch_verifier_jwks(monkeypatch, verifier, idp)

    with caplog.at_level(logging.WARNING, logger="agent_id_service_sdk.verifier"):
        await verifier.verify(f"Bearer {token}")

    deprecation_msgs = [
        r for r in caplog.records if "Bearer" in r.message and "DPoP" in r.message
    ]
    assert deprecation_msgs == []
