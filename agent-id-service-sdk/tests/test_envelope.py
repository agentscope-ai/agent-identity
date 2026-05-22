"""Tests for hub-signed outer-envelope auth (design §5.0).

Covers sign_envelope + verify_envelope:
- Happy round-trip
- Body integrity (sha256 mismatch rejected)
- Audience cross-check (envelope signed for one service, presented at another)
- Skew window (iat too old / too new)
- Replay protection (jti already seen)
- JWKS resolution (kid present, kid missing → force refresh, kid still missing → reject)
- Signature integrity (key swap, body tamper)
"""

from __future__ import annotations

import time
from typing import Any

import pytest
from agent_id_service_sdk.envelope import (
    EnvelopeBodyMismatchError,
    EnvelopeMalformedError,
    EnvelopeReplayError,
    EnvelopeSignatureError,
    EnvelopeSigningError,
    EnvelopeSkewError,
    sign_envelope,
    verify_envelope,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


HUB_ISS = "https://api.dojozero.live"
ACTIVITY_AUD = "https://activity.dojozero.live"
KID = "hub-key-1"


class _ReplayCache:
    """Minimal in-memory replay cache for tests. Real impl in aip-activity."""

    def __init__(self) -> None:
        self._seen: dict[str, float] = {}

    def __contains__(self, jti: str) -> bool:
        return jti in self._seen

    def add(self, jti: str, *, ttl_seconds: int) -> None:
        self._seen[jti] = time.time() + ttl_seconds


@pytest.fixture
def keypair():
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


@pytest.fixture
def jwks(keypair):
    """Single-key JWKS keyed by kid."""
    _, public_key = keypair
    return {KID: public_key}


@pytest.fixture
def resolver(jwks):
    """An async resolver that returns the configured JWKS."""

    async def _resolve(iss: str, *, force_refresh: bool) -> dict[str, Any]:
        # Tests parameterize via the closure jwks; force_refresh is
        # observable but doesn't change behavior for single-key tests.
        if iss != HUB_ISS:
            return {}
        return jwks

    return _resolve


@pytest.fixture
def replay_cache():
    return _ReplayCache()


# ---------------------------------------------------------------------------
# sign_envelope shape
# ---------------------------------------------------------------------------


class TestSignEnvelope:
    def test_returns_compact_jws(self, keypair):
        private_key, _ = keypair
        jws = sign_envelope(
            private_key=private_key,
            kid=KID,
            iss=HUB_ISS,
            aud=ACTIVITY_AUD,
            body=b'{"events":[]}',
        )
        # Compact JWS has two dots: header.payload.signature
        assert jws.count(".") == 2

    def test_unknown_algorithm_rejected(self, keypair):
        private_key, _ = keypair
        with pytest.raises(EnvelopeSigningError, match="algorithm"):
            sign_envelope(
                private_key=private_key,
                kid=KID,
                iss=HUB_ISS,
                aud=ACTIVITY_AUD,
                body=b"",
                algorithm="HS256",  # type: ignore[arg-type]
            )

    def test_missing_iss_rejected(self, keypair):
        private_key, _ = keypair
        with pytest.raises(EnvelopeSigningError, match="iss"):
            sign_envelope(
                private_key=private_key,
                kid=KID,
                iss="",
                aud=ACTIVITY_AUD,
                body=b"",
            )


# ---------------------------------------------------------------------------
# Happy round-trip
# ---------------------------------------------------------------------------


class TestRoundTrip:
    @pytest.mark.asyncio
    async def test_sign_then_verify_succeeds(self, keypair, resolver, replay_cache):
        private_key, _ = keypair
        body = b'{"events":[{"category":"tool.use"}]}'
        jws = sign_envelope(
            private_key=private_key,
            kid=KID,
            iss=HUB_ISS,
            aud=ACTIVITY_AUD,
            body=body,
        )
        claims = await verify_envelope(
            jws=jws,
            body=body,
            expected_aud=ACTIVITY_AUD,
            resolve_jwks_for_iss=resolver,
            replay_cache=replay_cache,
        )
        assert claims["iss"] == HUB_ISS
        assert claims["aud"] == ACTIVITY_AUD
        assert claims["body_sha256"]
        assert claims["jti"]
        assert claims["iat"] > 0
        # Privacy claim absent when signer doesn't supply one.
        assert "privacy" not in claims


class TestPrivacyClaim:
    """Hub privacy posture travels in the envelope (design §5.0).

    Replaces the prior X-AgentID-Token forwarding path: the hub asserts
    its policy in the signed envelope, no separate IdP-issued token
    needed.
    """

    @pytest.mark.asyncio
    async def test_privacy_claim_round_trips(self, keypair, resolver, replay_cache):
        private_key, _ = keypair
        body = b"{}"
        privacy = {
            "default_level": "summary",
            "category_overrides": {"transfer.value": "full"},
        }
        jws = sign_envelope(
            private_key=private_key,
            kid=KID,
            iss=HUB_ISS,
            aud=ACTIVITY_AUD,
            body=body,
            privacy=privacy,
        )
        claims = await verify_envelope(
            jws=jws,
            body=body,
            expected_aud=ACTIVITY_AUD,
            resolve_jwks_for_iss=resolver,
            replay_cache=replay_cache,
        )
        assert claims["privacy"] == privacy

    @pytest.mark.asyncio
    async def test_privacy_claim_is_signed(self, keypair, resolver, replay_cache):
        """The claim is part of the JWS payload — tampering breaks the
        signature, just like any other claim."""
        import jwt as pyjwt

        private_key, _ = keypair
        body = b"{}"
        jws = sign_envelope(
            private_key=private_key,
            kid=KID,
            iss=HUB_ISS,
            aud=ACTIVITY_AUD,
            body=body,
            privacy={"default_level": "summary"},
        )
        # Decode unsigned, mutate, re-encode without re-signing — should
        # fail signature verify.
        header = pyjwt.get_unverified_header(jws)
        payload = pyjwt.decode(jws, options={"verify_signature": False})
        payload["privacy"] = {"default_level": "full"}  # tamper
        # Re-encode with a *different* key — same as a real attack.
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )

        attacker_key = Ed25519PrivateKey.generate()
        tampered = pyjwt.encode(
            payload, attacker_key, algorithm="EdDSA", headers=header
        )
        from agent_id_service_sdk.envelope import EnvelopeSignatureError

        with pytest.raises(EnvelopeSignatureError):
            await verify_envelope(
                jws=tampered,
                body=body,
                expected_aud=ACTIVITY_AUD,
                resolve_jwks_for_iss=resolver,
                replay_cache=replay_cache,
            )


# ---------------------------------------------------------------------------
# Failure modes — each is a distinct exception type so callers can branch
# without string parsing.
# ---------------------------------------------------------------------------


class TestBodyMismatch:
    @pytest.mark.asyncio
    async def test_tampered_body_rejected(self, keypair, resolver, replay_cache):
        private_key, _ = keypair
        signed_body = b'{"events":[{"category":"tool.use"}]}'
        jws = sign_envelope(
            private_key=private_key,
            kid=KID,
            iss=HUB_ISS,
            aud=ACTIVITY_AUD,
            body=signed_body,
        )
        # Verifier sees a different body than what the signer committed to.
        tampered = b'{"events":[{"category":"transfer.value"}]}'
        with pytest.raises(EnvelopeBodyMismatchError):
            await verify_envelope(
                jws=jws,
                body=tampered,
                expected_aud=ACTIVITY_AUD,
                resolve_jwks_for_iss=resolver,
                replay_cache=replay_cache,
            )


class TestAudienceCrossCheck:
    @pytest.mark.asyncio
    async def test_envelope_for_other_service_rejected(
        self, keypair, resolver, replay_cache
    ):
        private_key, _ = keypair
        body = b"{}"
        # Signer says the envelope is for activity_a.
        jws = sign_envelope(
            private_key=private_key,
            kid=KID,
            iss=HUB_ISS,
            aud="https://activity-a.example.com",
            body=body,
        )
        # Verifier is activity_b — must reject (replay across services).
        with pytest.raises(EnvelopeSignatureError, match="aud"):
            await verify_envelope(
                jws=jws,
                body=body,
                expected_aud="https://activity-b.example.com",
                resolve_jwks_for_iss=resolver,
                replay_cache=replay_cache,
            )


class TestSkewWindow:
    @pytest.mark.asyncio
    async def test_iat_too_old_rejected(self, keypair, resolver, replay_cache):
        private_key, _ = keypair
        body = b"{}"
        old_iat = int(time.time()) - 600
        jws = sign_envelope(
            private_key=private_key,
            kid=KID,
            iss=HUB_ISS,
            aud=ACTIVITY_AUD,
            body=body,
            iat=old_iat,
        )
        with pytest.raises(EnvelopeSkewError):
            await verify_envelope(
                jws=jws,
                body=body,
                expected_aud=ACTIVITY_AUD,
                resolve_jwks_for_iss=resolver,
                replay_cache=replay_cache,
                max_skew_seconds=60,
            )

    @pytest.mark.asyncio
    async def test_iat_too_new_rejected(self, keypair, resolver, replay_cache):
        private_key, _ = keypair
        body = b"{}"
        future_iat = int(time.time()) + 600
        jws = sign_envelope(
            private_key=private_key,
            kid=KID,
            iss=HUB_ISS,
            aud=ACTIVITY_AUD,
            body=body,
            iat=future_iat,
        )
        with pytest.raises(EnvelopeSkewError):
            await verify_envelope(
                jws=jws,
                body=body,
                expected_aud=ACTIVITY_AUD,
                resolve_jwks_for_iss=resolver,
                replay_cache=replay_cache,
                max_skew_seconds=60,
            )


class TestReplayProtection:
    @pytest.mark.asyncio
    async def test_repeat_jti_rejected(self, keypair, resolver, replay_cache):
        private_key, _ = keypair
        body = b"{}"
        jws = sign_envelope(
            private_key=private_key,
            kid=KID,
            iss=HUB_ISS,
            aud=ACTIVITY_AUD,
            body=body,
            jti="constant-jti-for-test",
        )
        # First time succeeds.
        await verify_envelope(
            jws=jws,
            body=body,
            expected_aud=ACTIVITY_AUD,
            resolve_jwks_for_iss=resolver,
            replay_cache=replay_cache,
        )
        # Second time with the same jti is the replay attack we're blocking.
        with pytest.raises(EnvelopeReplayError):
            await verify_envelope(
                jws=jws,
                body=body,
                expected_aud=ACTIVITY_AUD,
                resolve_jwks_for_iss=resolver,
                replay_cache=replay_cache,
            )


class TestSignatureIntegrity:
    @pytest.mark.asyncio
    async def test_wrong_key_rejected(self, keypair, replay_cache):
        private_key, _ = keypair
        body = b"{}"
        jws = sign_envelope(
            private_key=private_key,
            kid=KID,
            iss=HUB_ISS,
            aud=ACTIVITY_AUD,
            body=body,
        )
        # Resolver returns a *different* public key for the kid.
        wrong_pub = Ed25519PrivateKey.generate().public_key()

        async def _bad_resolver(iss, *, force_refresh):
            return {KID: wrong_pub}

        with pytest.raises(EnvelopeSignatureError):
            await verify_envelope(
                jws=jws,
                body=body,
                expected_aud=ACTIVITY_AUD,
                resolve_jwks_for_iss=_bad_resolver,
                replay_cache=replay_cache,
            )

    @pytest.mark.asyncio
    async def test_unknown_kid_triggers_refresh(self, keypair, replay_cache):
        """First resolution misses; force-refresh finds the key. This
        is the rotation-recovery case: aip-activity has a stale JWKS,
        the hub rotated, force-refresh repulls and the kid is now there."""
        private_key, public_key = keypair
        body = b"{}"
        jws = sign_envelope(
            private_key=private_key,
            kid=KID,
            iss=HUB_ISS,
            aud=ACTIVITY_AUD,
            body=body,
        )
        calls: list[bool] = []

        async def _resolver(iss, *, force_refresh):
            calls.append(force_refresh)
            return {KID: public_key} if force_refresh else {}

        claims = await verify_envelope(
            jws=jws,
            body=body,
            expected_aud=ACTIVITY_AUD,
            resolve_jwks_for_iss=_resolver,
            replay_cache=replay_cache,
        )
        # First call is the cache-hit path (returns {}); second is the
        # force-refresh that found the key.
        assert calls == [False, True]
        assert claims["iss"] == HUB_ISS

    @pytest.mark.asyncio
    async def test_unknown_kid_after_refresh_still_rejected(
        self, keypair, replay_cache
    ):
        private_key, _ = keypair
        body = b"{}"
        jws = sign_envelope(
            private_key=private_key,
            kid=KID,
            iss=HUB_ISS,
            aud=ACTIVITY_AUD,
            body=body,
        )

        async def _empty_resolver(iss, *, force_refresh):
            return {}

        with pytest.raises(EnvelopeSignatureError, match="no key with kid"):
            await verify_envelope(
                jws=jws,
                body=body,
                expected_aud=ACTIVITY_AUD,
                resolve_jwks_for_iss=_empty_resolver,
                replay_cache=replay_cache,
            )


class TestMalformed:
    @pytest.mark.asyncio
    async def test_garbage_jws_rejected(self, resolver, replay_cache):
        with pytest.raises(EnvelopeMalformedError):
            await verify_envelope(
                jws="not.a.jws",
                body=b"{}",
                expected_aud=ACTIVITY_AUD,
                resolve_jwks_for_iss=resolver,
                replay_cache=replay_cache,
            )
