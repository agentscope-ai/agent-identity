"""Tests for DPoP — RFC 9449 sender-constrained access tokens.

Covers verify_dpop_proof:
- Happy round-trip
- Thumbprint binding (proof key thumbprint must match cnf.jkt)
- HTTP binding (htm / htu must match request method / URL)
- Skew window
- Replay (jti seen twice)
- ath binding (proof commits to access token hash)
- Malformed inputs (typ, alg, missing claims, private key in jwk header)
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
from typing import Any

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_id_service_sdk.dpop import (
    DPoPBindingError,
    DPoPHTTPBindingError,
    DPoPMalformedError,
    DPoPReplayError,
    DPoPSignatureError,
    DPoPSkewError,
    DPoPTokenBindingError,
    InMemoryReplayCache,
    jwk_thumbprint,
    verify_dpop_proof,
)


# ---------------------------------------------------------------------------
# Helpers — build proofs from raw materials
# ---------------------------------------------------------------------------


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _ath(access_token: str) -> str:
    return _b64u(hashlib.sha256(access_token.encode("ascii")).digest())


def _public_jwk(priv: Ed25519PrivateKey) -> dict[str, Any]:
    pub_bytes = priv.public_key().public_bytes_raw()
    return {"kty": "OKP", "crv": "Ed25519", "x": _b64u(pub_bytes)}


def _make_proof(
    priv: Ed25519PrivateKey,
    *,
    htm: str = "POST",
    htu: str = "https://hub.example.com/api/foo",
    access_token: str = "fake.access.token",
    iat: int | None = None,
    jti: str | None = None,
    override_jwk: dict[str, Any] | None = None,
    override_typ: str | None = None,
    omit_ath: bool = False,
) -> str:
    headers = {
        "alg": "EdDSA",
        "typ": override_typ if override_typ is not None else "dpop+jwt",
        "jwk": override_jwk if override_jwk is not None else _public_jwk(priv),
    }
    payload: dict[str, Any] = {
        "htm": htm,
        "htu": htu,
        "iat": iat if iat is not None else int(time.time()),
        "jti": jti if jti is not None else secrets.token_hex(16),
    }
    if not omit_ath:
        payload["ath"] = _ath(access_token)
    return pyjwt.encode(payload, priv, algorithm="EdDSA", headers=headers)


@pytest.fixture
def priv():
    return Ed25519PrivateKey.generate()


@pytest.fixture
def cnf_jkt(priv):
    return jwk_thumbprint(_public_jwk(priv))


@pytest.fixture
def access_token():
    return "header.payload.signature"


@pytest.fixture
def cache():
    return InMemoryReplayCache()


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------


def test_happy_path(priv, cnf_jkt, access_token, cache):
    proof = _make_proof(priv, access_token=access_token)
    claims = verify_dpop_proof(
        dpop_header=proof,
        access_token=access_token,
        cnf_jkt=cnf_jkt,
        http_method="POST",
        http_url="https://hub.example.com/api/foo",
        replay_cache=cache,
    )
    assert claims["htm"] == "POST"
    assert claims["htu"] == "https://hub.example.com/api/foo"


def test_htu_query_and_fragment_stripped(priv, cnf_jkt, access_token, cache):
    """Proof's htu can elide query/fragment; request URL too. Both normalized."""
    proof = _make_proof(
        priv,
        htu="https://hub.example.com/api/foo",
        access_token=access_token,
    )
    # Request URL has query + fragment; htu in proof doesn't.
    verify_dpop_proof(
        dpop_header=proof,
        access_token=access_token,
        cnf_jkt=cnf_jkt,
        http_method="POST",
        http_url="https://hub.example.com/api/foo?x=1#frag",
        replay_cache=cache,
    )


def test_method_case_insensitive(priv, cnf_jkt, access_token, cache):
    proof = _make_proof(priv, htm="POST", access_token=access_token)
    verify_dpop_proof(
        dpop_header=proof,
        access_token=access_token,
        cnf_jkt=cnf_jkt,
        http_method="post",
        http_url="https://hub.example.com/api/foo",
        replay_cache=cache,
    )


# ---------------------------------------------------------------------------
# Thumbprint binding — the load-bearing check
# ---------------------------------------------------------------------------


def test_rejects_when_proof_key_differs_from_cnf_jkt(priv, access_token, cache):
    """Attacker holds the access token but signs the proof with their own key.
    cnf.jkt was computed against the legitimate agent's key; the attacker's
    thumbprint doesn't match. Rejected."""
    attacker_priv = Ed25519PrivateKey.generate()
    legitimate_cnf_jkt = jwk_thumbprint(_public_jwk(priv))
    proof = _make_proof(attacker_priv, access_token=access_token)
    with pytest.raises(DPoPBindingError):
        verify_dpop_proof(
            dpop_header=proof,
            access_token=access_token,
            cnf_jkt=legitimate_cnf_jkt,
            http_method="POST",
            http_url="https://hub.example.com/api/foo",
            replay_cache=cache,
        )


def test_rejects_when_jwk_swapped_in_header(priv, cnf_jkt, access_token, cache):
    """Attacker tampers with the embedded jwk to be their own (but still signs
    with the original key). Thumbprint check catches it first; signature would
    also fail."""
    attacker_priv = Ed25519PrivateKey.generate()
    # Build a proof signed by `priv` but lying about the jwk in the header.
    bad_proof = _make_proof(
        priv,
        access_token=access_token,
        override_jwk=_public_jwk(attacker_priv),
    )
    with pytest.raises((DPoPBindingError, DPoPSignatureError)):
        verify_dpop_proof(
            dpop_header=bad_proof,
            access_token=access_token,
            cnf_jkt=cnf_jkt,
            http_method="POST",
            http_url="https://hub.example.com/api/foo",
            replay_cache=cache,
        )


# ---------------------------------------------------------------------------
# HTTP binding
# ---------------------------------------------------------------------------


def test_rejects_method_mismatch(priv, cnf_jkt, access_token, cache):
    proof = _make_proof(priv, htm="POST", access_token=access_token)
    with pytest.raises(DPoPHTTPBindingError):
        verify_dpop_proof(
            dpop_header=proof,
            access_token=access_token,
            cnf_jkt=cnf_jkt,
            http_method="GET",
            http_url="https://hub.example.com/api/foo",
            replay_cache=cache,
        )


def test_rejects_url_mismatch(priv, cnf_jkt, access_token, cache):
    proof = _make_proof(
        priv,
        htu="https://hub.example.com/api/foo",
        access_token=access_token,
    )
    with pytest.raises(DPoPHTTPBindingError):
        verify_dpop_proof(
            dpop_header=proof,
            access_token=access_token,
            cnf_jkt=cnf_jkt,
            http_method="POST",
            http_url="https://hub.example.com/api/different",
            replay_cache=cache,
        )


def test_rejects_replay_from_other_endpoint(priv, cnf_jkt, access_token, cache):
    """A proof captured from a request to hub-b can't be used at hub-a.
    The htu binding catches it before the jti check."""
    proof = _make_proof(
        priv,
        htu="https://evil-hub.example.com/api/foo",
        access_token=access_token,
    )
    with pytest.raises(DPoPHTTPBindingError):
        verify_dpop_proof(
            dpop_header=proof,
            access_token=access_token,
            cnf_jkt=cnf_jkt,
            http_method="POST",
            http_url="https://hub.example.com/api/foo",
            replay_cache=cache,
        )


# ---------------------------------------------------------------------------
# Skew
# ---------------------------------------------------------------------------


def test_rejects_stale_iat(priv, cnf_jkt, access_token, cache):
    proof = _make_proof(priv, iat=int(time.time()) - 600, access_token=access_token)
    with pytest.raises(DPoPSkewError):
        verify_dpop_proof(
            dpop_header=proof,
            access_token=access_token,
            cnf_jkt=cnf_jkt,
            http_method="POST",
            http_url="https://hub.example.com/api/foo",
            replay_cache=cache,
        )


def test_rejects_future_iat(priv, cnf_jkt, access_token, cache):
    proof = _make_proof(priv, iat=int(time.time()) + 600, access_token=access_token)
    with pytest.raises(DPoPSkewError):
        verify_dpop_proof(
            dpop_header=proof,
            access_token=access_token,
            cnf_jkt=cnf_jkt,
            http_method="POST",
            http_url="https://hub.example.com/api/foo",
            replay_cache=cache,
        )


# ---------------------------------------------------------------------------
# Replay
# ---------------------------------------------------------------------------


def test_rejects_replay_same_jti(priv, cnf_jkt, access_token, cache):
    jti = secrets.token_hex(16)
    iat = int(time.time())
    proof1 = _make_proof(priv, access_token=access_token, jti=jti, iat=iat)
    verify_dpop_proof(
        dpop_header=proof1,
        access_token=access_token,
        cnf_jkt=cnf_jkt,
        http_method="POST",
        http_url="https://hub.example.com/api/foo",
        replay_cache=cache,
    )
    # Second presentation of the same proof → reject.
    with pytest.raises(DPoPReplayError):
        verify_dpop_proof(
            dpop_header=proof1,
            access_token=access_token,
            cnf_jkt=cnf_jkt,
            http_method="POST",
            http_url="https://hub.example.com/api/foo",
            replay_cache=cache,
        )


# ---------------------------------------------------------------------------
# ath binding (token-hash commitment)
# ---------------------------------------------------------------------------


def test_rejects_missing_ath_when_required(priv, cnf_jkt, access_token, cache):
    proof = _make_proof(priv, access_token=access_token, omit_ath=True)
    with pytest.raises(DPoPTokenBindingError):
        verify_dpop_proof(
            dpop_header=proof,
            access_token=access_token,
            cnf_jkt=cnf_jkt,
            http_method="POST",
            http_url="https://hub.example.com/api/foo",
            replay_cache=cache,
        )


def test_rejects_ath_for_different_token(priv, cnf_jkt, access_token, cache):
    """Attacker captures a proof intended for one token and tries to pair it
    with a different one."""
    proof = _make_proof(priv, access_token="some.other.token")
    with pytest.raises(DPoPTokenBindingError):
        verify_dpop_proof(
            dpop_header=proof,
            access_token=access_token,  # different from the one ath was computed for
            cnf_jkt=cnf_jkt,
            http_method="POST",
            http_url="https://hub.example.com/api/foo",
            replay_cache=cache,
        )


# ---------------------------------------------------------------------------
# Malformed inputs
# ---------------------------------------------------------------------------


def test_rejects_wrong_typ(priv, cnf_jkt, access_token, cache):
    proof = _make_proof(priv, access_token=access_token, override_typ="JWT")
    with pytest.raises(DPoPMalformedError):
        verify_dpop_proof(
            dpop_header=proof,
            access_token=access_token,
            cnf_jkt=cnf_jkt,
            http_method="POST",
            http_url="https://hub.example.com/api/foo",
            replay_cache=cache,
        )


def test_rejects_private_key_in_header(priv, cnf_jkt, access_token, cache):
    """A naive signer that pastes the whole keypair into the header leaks the
    private material. RFC 9449 §4.1 forbids it; we reject."""
    pub_bytes = priv.public_key().public_bytes_raw()
    leaked = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": _b64u(pub_bytes),
        "d": _b64u(priv.private_bytes_raw()),  # the leak
    }
    proof = _make_proof(priv, access_token=access_token, override_jwk=leaked)
    with pytest.raises(DPoPMalformedError):
        verify_dpop_proof(
            dpop_header=proof,
            access_token=access_token,
            cnf_jkt=cnf_jkt,
            http_method="POST",
            http_url="https://hub.example.com/api/foo",
            replay_cache=cache,
        )


def test_rejects_garbage_jws(cnf_jkt, access_token, cache):
    with pytest.raises(DPoPMalformedError):
        verify_dpop_proof(
            dpop_header="not.a.jws",
            access_token=access_token,
            cnf_jkt=cnf_jkt,
            http_method="POST",
            http_url="https://hub.example.com/api/foo",
            replay_cache=cache,
        )


# ---------------------------------------------------------------------------
# Replay cache duck-typing — make sure an external impl with the same Protocol
# is acceptable (the SDK should not require InMemoryReplayCache).
# ---------------------------------------------------------------------------


def test_accepts_duck_typed_replay_cache(priv, cnf_jkt, access_token):
    class _Cache:
        def __init__(self):
            self.seen: set[str] = set()

        def __contains__(self, jti):
            return jti in self.seen

        def add(self, jti, *, ttl_seconds):
            self.seen.add(jti)

    cache = _Cache()
    proof = _make_proof(priv, access_token=access_token)
    verify_dpop_proof(
        dpop_header=proof,
        access_token=access_token,
        cnf_jkt=cnf_jkt,
        http_method="POST",
        http_url="https://hub.example.com/api/foo",
        replay_cache=cache,
    )
    assert len(cache.seen) == 1
