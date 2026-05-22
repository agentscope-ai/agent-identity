"""Tests for client-side DPoP signing (Identity.sign_dpop_proof, Client.dpop)."""

from __future__ import annotations

import base64
import hashlib
import json
import time

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_id_client_sdk.client import Client
from agent_id_client_sdk.identity import Identity


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _make_identity() -> Identity:
    priv = Ed25519PrivateKey.generate()
    seed = priv.private_bytes_raw()
    return Identity(
        agent_id="agentid:localhost:8000:agent_x",
        kid="dummy-kid",
        private_key_bytes=seed,
        idp_url="http://localhost:8000",
    )


def _decode_unverified(jws: str) -> tuple[dict, dict]:
    """Return (header, payload) without signature verification."""
    parts = jws.split(".")
    pad = lambda s: s + "=" * (-len(s) % 4)  # noqa: E731
    header = json.loads(base64.urlsafe_b64decode(pad(parts[0])))
    payload = json.loads(base64.urlsafe_b64decode(pad(parts[1])))
    return header, payload


# ---------------------------------------------------------------------------
# Identity.public_jwk and sign_dpop_proof
# ---------------------------------------------------------------------------


def test_public_jwk_shape():
    ident = _make_identity()
    jwk = ident.public_jwk()
    assert jwk["kty"] == "OKP"
    assert jwk["crv"] == "Ed25519"
    assert isinstance(jwk["x"], str)
    assert "d" not in jwk  # no private key material


def test_dpop_proof_header_typ_alg_jwk():
    ident = _make_identity()
    proof = ident.sign_dpop_proof(
        htm="POST",
        htu="https://hub.example.com/api/foo",
        access_token="some.token",
    )
    header, _ = _decode_unverified(proof)
    assert header["typ"] == "dpop+jwt"
    assert header["alg"] == "EdDSA"
    assert header["jwk"] == ident.public_jwk()


def test_dpop_proof_payload_claims():
    ident = _make_identity()
    proof = ident.sign_dpop_proof(
        htm="post",  # input lowercase → output upper per RFC 9449
        htu="https://hub.example.com/api/foo",
        access_token="abc.def.ghi",
    )
    _, payload = _decode_unverified(proof)
    assert payload["htm"] == "POST"
    assert payload["htu"] == "https://hub.example.com/api/foo"
    assert isinstance(payload["iat"], int)
    assert abs(payload["iat"] - int(time.time())) < 5
    assert isinstance(payload["jti"], str) and len(payload["jti"]) >= 16
    expected_ath = _b64u(hashlib.sha256(b"abc.def.ghi").digest())
    assert payload["ath"] == expected_ath


def test_dpop_proof_no_ath_when_no_token():
    ident = _make_identity()
    proof = ident.sign_dpop_proof(
        htm="GET",
        htu="https://hub.example.com/api/foo",
    )
    _, payload = _decode_unverified(proof)
    assert "ath" not in payload


def test_dpop_proof_signature_verifies_against_embedded_jwk():
    """End-to-end: decode the proof using the jwk in its own header."""
    ident = _make_identity()
    proof = ident.sign_dpop_proof(
        htm="POST",
        htu="https://hub.example.com/api/foo",
        access_token="x.y.z",
    )
    header, _ = _decode_unverified(proof)
    pubkey = pyjwt.PyJWK(header["jwk"]).key
    # Will raise if signature is bad.
    decoded = pyjwt.decode(
        proof,
        pubkey,
        algorithms=["EdDSA"],
        options={"verify_aud": False, "verify_exp": False},
    )
    assert decoded["htm"] == "POST"


def test_dpop_proof_jti_uniqueness():
    ident = _make_identity()
    p1 = ident.sign_dpop_proof(htm="POST", htu="https://h/x", access_token="t")
    p2 = ident.sign_dpop_proof(htm="POST", htu="https://h/x", access_token="t")
    _, c1 = _decode_unverified(p1)
    _, c2 = _decode_unverified(p2)
    assert c1["jti"] != c2["jti"]


# ---------------------------------------------------------------------------
# Client.dpop wiring — header construction
# ---------------------------------------------------------------------------


def test_client_default_is_bearer():
    ident = _make_identity()
    client = Client(ident)
    headers: dict = {}
    client._attach_auth_headers(
        headers, method="POST", url="https://hub.example.com/api/foo", token="abc"
    )
    assert headers["Authorization"] == "Bearer abc"
    assert "DPoP" not in headers


def test_client_dpop_mode_sets_dpop_scheme_and_header():
    ident = _make_identity()
    client = Client(ident, dpop=True)
    headers: dict = {}
    client._attach_auth_headers(
        headers,
        method="POST",
        url="https://hub.example.com/api/foo",
        token="abc",
    )
    assert headers["Authorization"] == "DPoP abc"
    assert "DPoP" in headers
    # The DPoP header value is a JWS; verify shape.
    proof = headers["DPoP"]
    header, payload = _decode_unverified(proof)
    assert header["typ"] == "dpop+jwt"
    assert payload["htm"] == "POST"
    assert payload["htu"] == "https://hub.example.com/api/foo"
    assert payload["ath"] == _b64u(hashlib.sha256(b"abc").digest())


def test_client_dpop_each_call_signs_fresh_proof():
    """Re-attaching headers (e.g. on retry) MUST produce a fresh proof.
    Replaying a captured proof from a previous request is rejected by
    the verifier's jti cache and htu binding; refreshing per-call is
    structurally cheaper than figuring out which one to re-use."""
    ident = _make_identity()
    client = Client(ident, dpop=True)

    h1: dict = {}
    client._attach_auth_headers(
        h1, method="POST", url="https://hub.example.com/api/foo", token="abc"
    )
    h2: dict = {}
    client._attach_auth_headers(
        h2, method="POST", url="https://hub.example.com/api/foo", token="abc"
    )
    _, p1 = _decode_unverified(h1["DPoP"])
    _, p2 = _decode_unverified(h2["DPoP"])
    assert p1["jti"] != p2["jti"]


def test_client_dpop_to_bearer_cleans_dpop_header():
    """Edge: a header dict that previously had DPoP set is reused with bearer.
    The bearer path MUST remove the stale DPoP header so the verifier doesn't
    see an inconsistent pair."""
    ident = _make_identity()
    # Use dpop=False client, but pre-populate stale DPoP header.
    client = Client(ident, dpop=False)
    headers = {"DPoP": "stale.jws.bytes"}
    client._attach_auth_headers(headers, method="POST", url="https://h", token="abc")
    assert headers["Authorization"] == "Bearer abc"
    assert "DPoP" not in headers
