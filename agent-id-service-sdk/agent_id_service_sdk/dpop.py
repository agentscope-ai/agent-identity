"""DPoP — Demonstrating Proof of Possession (RFC 9449) for access tokens.

DPoP binds a bearer-shaped access token to a holder key pair: even if the
token leaks, a thief cannot use it without the matching private key. The
holder presents *two* headers on each request:

    Authorization: DPoP <access_token>
    DPoP: <proof_jws>

The access token has been issued with a ``cnf.jkt`` claim (RFC 7638 JWK
thumbprint of the holder's public key). The ``DPoP`` header is a short
JWS whose payload commits to the HTTP method, URL, current time, a
random nonce, and (optionally) the access token's hash. The JWS header
embeds the holder's public key inline via ``jwk``.

A resource server verifies:

  1. Standard access-token validation (signature, aud, exp, ...).
  2. The DPoP JWS signature against the ``jwk`` in its header.
  3. The thumbprint of that ``jwk`` equals the access token's ``cnf.jkt``
     — proving the proof signer is the certified holder.
  4. ``htm`` and ``htu`` match the actual request method and URL.
  5. ``iat`` is within an acceptable skew window.
  6. (When ``ath`` is present) ``base64url(sha256(access_token))`` matches.
  7. ``jti`` has not been seen recently (replay-cache).

Attack defeated: a thief holds the access token but not the holder's
private key; they cannot sign a DPoP proof whose embedded ``jwk`` matches
``cnf.jkt``, so step 3 fails. Reusing a captured proof fails step 4
(different ``htu``) or step 7 (replay cache). Hub-side leak surfaces
(access logs, telemetry, IPC) stop being credential-compromise events.

This module:
  * Defines :func:`verify_dpop_proof` — the entry point a Verifier calls.
  * Provides :class:`InMemoryReplayCache` — duck-typed for the same
    ``__contains__`` / ``add`` Protocol used by :mod:`agent_id_service_sdk.envelope`.
  * Provides :func:`jwk_thumbprint` for JWK-dict inputs (the IdP-side
    pubkey-bytes variant lives in :mod:`agent_id_service_sdk` callers).
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from typing import Any, Literal
from urllib.parse import urlparse

import jwt as pyjwt


_ACCEPTED_ALGS: tuple[Literal["EdDSA", "ES256"], ...] = ("EdDSA", "ES256")
_REQUIRED_CLAIMS = ("htm", "htu", "iat", "jti")
_DPOP_TYP = "dpop+jwt"


# ---------------------------------------------------------------------------
# Exception hierarchy — caller can catch DPoPError broadly or each subtype
# specifically for branchable error responses.
# ---------------------------------------------------------------------------


class DPoPError(Exception):
    """Base class for all DPoP verification failures."""


class DPoPMalformedError(DPoPError):
    """JWS structure wrong, required claims missing, or typ/alg unacceptable."""


class DPoPSignatureError(DPoPError):
    """JWS signature didn't verify against the embedded jwk."""


class DPoPBindingError(DPoPError):
    """The DPoP key's thumbprint doesn't match the access token's cnf.jkt."""


class DPoPHTTPBindingError(DPoPError):
    """htm/htu in the proof don't match the actual request method/URL."""


class DPoPSkewError(DPoPError):
    """iat is outside the accepted skew window."""


class DPoPReplayError(DPoPError):
    """jti has already been seen within the replay-cache window."""


class DPoPTokenBindingError(DPoPError):
    """ath claim is present but doesn't match sha256 of the access token."""


# ---------------------------------------------------------------------------
# Thumbprint helper for JWK dicts
# ---------------------------------------------------------------------------


def jwk_thumbprint(jwk: dict[str, Any]) -> str:
    """Compute the RFC 7638 SHA-256 thumbprint of a JWK dictionary.

    Returns base64url-encoded SHA-256 digest of the canonical JWK form
    (REQUIRED members only, lexicographically sorted, no whitespace).
    Per RFC 7638:

        * OKP keys: ``crv``, ``kty``, ``x``
        * EC keys:  ``crv``, ``kty``, ``x``, ``y``
        * RSA keys: ``e``, ``kty``, ``n``
        * oct keys: ``k``, ``kty``

    Anything else raises :class:`DPoPMalformedError`.
    """
    kty = jwk.get("kty")
    if kty == "OKP":
        required = ("crv", "kty", "x")
    elif kty == "EC":
        required = ("crv", "kty", "x", "y")
    elif kty == "RSA":
        required = ("e", "kty", "n")
    elif kty == "oct":
        required = ("k", "kty")
    else:
        raise DPoPMalformedError(f"unsupported JWK kty: {kty!r}")

    canonical_obj = {}
    for k in required:
        v = jwk.get(k)
        if not isinstance(v, str):
            raise DPoPMalformedError(f"JWK missing required member {k!r}")
        canonical_obj[k] = v

    canonical = json.dumps(canonical_obj, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )
    digest = hashlib.sha256(canonical).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


# ---------------------------------------------------------------------------
# In-memory replay cache (duck-types the envelope.py protocol)
# ---------------------------------------------------------------------------


class InMemoryReplayCache:
    """Single-process replay cache with lazy TTL eviction.

    Duck-typed for the same Protocol used by :mod:`agent_id_service_sdk.envelope`:
    ``__contains__(jti) -> bool``, ``add(jti, ttl_seconds)``.

    For multi-instance deployments, swap with a Redis-backed implementation
    that exposes the same interface.
    """

    def __init__(self) -> None:
        self._seen: dict[str, float] = {}

    def __contains__(self, jti: str) -> bool:
        expiry = self._seen.get(jti)
        if expiry is None:
            return False
        if time.time() > expiry:
            # Stale: pop and treat as not seen.
            self._seen.pop(jti, None)
            return False
        return True

    def add(self, jti: str, *, ttl_seconds: int) -> None:
        # Opportunistic sweep to bound memory growth.
        now = time.time()
        if len(self._seen) > 1024 and len(self._seen) % 64 == 0:
            self._seen = {k: v for k, v in self._seen.items() if v > now}
        self._seen[jti] = now + ttl_seconds


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ath_for_token(access_token: str) -> str:
    """RFC 9449 §4.2: ath = base64url(sha256(access_token))."""
    digest = hashlib.sha256(access_token.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _normalize_htu(url: str) -> str:
    """Per RFC 9449 §4.3, htu MUST equal the URL of the request excluding
    fragment and query. We compare scheme+netloc+path; query/fragment are
    stripped. Scheme/host lowercased."""
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path or ""
    return f"{scheme}://{netloc}{path}"


def _jwk_to_pyjwt_key(jwk: dict[str, Any]):
    """Convert a JWK dict (as embedded in a DPoP header) into a pyjwt-usable
    public key object. pyjwt's PyJWK accepts a JWK dict directly."""
    return pyjwt.PyJWK(jwk).key


# ---------------------------------------------------------------------------
# Verification entry point
# ---------------------------------------------------------------------------


def verify_dpop_proof(
    *,
    dpop_header: str,
    access_token: str,
    cnf_jkt: str,
    http_method: str,
    http_url: str,
    replay_cache,
    max_skew_seconds: int = 60,
    replay_ttl_seconds: int = 120,
    require_ath: bool = True,
    now: int | None = None,
) -> dict[str, Any]:
    """Verify a DPoP proof attached to an access-token-protected request.

    Args:
        dpop_header: Raw value of the ``DPoP`` HTTP header (a compact JWS).
        access_token: The presented access token (the JWT after the
            ``DPoP`` Authorization scheme).
        cnf_jkt: The ``cnf.jkt`` thumbprint claimed by the access token —
            the thumbprint the proof's embedded jwk MUST match.
        http_method: The actual HTTP method of the incoming request
            (case-insensitive; compared upper-cased).
        http_url: The actual full URL of the incoming request. Query
            string and fragment are stripped before comparison.
        replay_cache: Object with ``__contains__(jti)`` and
            ``add(jti, ttl_seconds)``. See :class:`InMemoryReplayCache`.
        max_skew_seconds: ``|now - iat|`` tolerance. Default 60.
        replay_ttl_seconds: How long a ``jti`` is remembered. Should be
            ``>= 2 * max_skew_seconds`` so a replay during the skew window
            is always caught. Default 120.
        require_ath: When True (default), the proof MUST include ``ath``
            matching ``base64url(sha256(access_token))``. Setting False
            permits proofs intended for unprotected resources (rare).
        now: Override the current time (testing only).

    Returns:
        The parsed proof claims dict on success.

    Raises:
        DPoPMalformedError: structure / typ / alg / required-claim issue.
        DPoPSignatureError: JWS signature didn't verify.
        DPoPBindingError: embedded jwk's thumbprint != cnf.jkt.
        DPoPHTTPBindingError: htm/htu mismatch.
        DPoPSkewError: iat outside skew window.
        DPoPReplayError: jti already seen.
        DPoPTokenBindingError: ath missing or mismatched.
    """
    # 1. Parse header + claims unverified (we need jwk before verifying sig).
    try:
        unverified_header = pyjwt.get_unverified_header(dpop_header)
        unverified_claims = pyjwt.decode(
            dpop_header, options={"verify_signature": False}
        )
    except Exception as exc:
        raise DPoPMalformedError(f"could not parse DPoP JWS: {exc}") from exc

    # 2. Header typ/alg/jwk checks.
    typ = unverified_header.get("typ")
    if typ != _DPOP_TYP:
        raise DPoPMalformedError(f"DPoP typ must be {_DPOP_TYP!r}, got {typ!r}")

    alg = unverified_header.get("alg")
    if alg not in _ACCEPTED_ALGS:
        raise DPoPMalformedError(
            f"DPoP alg must be one of {_ACCEPTED_ALGS}, got {alg!r}"
        )

    jwk = unverified_header.get("jwk")
    if not isinstance(jwk, dict):
        raise DPoPMalformedError("DPoP header missing jwk (required by RFC 9449)")

    # 2a. Reject private-key JWKs in the proof header. The header MUST carry
    # only the public components; a smart-but-naive signer that passes the
    # whole keypair would leak it. RFC 9449 §4.1.
    for private_member in ("d", "p", "q", "dp", "dq", "qi", "k"):
        if private_member in jwk:
            raise DPoPMalformedError(
                f"DPoP jwk header MUST NOT contain private member {private_member!r}"
            )

    # 3. Thumbprint binding — the cnf.jkt-matters check.
    proof_thumbprint = jwk_thumbprint(jwk)
    if proof_thumbprint != cnf_jkt:
        raise DPoPBindingError(
            f"DPoP key thumbprint {proof_thumbprint!r} != cnf.jkt {cnf_jkt!r}"
        )

    # 4. Required claims present.
    missing = [c for c in _REQUIRED_CLAIMS if c not in unverified_claims]
    if missing:
        raise DPoPMalformedError(f"DPoP claims missing required: {', '.join(missing)}")

    # 5. Verify signature against the embedded jwk.
    try:
        public_key = _jwk_to_pyjwt_key(jwk)
        verified = pyjwt.decode(
            dpop_header,
            public_key,
            algorithms=list(_ACCEPTED_ALGS),
            options={
                "verify_aud": False,
                "verify_exp": False,
                "verify_iat": False,
            },
        )
    except pyjwt.PyJWTError as exc:
        raise DPoPSignatureError(f"DPoP signature invalid: {exc}") from exc
    except Exception as exc:
        raise DPoPMalformedError(f"DPoP jwk unusable for verification: {exc}") from exc

    # 6. htm/htu binding.
    claimed_htm = verified.get("htm")
    if not isinstance(claimed_htm, str) or claimed_htm.upper() != http_method.upper():
        raise DPoPHTTPBindingError(
            f"DPoP htm {claimed_htm!r} doesn't match request method {http_method!r}"
        )

    claimed_htu = verified.get("htu")
    expected_htu = _normalize_htu(http_url)
    if not isinstance(claimed_htu, str) or _normalize_htu(claimed_htu) != expected_htu:
        raise DPoPHTTPBindingError(
            f"DPoP htu {claimed_htu!r} doesn't match request URL {expected_htu!r}"
        )

    # 7. iat skew.
    iat = verified.get("iat")
    if not isinstance(iat, (int, float)):
        raise DPoPMalformedError("DPoP iat must be a number")
    n = now if now is not None else int(time.time())
    if abs(n - int(iat)) > max_skew_seconds:
        raise DPoPSkewError(
            f"DPoP iat={iat} outside ±{max_skew_seconds}s window from {n}"
        )

    # 8. ath binding (when verifying against an access token).
    if require_ath:
        ath = verified.get("ath")
        expected_ath = _ath_for_token(access_token)
        if not isinstance(ath, str):
            raise DPoPTokenBindingError(
                "DPoP ath claim required when verifying against an access token"
            )
        if ath != expected_ath:
            raise DPoPTokenBindingError(
                "DPoP ath claim does not match sha256(access_token)"
            )

    # 9. Replay cache.
    jti = verified["jti"]
    if not isinstance(jti, str):
        raise DPoPMalformedError("DPoP jti must be a string")
    if jti in replay_cache:
        raise DPoPReplayError(f"DPoP jti={jti!r} already seen")
    replay_cache.add(jti, ttl_seconds=replay_ttl_seconds)

    return verified


__all__ = [
    "DPoPError",
    "DPoPMalformedError",
    "DPoPSignatureError",
    "DPoPBindingError",
    "DPoPHTTPBindingError",
    "DPoPSkewError",
    "DPoPReplayError",
    "DPoPTokenBindingError",
    "InMemoryReplayCache",
    "jwk_thumbprint",
    "verify_dpop_proof",
]
