"""Hub-signed outer envelope for activity ingest auth.

Per the activity-discovery design doc §5.0: hubs authenticate to
``aip-activity`` by signing each ``POST /agentid/activity`` with a
JWS-compact envelope, presented as ``Authorization: HubJWS <jws>``.

The envelope's claims include a sha256 of the raw request body, an
``iat`` for skew checking, and a ``jti`` nonce for replay protection.
The activity service:

  1. Parses the JWS (untrusted) to extract ``iss`` (hub service_id) and
     ``kid``.
  2. Fetches the hub's JWKS via ``HubManifestFetcher.fetch(iss)`` and
     verifies the signature.
  3. Confirms ``body_sha256`` matches the request body.
  4. Confirms ``iat`` is within ±``max_skew_seconds`` (default 60).
  5. Confirms ``jti`` isn't in the replay cache.

This module is the symmetric counterpart of the verifier path: the
:func:`sign_envelope` that the hub calls and the :func:`verify_envelope`
that the activity service calls. Both share enough logic that keeping
them in one module avoids drift.
"""

from __future__ import annotations

import hashlib
import secrets
import time
from typing import Any, Literal

import jwt as pyjwt


_ACCEPTED_ALGS: tuple[Literal["EdDSA", "ES256"], ...] = ("EdDSA", "ES256")
_REQUIRED_CLAIMS = ("iss", "aud", "iat", "jti", "body_sha256")


class EnvelopeSigningError(Exception):
    """Raised when the inputs to :func:`sign_envelope` are invalid."""


class EnvelopeVerificationError(Exception):
    """Raised when an envelope fails verification.

    Subclasses make the failure mode loggable / branchable without
    string parsing. All inherit from this base so a catch-all
    ``except EnvelopeVerificationError`` works.
    """


class EnvelopeSignatureError(EnvelopeVerificationError):
    """JWS signature didn't verify, or the kid wasn't found in the JWKS."""


class EnvelopeBodyMismatchError(EnvelopeVerificationError):
    """The body_sha256 claim doesn't match the actual request body."""


class EnvelopeSkewError(EnvelopeVerificationError):
    """The iat claim is outside the accepted skew window."""


class EnvelopeReplayError(EnvelopeVerificationError):
    """The jti has already been seen within the replay cache window."""


class EnvelopeMalformedError(EnvelopeVerificationError):
    """JWS structure is wrong, claims are missing, or values have the wrong type."""


def _body_sha256(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def sign_envelope(
    *,
    private_key: Any,
    kid: str,
    iss: str,
    aud: str,
    body: bytes,
    algorithm: Literal["EdDSA", "ES256"] = "EdDSA",
    iat: int | None = None,
    jti: str | None = None,
) -> str:
    """Sign an outer envelope for one ``POST /agentid/activity`` request.

    Args:
        private_key: Hub's private key (Ed25519 or ECDSA P-256).
        kid: Key id matching one published in the hub's JWKS.
        iss: Hub's ``service_id`` (= manifest.service_id).
        aud: Activity service origin (e.g. ``https://activity.dojozero.live``).
        body: The exact request body bytes that will be sent. The hash
            commits the signer to *these* bytes — the verifier hashes
            what it receives and compares.
        algorithm: ``EdDSA`` (default) or ``ES256``.
        iat: Override the issued-at timestamp (testing only). Defaults
            to ``time.time()``.
        jti: Override the nonce (testing only). Defaults to
            ``secrets.token_hex(16)``.

    Returns:
        Compact JWS string, ready for ``Authorization: HubJWS <jws>``.
    """
    if algorithm not in _ACCEPTED_ALGS:
        raise EnvelopeSigningError(
            f"algorithm must be one of {_ACCEPTED_ALGS} (got {algorithm!r})"
        )
    if not iss or not aud or not kid:
        raise EnvelopeSigningError("iss, aud, and kid are all required")

    claims: dict[str, Any] = {
        "iss": iss,
        "aud": aud,
        "iat": iat if iat is not None else int(time.time()),
        "jti": jti if jti is not None else secrets.token_hex(16),
        "body_sha256": _body_sha256(body),
    }
    return pyjwt.encode(
        claims,
        private_key,
        algorithm=algorithm,
        headers={"kid": kid, "typ": "hub-envelope+jws"},
    )


async def verify_envelope(
    *,
    jws: str,
    body: bytes,
    expected_aud: str,
    resolve_jwks_for_iss,
    replay_cache,
    max_skew_seconds: int = 60,
    replay_ttl_seconds: int = 120,
    now: int | None = None,
) -> dict[str, Any]:
    """Verify a HubJWS envelope; returns the parsed claims on success.

    Args:
        jws: The compact JWS from ``Authorization: HubJWS <jws>``.
        body: The actual request body bytes received.
        expected_aud: This service's origin. Rejected if the envelope's
            ``aud`` claim doesn't match — defends against an envelope
            captured from one activity service being replayed at another.
        resolve_jwks_for_iss: Async callable
            ``(iss: str, *, force_refresh: bool) -> dict[kid, public_key]``.
            Called once normally, again with ``force_refresh=True`` if
            the kid isn't found.
        replay_cache: Object with ``__contains__(jti)`` (sync) and
            ``add(jti, ttl_seconds: int)`` (sync). The cache TTL is the
            insertion TTL; expiry is the cache's responsibility.
        max_skew_seconds: ``|now - iat|`` window. Default 60.
        replay_ttl_seconds: How long to remember a ``jti`` after first
            sight. Should be ``>= 2 * max_skew_seconds``. Default 120.
        now: Override current time (testing only).

    Returns:
        The parsed claims dict on success. ``iss`` is the authenticated
        hub's ``service_id``.

    Raises:
        EnvelopeMalformedError: JWS structure / required-claim issue.
        EnvelopeSignatureError: Signature mismatch or unknown kid.
        EnvelopeBodyMismatchError: ``body_sha256`` doesn't match the
            request body.
        EnvelopeSkewError: ``iat`` outside the skew window.
        EnvelopeReplayError: ``jti`` already in the cache.
    """
    try:
        unverified_header = pyjwt.get_unverified_header(jws)
        unverified_claims = pyjwt.decode(jws, options={"verify_signature": False})
    except Exception as exc:
        raise EnvelopeMalformedError(f"could not parse envelope JWS: {exc}") from exc

    kid = unverified_header.get("kid")
    if not kid or not isinstance(kid, str):
        raise EnvelopeMalformedError("envelope JWS header missing 'kid'")

    iss = unverified_claims.get("iss")
    if not iss or not isinstance(iss, str):
        raise EnvelopeMalformedError("envelope claims missing 'iss'")

    missing = [c for c in _REQUIRED_CLAIMS if c not in unverified_claims]
    if missing:
        raise EnvelopeMalformedError(
            f"envelope claims missing required: {', '.join(missing)}"
        )

    keys = await resolve_jwks_for_iss(iss, force_refresh=False)
    public_key = keys.get(kid)
    if public_key is None:
        keys = await resolve_jwks_for_iss(iss, force_refresh=True)
        public_key = keys.get(kid)
        if public_key is None:
            raise EnvelopeSignatureError(
                f"hub {iss!r} has no key with kid {kid!r} in its JWKS"
            )

    try:
        # pyjwt's iat check rejects future iat as InvalidIssuedAtError; we
        # want our own EnvelopeSkewError with both directions, so disable
        # pyjwt's iat validation and run the skew check explicitly below.
        verified = pyjwt.decode(
            jws,
            public_key,
            algorithms=list(_ACCEPTED_ALGS),
            audience=expected_aud,
            options={"verify_aud": True, "verify_exp": False, "verify_iat": False},
        )
    except pyjwt.InvalidAudienceError as exc:
        raise EnvelopeSignatureError(
            f"envelope aud doesn't match expected {expected_aud!r}: {exc}"
        ) from exc
    except pyjwt.PyJWTError as exc:
        raise EnvelopeSignatureError(f"envelope signature invalid: {exc}") from exc

    if verified.get("body_sha256") != _body_sha256(body):
        raise EnvelopeBodyMismatchError(
            "envelope body_sha256 does not match request body"
        )

    iat = verified.get("iat")
    if not isinstance(iat, (int, float)):
        raise EnvelopeMalformedError("envelope iat must be a number")
    n = now if now is not None else int(time.time())
    if abs(n - int(iat)) > max_skew_seconds:
        raise EnvelopeSkewError(
            f"envelope iat={iat} outside ±{max_skew_seconds}s window from {n}"
        )

    jti = verified["jti"]
    if jti in replay_cache:
        raise EnvelopeReplayError(f"envelope jti={jti!r} already seen")
    replay_cache.add(jti, ttl_seconds=replay_ttl_seconds)

    return verified


__all__ = [
    "AUTHORIZATION_SCHEME",
    "EnvelopeBodyMismatchError",
    "EnvelopeMalformedError",
    "EnvelopeReplayError",
    "EnvelopeSignatureError",
    "EnvelopeSigningError",
    "EnvelopeSkewError",
    "EnvelopeVerificationError",
    "sign_envelope",
    "verify_envelope",
]


AUTHORIZATION_SCHEME = "HubJWS"
"""The Authorization-header scheme name. Adopters use:

    headers["Authorization"] = f"{AUTHORIZATION_SCHEME} {jws}"
"""
