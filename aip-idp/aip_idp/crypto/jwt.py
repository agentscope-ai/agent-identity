"""JWT creation and decoding for AIP tokens."""

import time
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def create_agent_token(
    agent_id: str,
    agent_name: str,
    principal: dict[str, Any],
    audience: str,
    capabilities: list[str] | None,
    idp_private_key: Ed25519PrivateKey,
    idp_kid: str,
    issuer: str,
    ttl_seconds: int,
    *,
    scopes: list[str] | None = None,
    delegation: dict[str, Any] | None = None,
    model_info: dict[str, Any] | None = None,
    spawned_by: str | None = None,
    jurisdiction: str | None = None,
    compliance: dict[str, Any] | None = None,
) -> str:
    """Create a signed JWT for an agent.

    The token is signed with the IdP's private key (EdDSA / Ed25519).

    Returns:
        Encoded JWT string.
    """
    now = int(time.time())
    payload: dict[str, Any] = {
        "iss": issuer,
        "sub": agent_id,
        "aud": audience,
        "iat": now,
        "exp": now + ttl_seconds,
        "aip_version": "0.1",
        "agent_name": agent_name,
        "principal": principal,
    }

    if capabilities:
        payload["capabilities"] = capabilities
    if scopes:
        payload["scopes"] = scopes
    if delegation:
        payload["delegation"] = delegation
    if model_info:
        payload["model_info"] = model_info
    if spawned_by:
        payload["spawned_by"] = spawned_by
    if jurisdiction:
        payload["jurisdiction"] = jurisdiction
    if compliance:
        payload["compliance"] = compliance

    headers = {"kid": idp_kid}
    return jwt.encode(payload, idp_private_key, algorithm="EdDSA", headers=headers)


def decode_token_unverified(token: str) -> dict[str, Any]:
    """Decode a JWT without verifying the signature (for debugging)."""
    return jwt.decode(token, options={"verify_signature": False}, algorithms=["EdDSA"])
