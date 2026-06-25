"""Token exchange endpoint — ModelScope Agent IdP protocol.

The agent signs ``"{agent_id}|{kid}|{audience}|{timestamp}"`` with its Ed25519
private key; the signature is base64url (no padding) and the timestamp is a
Unix-epoch integer with a ±60s validity window. The IdP verifies the signature
against the stored public key and issues a short, minimal JWT.

Response is wrapped in the ModelScope envelope:
``{"success": true, "request_id": ..., "data": {...}}``.
"""

import time
import uuid

import jwt as pyjwt
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select

from ref_idp.crypto.keys import b64u_decode, rfc7638_thumbprint, verify_signature
from ref_idp.models.database import Agent, AgentKey, async_session

router = APIRouter()

# ModelScope: the request timestamp must be within ±60s of server time.
TIMESTAMP_TOLERANCE = 60


class TokenRequest(BaseModel):
    agent_id: str
    kid: str
    audience: str
    timestamp: int  # Unix epoch seconds
    signature: str  # base64url (no padding) Ed25519 signature


@router.post("/token")
async def issue_token(body: TokenRequest, request: Request):
    """Exchange a signed request for a short JWT (no AccessToken needed)."""
    app = request.app

    # 1. Look up the agent and the (active) key referenced by kid.
    async with async_session() as session:
        agent_res = await session.execute(
            select(Agent).where(Agent.agent_id == body.agent_id)
        )
        agent = agent_res.scalar_one_or_none()
        if not agent:
            raise HTTPException(404, "ResourceNotFound: agent not registered")

        key_res = await session.execute(
            select(AgentKey).where(
                AgentKey.agent_id == agent.id,
                AgentKey.kid == body.kid,
                AgentKey.is_active == True,  # noqa: E712
            )
        )
        key = key_res.scalar_one_or_none()
        if not key:
            raise HTTPException(404, "ResourceNotFound: kid not found for agent")

    # 2. Validate timestamp window (±60s).
    now = int(time.time())
    if abs(now - body.timestamp) > TIMESTAMP_TOLERANCE:
        raise HTTPException(
            400, "InputParameterError: timestamp outside the ±60s window"
        )

    # 3. Verify the base64url Ed25519 signature.
    message = f"{body.agent_id}|{body.kid}|{body.audience}|{body.timestamp}".encode(
        "utf-8"
    )
    try:
        sig_bytes = b64u_decode(body.signature)
    except Exception:
        raise HTTPException(400, "InputParameterError: signature is not base64url")
    pk_bytes = bytes.fromhex(key.public_key_bytes)
    if not verify_signature(pk_bytes, message, sig_bytes):
        raise HTTPException(401, "InvalidAuthentication: signature verification failed")

    # 4. Issue a minimal JWT (iss/sub/aud/iat/exp/jti) — ModelScope shape.
    ttl = app.state.token_ttl_seconds
    jti = "jti-" + str(uuid.uuid4())
    payload = {
        "iss": app.state.idp_base_url,
        "sub": body.agent_id,
        "aud": body.audience,
        "iat": now,
        "exp": now + ttl,
        "jti": jti,
    }
    # Optional DPoP holder binding (RFC 9449). Off by default to mirror
    # ModelScope; toggle with REF_AGENT_IDP_DPOP_ENABLED. Read app.state
    # directly (set at startup) so a wiring regression fails loudly rather than
    # silently disabling the switch. ``pk_bytes`` was decoded above.
    if app.state.dpop_enabled:
        payload["cnf"] = {"jkt": rfc7638_thumbprint(pk_bytes)}
    token = pyjwt.encode(
        payload,
        app.state.idp_private_key,
        algorithm="EdDSA",
        headers={"kid": app.state.idp_kid},
    )

    return {
        "success": True,
        "request_id": str(uuid.uuid4()),
        "data": {
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": ttl,
            "jti": jti,
        },
    }
