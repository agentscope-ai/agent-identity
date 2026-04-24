"""Token exchange endpoint - agent proves key ownership to get a JWT."""

import time

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select

from ref_idp.crypto.jwt import create_agent_token
from ref_idp.crypto.keys import verify_signature
from ref_idp.models.database import Agent, AgentKey, Principal, async_session

router = APIRouter(prefix="/aip")

# Maximum allowed clock skew for timestamp validation (seconds).
TIMESTAMP_TOLERANCE = 5 * 60


class TokenRequest(BaseModel):
    agent_id: str
    kid: str
    audience: str
    timestamp: str  # ISO or unix timestamp as string
    signature: str  # hex-encoded Ed25519 signature


@router.post("/token")
async def exchange_token(body: TokenRequest, request: Request):
    """Exchange a signed request for a JWT.

    The agent signs the message: "{agent_id}|{kid}|{audience}|{timestamp}"
    with its Ed25519 private key. The IdP verifies the signature against the
    stored public key and issues a JWT signed with the IdP's own key.
    """
    app = request.app

    # 1. Look up agent and key
    async with async_session() as session:
        agent_result = await session.execute(
            select(Agent).where(Agent.agent_id == body.agent_id)
        )
        agent = agent_result.scalar_one_or_none()
        if not agent:
            raise HTTPException(404, "Agent not found")

        key_result = await session.execute(
            select(AgentKey).where(
                AgentKey.agent_id == agent.id,
                AgentKey.kid == body.kid,
                AgentKey.is_active == True,
            )
        )
        key = key_result.scalar_one_or_none()
        if not key:
            raise HTTPException(404, "Active key not found for this agent")

        # Fetch principal info
        principal_result = await session.execute(
            select(Principal).where(Principal.id == agent.principal_id)
        )
        principal = principal_result.scalar_one_or_none()

    # 2. Reconstruct the signed message
    message = f"{body.agent_id}|{body.kid}|{body.audience}|{body.timestamp}"
    message_bytes = message.encode("utf-8")

    # 3. Verify signature
    try:
        sig_bytes = bytes.fromhex(body.signature)
        pk_bytes = bytes.fromhex(key.public_key_bytes)
    except ValueError:
        raise HTTPException(400, "Invalid hex encoding in signature or key")

    if not verify_signature(pk_bytes, message_bytes, sig_bytes):
        raise HTTPException(401, "Invalid signature")

    # 4. Validate timestamp (within 5 minutes)
    try:
        req_time = int(body.timestamp)
    except ValueError:
        raise HTTPException(400, "Timestamp must be a unix epoch integer (as string)")

    now = int(time.time())
    if abs(now - req_time) > TIMESTAMP_TOLERANCE:
        raise HTTPException(401, "Timestamp out of range (must be within 5 minutes)")

    # 5. Issue JWT
    idp_private_key = app.state.idp_private_key
    idp_kid = app.state.idp_kid
    ttl = app.state.token_ttl_seconds

    if principal:
        principal_claim: dict = {
            "type": principal.type,
            "id": principal.id,
            "name": principal.name,
        }
        if principal.notification_endpoint:
            principal_claim["notification_endpoint"] = principal.notification_endpoint
    else:
        principal_claim = {"type": "unknown", "id": "", "name": ""}

    token = create_agent_token(
        agent_id=body.agent_id,
        agent_name=agent.name,
        principal=principal_claim,
        audience=body.audience,
        capabilities=None,
        idp_private_key=idp_private_key,
        idp_kid=idp_kid,
        issuer=f"https://{app.state.idp_domain}",
        ttl_seconds=ttl,
    )

    expires_at = now + ttl
    return {"token": token, "expires_at": expires_at}
