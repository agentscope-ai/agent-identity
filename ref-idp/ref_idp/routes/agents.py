"""Agent registration and key management routes."""

import json
import secrets
import uuid

import jwt as pyjwt
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select

from ref_idp.crypto.keys import compute_kid
from ref_idp.models.database import Agent, AgentKey, Principal, async_session

router = APIRouter(prefix="/aip/agents")


class RegisterAgentRequest(BaseModel):
    name: str
    public_key: str  # hex-encoded 32-byte Ed25519 public key
    principal_id: str
    metadata: dict | None = None


class AddKeyRequest(BaseModel):
    public_key: str  # hex-encoded


def _verify_management_token(request: Request) -> dict:
    """Verify the Authorization header contains a valid management token.

    Returns the decoded token payload.
    """
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(401, "Missing or invalid Authorization header")

    token = auth_header.split(" ", 1)[1]
    app = request.app
    public_key = app.state.idp_private_key.public_key()

    try:
        payload = pyjwt.decode(
            token,
            public_key,
            algorithms=["EdDSA"],
            options={"verify_aud": False},
        )
    except pyjwt.InvalidTokenError as e:
        raise HTTPException(401, f"Invalid management token: {e}")

    if payload.get("type") != "management":
        raise HTTPException(403, "Token is not a management token")

    return payload


@router.post("")
async def register_agent(body: RegisterAgentRequest, request: Request):
    """Register a new agent under a principal."""
    token_payload = _verify_management_token(request)

    # The principal in the token must match the requested principal_id
    if token_payload["sub"] != body.principal_id:
        raise HTTPException(
            403, "Token principal does not match requested principal_id"
        )

    # Validate public key hex
    try:
        pk_bytes = bytes.fromhex(body.public_key)
        if len(pk_bytes) != 32:
            raise ValueError("Public key must be 32 bytes")
    except ValueError as e:
        raise HTTPException(400, f"Invalid public key: {e}")

    app = request.app
    domain = app.state.idp_domain
    random_part = "agent_" + secrets.token_hex(4)
    agent_id = f"aip:{domain}:{random_part}"
    kid = compute_kid(pk_bytes)

    async with async_session() as session:
        # Verify principal exists
        result = await session.execute(
            select(Principal).where(Principal.id == body.principal_id)
        )
        principal = result.scalar_one_or_none()
        if not principal:
            raise HTTPException(404, "Principal not found")

        db_agent_id = str(uuid.uuid4())
        agent = Agent(
            id=db_agent_id,
            agent_id=agent_id,
            name=body.name,
            principal_id=body.principal_id,
            metadata_json=json.dumps(body.metadata) if body.metadata else None,
        )
        session.add(agent)

        key = AgentKey(
            id=str(uuid.uuid4()),
            agent_id=db_agent_id,
            kid=kid,
            public_key_bytes=body.public_key,
            is_active=True,
        )
        session.add(key)
        await session.commit()

    return {"agent_id": agent_id, "kid": kid}


@router.get("/{agent_id:path}")
async def get_agent(agent_id: str):
    """Get agent public info."""
    async with async_session() as session:
        result = await session.execute(select(Agent).where(Agent.agent_id == agent_id))
        agent = result.scalar_one_or_none()
        if not agent:
            raise HTTPException(404, "Agent not found")

        # Fetch principal type
        p_result = await session.execute(
            select(Principal).where(Principal.id == agent.principal_id)
        )
        principal = p_result.scalar_one_or_none()

        # Fetch active keys
        keys_result = await session.execute(
            select(AgentKey).where(
                AgentKey.agent_id == agent.id,
                AgentKey.is_active == True,
            )
        )
        keys = keys_result.scalars().all()

    return {
        "agent_id": agent.agent_id,
        "name": agent.name,
        "principal_type": principal.type if principal else None,
        "public_keys": [{"kid": k.kid, "public_key": k.public_key_bytes} for k in keys],
        "created_at": str(agent.created_at),
    }


@router.post("/{agent_id:path}/keys")
async def add_key(agent_id: str, body: AddKeyRequest, request: Request):
    """Add a new public key to an agent."""
    token_payload = _verify_management_token(request)

    try:
        pk_bytes = bytes.fromhex(body.public_key)
        if len(pk_bytes) != 32:
            raise ValueError("Public key must be 32 bytes")
    except ValueError as e:
        raise HTTPException(400, f"Invalid public key: {e}")

    kid = compute_kid(pk_bytes)

    async with async_session() as session:
        result = await session.execute(select(Agent).where(Agent.agent_id == agent_id))
        agent = result.scalar_one_or_none()
        if not agent:
            raise HTTPException(404, "Agent not found")

        if agent.principal_id != token_payload["sub"]:
            raise HTTPException(403, "Not authorized for this agent")

        key = AgentKey(
            id=str(uuid.uuid4()),
            agent_id=agent.id,
            kid=kid,
            public_key_bytes=body.public_key,
            is_active=True,
        )
        session.add(key)
        await session.commit()

    return {"kid": kid}


@router.delete("/{agent_id:path}/keys/{kid}")
async def revoke_key(agent_id: str, kid: str, request: Request):
    """Revoke an agent's public key."""
    token_payload = _verify_management_token(request)

    async with async_session() as session:
        result = await session.execute(select(Agent).where(Agent.agent_id == agent_id))
        agent = result.scalar_one_or_none()
        if not agent:
            raise HTTPException(404, "Agent not found")

        if agent.principal_id != token_payload["sub"]:
            raise HTTPException(403, "Not authorized for this agent")

        key_result = await session.execute(
            select(AgentKey).where(
                AgentKey.agent_id == agent.id,
                AgentKey.kid == kid,
                AgentKey.is_active == True,
            )
        )
        key = key_result.scalar_one_or_none()
        if not key:
            raise HTTPException(404, "Active key not found")

        key.is_active = False
        from datetime import datetime, timezone

        key.revoked_at = datetime.now(timezone.utc)
        await session.commit()

    return {"status": "revoked", "kid": kid}
