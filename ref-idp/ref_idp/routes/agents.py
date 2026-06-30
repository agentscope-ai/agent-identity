"""Agent identity registration — ModelScope-shaped (dev stand-in).

Auth is a Bearer **AccessToken**. In this reference IdP (dev only), ANY
non-empty bearer is accepted and mapped to a principal (auto-created, keyed by
a hash of the token) — standing in for a real ModelScope account token. The
public key is uploaded as an Ed25519 OKP JWK with a client-chosen ``kid``.

Mounted at ``/openapi/v1`` with router prefix ``/agent_ids`` →
``POST /openapi/v1/agent_ids``.
"""

import hashlib
import json
import secrets
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select

from ref_idp.crypto.keys import b64u_decode
from ref_idp.models.database import Agent, AgentKey, Principal, async_session

router = APIRouter(prefix="/agent_ids")


class PublicJWK(BaseModel):
    kty: str
    crv: str
    x: str
    kid: str


class RegisterAgentRequest(BaseModel):
    agent_name: str
    public_key: PublicJWK
    description: str | None = None
    key_alg_type: str | None = None
    token_expire_time: int | None = None


def _bearer(request: Request) -> str:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "InvalidAuthentication: missing bearer access token")
    token = auth.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(401, "InvalidAuthentication: empty access token")
    return token


async def _principal_for_token(session, token: str) -> Principal:
    """Map an AccessToken to a principal, auto-creating one in dev."""
    ext = "accesstoken:" + hashlib.sha256(token.encode()).hexdigest()[:12]
    res = await session.execute(select(Principal).where(Principal.external_id == ext))
    principal = res.scalar_one_or_none()
    if principal is None:
        principal = Principal(
            id=str(uuid.uuid4()), type="user", external_id=ext, name="dev-user"
        )
        session.add(principal)
        await session.flush()
    return principal


@router.post("")
async def register_agent(body: RegisterAgentRequest, request: Request):
    """Register an agent's public key; returns its assigned ``aip:`` identity."""
    token = _bearer(request)

    jwk = body.public_key
    if jwk.kty != "OKP" or jwk.crv != "Ed25519":
        raise HTTPException(
            400, "InputParameterError: public_key must be OKP / Ed25519"
        )
    try:
        pk_bytes = b64u_decode(jwk.x)
        if len(pk_bytes) != 32:
            raise ValueError
    except Exception:
        raise HTTPException(
            400, "InputParameterError: public_key.x must be a 32-byte base64url value"
        )

    app = request.app
    domain = app.state.idp_domain
    agent_id = f"aip:{domain}:agent_{secrets.token_hex(6)}"
    kid = jwk.kid  # client-chosen; echoed back

    created = datetime.now(timezone.utc)
    async with async_session() as session:
        principal = await _principal_for_token(session, token)
        db_id = str(uuid.uuid4())
        agent = Agent(
            id=db_id,
            agent_id=agent_id,
            name=body.agent_name,
            principal_id=principal.id,
            metadata_json=(
                json.dumps({"description": body.description})
                if body.description
                else None
            ),
        )
        session.add(agent)
        session.add(
            AgentKey(
                id=str(uuid.uuid4()),
                agent_id=db_id,
                kid=kid,
                public_key_bytes=pk_bytes.hex(),
                is_active=True,
            )
        )
        await session.commit()

    return {
        "success": True,
        "request_id": str(uuid.uuid4()),
        "data": {
            "agent_id": agent_id,
            "agent_name": body.agent_name,
            "kid": kid,
            "public_key": jwk.model_dump(),
            "token_expire_time": body.token_expire_time or app.state.token_ttl_seconds,
            "status": "active",
            "create_time": created.isoformat(),
        },
    }
