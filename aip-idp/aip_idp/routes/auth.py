"""Principal authentication routes (simplified placeholder)."""

import uuid

import jwt as pyjwt
from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select

from aip_idp.models.database import Principal, async_session

router = APIRouter(prefix="/aip/auth")


class RegisterPrincipalRequest(BaseModel):
    type: str  # "human" or "org"
    name: str
    external_id: str  # e.g. "github:alice"


class LoginRequest(BaseModel):
    external_id: str


def _make_management_token(principal_id: str, request: Request) -> str:
    """Create a simple management JWT for a principal."""
    app = request.app
    private_key = app.state.idp_private_key
    kid = app.state.idp_kid

    payload = {
        "sub": principal_id,
        "type": "management",
        "iss": f"https://{app.state.idp_domain}",
    }
    return pyjwt.encode(payload, private_key, algorithm="EdDSA", headers={"kid": kid})


@router.post("/register")
async def register_principal(body: RegisterPrincipalRequest, request: Request):
    """Register a new principal (human or org)."""
    if body.type not in ("human", "org"):
        raise HTTPException(400, "type must be 'human' or 'org'")

    async with async_session() as session:
        existing = await session.execute(
            select(Principal).where(Principal.external_id == body.external_id)
        )
        if existing.scalar_one_or_none():
            raise HTTPException(409, "Principal with this external_id already exists")

        principal_id = str(uuid.uuid4())
        principal = Principal(
            id=principal_id,
            type=body.type,
            name=body.name,
            external_id=body.external_id,
        )
        session.add(principal)
        await session.commit()

    token = _make_management_token(principal_id, request)
    return {"principal_id": principal_id, "management_token": token}


@router.post("/login")
async def login_principal(body: LoginRequest, request: Request):
    """Login an existing principal by external_id."""
    async with async_session() as session:
        result = await session.execute(
            select(Principal).where(Principal.external_id == body.external_id)
        )
        principal = result.scalar_one_or_none()
        if not principal:
            raise HTTPException(404, "Principal not found")

    token = _make_management_token(principal.id, request)
    return {"principal_id": principal.id, "management_token": token}
