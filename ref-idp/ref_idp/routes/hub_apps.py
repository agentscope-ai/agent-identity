"""Hub app registration — ModelScope-shaped (dev stand-in).

Mints a ``hub_<6hex>`` client_id for a resource server and persists it, so the
token endpoint can enforce that a requested ``audience`` is a registered hub
(see ``REF_AGENT_IDP_ENFORCE_AUDIENCE`` — on by default, mirroring ModelScope).
The agent then requests a token for this client_id as the audience.

Mounted at ``/openapi/v1`` with router prefix ``/hub_apps`` →
``POST /openapi/v1/hub_apps``.
"""

import secrets
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from ref_idp.models.database import HubApp, async_session

router = APIRouter(prefix="/hub_apps")


class CreateHubAppRequest(BaseModel):
    app_name: str
    app_homepage: str
    app_logo: str | None = None


@router.post("")
async def create_hub_app(body: CreateHubAppRequest, request: Request):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer ") or not auth.split(" ", 1)[1].strip():
        raise HTTPException(401, "InvalidAuthentication: missing bearer access token")

    client_id = "hub_" + secrets.token_hex(3)
    owner = "dev-user"
    created = datetime.now(timezone.utc)
    async with async_session() as session:
        session.add(
            HubApp(
                client_id=client_id,
                app_name=body.app_name,
                app_homepage=body.app_homepage,
                app_logo=body.app_logo,
                owner=owner,
            )
        )
        await session.commit()

    return {
        "success": True,
        "request_id": str(uuid.uuid4()),
        "data": {
            "client_id": client_id,
            "app_name": body.app_name,
            "app_homepage": body.app_homepage,
            "app_logo": body.app_logo,
            "owner": owner,
            "create_time": created.isoformat(),
        },
    }
