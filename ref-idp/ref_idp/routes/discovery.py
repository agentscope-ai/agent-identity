"""AgentID discovery endpoints — ModelScope shape (public, no auth).

Mounted under ``/openapi/v1/agent_id`` so the paths mirror ModelScope:
``/openapi/v1/agent_id/.well-known/agentid-{configuration,jwks}``.
"""

import base64

from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, Request

router = APIRouter()


@router.get("/.well-known/agentid-configuration")
async def agentid_configuration(request: Request):
    base = request.app.state.idp_base_url
    api = f"{base}/openapi/v1/agent_id"
    return {
        "issuer": base,
        "token_endpoint": f"{api}/token",
        "jwks_uri": f"{api}/.well-known/agentid-jwks",
        "id_token_signing_alg_values_supported": "EdDSA",
    }


@router.get("/.well-known/agentid-jwks")
async def agentid_jwks(request: Request):
    private_key = request.app.state.idp_private_key
    kid = request.app.state.idp_kid

    raw_public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    x_b64 = base64.urlsafe_b64encode(raw_public).rstrip(b"=").decode()

    return {
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": kid,
                "x": x_b64,
                "use": "sig",
                "alg": "EdDSA",
            }
        ]
    }
