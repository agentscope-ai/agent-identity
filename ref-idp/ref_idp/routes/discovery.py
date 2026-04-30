"""AgentID discovery endpoints (well-known configuration and JWKS)."""

import base64

from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, Request

router = APIRouter()


@router.get("/.well-known/agentid-configuration")
async def agentid_configuration(request: Request):
    base = request.app.state.idp_base_url
    return {
        "issuer": base,
        "token_endpoint": f"{base}/agentid/token",
        "jwks_uri": f"{base}/.well-known/agentid-jwks",
        "registration_endpoint": f"{base}/agentid/agents",
        "activity_endpoint": f"{base}/agentid/activity",
        "supported_algorithms": ["EdDSA"],
        "agentid_version": "0.1",
    }


@router.get("/.well-known/agentid-jwks")
async def agentid_jwks(request: Request):
    private_key = request.app.state.idp_private_key
    kid = request.app.state.idp_kid

    public_key = private_key.public_key()
    raw_public = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    # OKP JWK format for Ed25519
    x_b64 = base64.urlsafe_b64encode(raw_public).rstrip(b"=").decode()

    return {
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "use": "sig",
                "kid": kid,
                "x": x_b64,
            }
        ]
    }
