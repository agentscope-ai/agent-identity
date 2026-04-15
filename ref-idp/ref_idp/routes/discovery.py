"""AIP discovery endpoints (well-known configuration and JWKS)."""

import base64

from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, Request

router = APIRouter()


@router.get("/.well-known/aip-configuration")
async def aip_configuration(request: Request):
    """Return the AIP IdP configuration document."""
    app = request.app
    base = app.state.idp_base_url
    return {
        "issuer": base,
        "token_endpoint": f"{base}/aip/token",
        "jwks_uri": f"{base}/.well-known/aip-jwks",
        "registration_endpoint": f"{base}/aip/agents",
        "activity_endpoint": f"{base}/aip/activity",
        "supported_algorithms": ["EdDSA"],
        "aip_version": "0.1",
    }


@router.get("/.well-known/aip-jwks")
async def aip_jwks(request: Request):
    """Return the JWKS containing the IdP's public signing key."""
    app = request.app
    private_key = app.state.idp_private_key
    kid = app.state.idp_kid

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
