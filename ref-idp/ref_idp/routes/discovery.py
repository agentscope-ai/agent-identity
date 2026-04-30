"""AgentID discovery endpoints (well-known configuration and JWKS).

Phase 4 dual-serve: both `.well-known/agentid-*` (canonical) and
`.well-known/aip-*` (legacy) are mounted with matching content.
"""

import base64

from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, Request

router = APIRouter()


def _build_config(base: str, prefix: str, jwks_path: str) -> dict:
    return {
        "issuer": base,
        "token_endpoint": f"{base}{prefix}/token",
        "jwks_uri": f"{base}{jwks_path}",
        "registration_endpoint": f"{base}{prefix}/agents",
        "activity_endpoint": f"{base}{prefix}/activity",
        "supported_algorithms": ["EdDSA"],
        "agentid_version": "0.1",
        "aip_version": "0.1",
    }


@router.get("/.well-known/agentid-configuration")
async def agentid_configuration(request: Request):
    base = request.app.state.idp_base_url
    return _build_config(base, "/agentid", "/.well-known/agentid-jwks")


@router.get("/.well-known/aip-configuration")
async def aip_configuration(request: Request):
    """Legacy discovery endpoint — kept through Phase 9 for back-compat."""
    base = request.app.state.idp_base_url
    return _build_config(base, "/aip", "/.well-known/aip-jwks")


def _build_jwks(request: Request) -> dict:
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


@router.get("/.well-known/agentid-jwks")
async def agentid_jwks(request: Request):
    return _build_jwks(request)


@router.get("/.well-known/aip-jwks")
async def aip_jwks(request: Request):
    """Legacy JWKS endpoint — same key set, kept through Phase 9."""
    return _build_jwks(request)
