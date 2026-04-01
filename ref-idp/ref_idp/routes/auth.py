"""Principal authentication routes.

Supports three modes:
1. GitHub OAuth Authorization Code + PKCE (web portal) — browser-based login.
2. GitHub OAuth Device Flow (CLI) — terminal-based login.
3. Direct register/login (development/testing) — no verification.
"""

import hashlib
import secrets
import time
import uuid
from base64 import urlsafe_b64encode

import httpx
import jwt as pyjwt
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy import select

from ref_idp.config import settings
from ref_idp.models.database import Principal, async_session

router = APIRouter(prefix="/aip/auth")

# ---------------------------------------------------------------------------
# In-memory stores for pending OAuth flows
# ---------------------------------------------------------------------------

_pending_flows: dict[str, dict] = {}  # device flow: device_code -> flow state
_pending_authz: dict[str, dict] = {}  # authz code flow: state -> flow state

GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
GITHUB_DEVICE_CODE_URL = "https://github.com/login/device/code"
GITHUB_ACCESS_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_USER_URL = "https://api.github.com/user"

# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class RegisterPrincipalRequest(BaseModel):
    type: str  # "human" or "org"
    name: str
    external_id: str  # e.g. "github:alice"


class LoginRequest(BaseModel):
    external_id: str


class DeviceTokenRequest(BaseModel):
    device_code: str


class AuthzStartRequest(BaseModel):
    redirect_uri: str  # Where to redirect after GitHub login


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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


async def _get_or_create_principal(
    external_id: str, name: str, principal_type: str = "human",
) -> tuple[str, bool]:
    """Return (principal_id, created). Creates the principal if it doesn't exist."""
    async with async_session() as session:
        result = await session.execute(
            select(Principal).where(Principal.external_id == external_id)
        )
        existing = result.scalar_one_or_none()
        if existing:
            return existing.id, False

        principal_id = str(uuid.uuid4())
        session.add(Principal(
            id=principal_id,
            type=principal_type,
            name=name,
            external_id=external_id,
        ))
        await session.commit()
        return principal_id, True


def _cleanup_expired_flows() -> None:
    """Remove expired entries from pending flow stores."""
    now = time.time()
    for store in (_pending_flows, _pending_authz):
        expired = [k for k, v in store.items() if v["expires_at"] <= now]
        for k in expired:
            del store[k]


async def _github_post(url: str, **kwargs) -> httpx.Response:
    """POST to GitHub API. Extracted for testability."""
    async with httpx.AsyncClient() as http:
        return await http.post(url, **kwargs)


async def _github_get(url: str, **kwargs) -> httpx.Response:
    """GET from GitHub API. Extracted for testability."""
    async with httpx.AsyncClient() as http:
        return await http.get(url, **kwargs)


# ---------------------------------------------------------------------------
# GitHub OAuth Authorization Code + PKCE (web portal)
# ---------------------------------------------------------------------------


@router.post("/login/github")
async def authz_code_start(body: AuthzStartRequest, request: Request):
    """Start GitHub OAuth Authorization Code flow with PKCE.

    Returns a URL the frontend should redirect the user's browser to.
    Used by web-based IdP portals (as opposed to the device flow for CLIs).
    """
    client_id = settings.github_client_id
    if not client_id:
        raise HTTPException(
            501,
            "GitHub OAuth is not configured. Set github_client_id in IdP settings.",
        )

    _cleanup_expired_flows()

    # Generate PKCE code verifier and challenge
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = (
        urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )

    # Generate state parameter (CSRF protection)
    state = secrets.token_urlsafe(32)
    _pending_authz[state] = {
        "code_verifier": code_verifier,
        "redirect_uri": body.redirect_uri,
        "expires_at": time.time() + 600,  # 10 minutes
    }

    # Build GitHub authorization URL
    params = (
        f"client_id={client_id}"
        f"&redirect_uri={request.url_for('authz_code_callback')}"
        f"&scope=read:user"
        f"&state={state}"
        f"&code_challenge={code_challenge}"
        f"&code_challenge_method=S256"
    )
    github_url = f"{GITHUB_AUTHORIZE_URL}?{params}"

    return {"authorize_url": github_url, "state": state}


@router.get("/callback/github")
async def authz_code_callback(code: str, state: str, request: Request):
    """GitHub redirects here after user authorizes.

    Exchanges the authorization code for an access token, fetches the GitHub
    user profile, registers/logs in the principal, and redirects the frontend
    with the management token.
    """
    _cleanup_expired_flows()

    if state not in _pending_authz:
        raise HTTPException(400, "Invalid or expired state parameter.")

    flow = _pending_authz.pop(state)
    code_verifier = flow["code_verifier"]
    frontend_redirect_uri = flow["redirect_uri"]

    client_id = settings.github_client_id
    client_secret = settings.github_client_secret

    # Exchange authorization code for access token
    token_data = {
        "client_id": client_id,
        "code": code,
        "code_verifier": code_verifier,
    }
    if client_secret:
        token_data["client_secret"] = client_secret

    resp = await _github_post(
        GITHUB_ACCESS_TOKEN_URL,
        data=token_data,
        headers={"Accept": "application/json"},
    )
    if resp.status_code != 200:
        raise HTTPException(502, "GitHub token exchange failed.")

    gh_data = resp.json()
    if "error" in gh_data:
        raise HTTPException(400, f"GitHub OAuth error: {gh_data['error']}")

    access_token = gh_data["access_token"]

    # Fetch GitHub user profile
    user_resp = await _github_get(
        GITHUB_USER_URL,
        headers={
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        },
    )
    if user_resp.status_code != 200:
        raise HTTPException(502, "Failed to fetch GitHub user profile.")

    user_data = user_resp.json()
    github_login = user_data["login"]
    github_name = user_data.get("name") or github_login

    # Register or login the principal
    external_id = f"github:{github_login}"
    principal_id, _ = await _get_or_create_principal(
        external_id=external_id, name=github_name, principal_type="human",
    )

    mgmt_token = _make_management_token(principal_id, request)

    # Redirect back to the frontend with credentials
    separator = "&" if "?" in frontend_redirect_uri else "?"
    redirect_url = (
        f"{frontend_redirect_uri}{separator}"
        f"principal_id={principal_id}"
        f"&management_token={mgmt_token}"
        f"&external_id={external_id}"
        f"&name={github_name}"
    )
    return RedirectResponse(url=redirect_url, status_code=302)


# ---------------------------------------------------------------------------
# GitHub OAuth Device Flow (CLI)
# ---------------------------------------------------------------------------


@router.post("/device")
async def device_flow_start(request: Request):
    """Initiate GitHub OAuth Device Flow.

    Returns a user_code and verification_uri for the user to visit in a browser.
    """
    client_id = settings.github_client_id
    if not client_id:
        raise HTTPException(
            501,
            "GitHub OAuth is not configured. Set github_client_id in IdP settings.",
        )

    _cleanup_expired_flows()

    resp = await _github_post(
        GITHUB_DEVICE_CODE_URL,
        data={"client_id": client_id, "scope": "read:user"},
        headers={"Accept": "application/json"},
    )
    if resp.status_code != 200:
        raise HTTPException(502, f"GitHub device code request failed: {resp.text}")

    data = resp.json()

    device_code = data["device_code"]
    _pending_flows[device_code] = {
        "github_device_code": device_code,
        "expires_at": time.time() + data.get("expires_in", 900),
    }

    return {
        "device_code": device_code,
        "user_code": data["user_code"],
        "verification_uri": data["verification_uri"],
        "expires_in": data.get("expires_in", 900),
        "interval": data.get("interval", 5),
    }


@router.post("/device/token")
async def device_flow_token(body: DeviceTokenRequest, request: Request):
    """Poll for device flow completion.

    Returns authorization_pending while the user hasn't authorized yet.
    Returns principal_id + management_token once GitHub confirms the identity.
    """
    client_id = settings.github_client_id
    if not client_id:
        raise HTTPException(501, "GitHub OAuth is not configured.")

    _cleanup_expired_flows()

    if body.device_code not in _pending_flows:
        raise HTTPException(404, "Unknown or expired device code.")

    # Poll GitHub for the access token
    resp = await _github_post(
        GITHUB_ACCESS_TOKEN_URL,
        data={
            "client_id": client_id,
            "device_code": body.device_code,
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        },
        headers={"Accept": "application/json"},
    )

    gh_data = resp.json()

    # Still waiting for user authorization
    if "error" in gh_data:
        error = gh_data["error"]
        if error in ("authorization_pending", "slow_down"):
            return {"error": error}
        # expired_token, access_denied, etc.
        del _pending_flows[body.device_code]
        raise HTTPException(400, f"GitHub OAuth error: {error}")

    # Success — GitHub returned an access token. Fetch user identity.
    access_token = gh_data["access_token"]

    user_resp = await _github_get(
        GITHUB_USER_URL,
        headers={
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        },
    )
    if user_resp.status_code != 200:
        del _pending_flows[body.device_code]
        raise HTTPException(502, "Failed to fetch GitHub user profile.")

    user_data = user_resp.json()
    github_login = user_data["login"]
    github_name = user_data.get("name") or github_login

    # Clean up the pending flow
    del _pending_flows[body.device_code]

    # Register or login the principal
    external_id = f"github:{github_login}"
    principal_id, _ = await _get_or_create_principal(
        external_id=external_id, name=github_name, principal_type="human",
    )

    mgmt_token = _make_management_token(principal_id, request)

    return {
        "principal_id": principal_id,
        "management_token": mgmt_token,
        "external_id": external_id,
        "name": github_name,
    }


# ---------------------------------------------------------------------------
# Direct register/login (development & testing — no identity verification)
# ---------------------------------------------------------------------------


@router.post("/register")
async def register_principal(body: RegisterPrincipalRequest, request: Request):
    """Register a new principal (no identity verification — for dev/testing)."""
    if body.type not in ("human", "org"):
        raise HTTPException(400, "type must be 'human' or 'org'")

    async with async_session() as session:
        existing_result = await session.execute(
            select(Principal).where(Principal.external_id == body.external_id)
        )
        if existing_result.scalar_one_or_none():
            raise HTTPException(409, "Principal already exists. Use /aip/auth/login instead.")

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
    """Login an existing principal by external_id (no verification — for dev/testing)."""
    async with async_session() as session:
        result = await session.execute(
            select(Principal).where(Principal.external_id == body.external_id)
        )
        principal = result.scalar_one_or_none()
        if not principal:
            raise HTTPException(404, "Principal not found")

    token = _make_management_token(principal.id, request)
    return {"principal_id": principal.id, "management_token": token}
