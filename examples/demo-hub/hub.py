"""
Demo hub with AIP token verification and approval workflow, over three
action endpoints to show different approval triggers:

- POST /api/book-flight — amount-based threshold (e.g. > $500 needs approval)
- POST /api/delete-file — destructive: always requires approval
- POST /api/trade       — amount-based threshold

Two approval modes are supported, auto-detected from the IdP's discovery doc:

- **Local (Model 1)** — hub holds approval state; `approve.py` hits the
  hub's /agentid/approvals endpoints directly.
- **IdP-delegated (Model 3)** — IdP advertises `approval_endpoint`;
  hub forwards the decision, IdP portal surfaces + signs it, hub verifies
  the JWT against JWKS and materializes a local grant.

Agents see the same 202 + poll + X-AgentID-Approval retry protocol in both modes.

Start: uvicorn hub:app --port 8001
The IdP target is selected by AGENTID_IDP (default: "local"); see IDP_PROFILES
below. Set AGENTID_IDP_URL to override with an arbitrary URL. Match this
to the agent-side AGENTID_IDP so the issued tokens are trusted.
"""

import os
import secrets
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse

import httpx
import jwt as pyjwt
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from agent_id_service_sdk import Verifier

# Module-level HTTP client so all hub→IdP calls share one connection pool.
# Created in the lifespan below and closed on shutdown.
_http: httpx.AsyncClient | None = None


def _client() -> httpx.AsyncClient:
    if _http is None:
        raise RuntimeError("HTTP client not initialized — lifespan did not run")
    return _http


@asynccontextmanager
async def lifespan(_: FastAPI):
    global _http
    _http = httpx.AsyncClient(timeout=5.0)
    try:
        yield
    finally:
        await _http.aclose()
        _http = None


app = FastAPI(title="Demo Hub", lifespan=lifespan)

HUB_URL = "http://localhost:8001"

# IdP target — pick a named profile via AGENTID_IDP, or override with AGENTID_IDP_URL.
# Provider domain is derived from the URL so trust stays consistent.
IDP_PROFILES = {
    "local": "http://localhost:8000",
    "pre": "https://pre.agent-id.live",
    "prod": "https://agent-id.live",
}


def _resolve_idp_url() -> tuple[str, str]:
    explicit = os.environ.get("AGENTID_IDP_URL")
    if explicit:
        return "custom", explicit
    profile = os.environ.get("AGENTID_IDP", "local")
    url = IDP_PROFILES.get(profile)
    if url is None:
        raise SystemExit(
            f"AGENTID_IDP={profile!r} unknown; choose {list(IDP_PROFILES)} or set AGENTID_IDP_URL"
        )
    return profile, url


_profile, IDP_BASE_URL = _resolve_idp_url()
IDP_PROVIDER = urlparse(IDP_BASE_URL).netloc
print(f"[config] IdP profile={_profile} → {IDP_BASE_URL} (provider={IDP_PROVIDER})")

verifier = Verifier(
    trusted_providers=[IDP_PROVIDER],
    audience=HUB_URL,
    provider_urls={IDP_PROVIDER: IDP_BASE_URL},
)

# Hub policy for amount-based actions.
REQUIRES_APPROVAL_ABOVE = 500.0
APPROVAL_TTL = timedelta(minutes=10)
GRANT_TTL = timedelta(minutes=30)

# In-memory state.
wallet_balance: dict[str, float] = {}  # principal_id -> balance
STARTING_BALANCE = 10_000.0

# Cached IdP discovery.
_idp_approval_endpoint: str | None = None
_idp_discovery_checked: bool = False


@dataclass
class ApprovalRequest:
    approval_id: str
    agent_id: str
    agent_name: str
    principal_id: str
    # Hub-native fields — used for local-mode grant enforcement.
    resource: str
    action: str
    details: dict[str, Any]
    reason: str
    expires_at: datetime
    # Protocol-generic display + payload, built by the action endpoint and
    # forwarded to the IdP verbatim in delegated mode.
    summary: str = ""
    facts: list[dict[str, Any]] = field(default_factory=list)
    hub_payload: dict[str, Any] = field(default_factory=dict)
    status: str = "pending"
    grant_id: str | None = None
    denial_reason: str | None = None
    approved_at: datetime | None = None
    approved_by: str | None = None
    delegated: bool = False
    idp_approval_id: str | None = None


@dataclass
class Grant:
    grant_id: str
    approval_id: str
    agent_id: str
    resource: str
    action: str
    constraints: dict[str, Any]
    approved_by: str
    approved_at: datetime
    expires_at: datetime
    used: bool = False


approvals: dict[str, ApprovalRequest] = {}
grants: dict[str, Grant] = {}


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


async def get_agent(request: Request):
    auth = request.headers.get("Authorization")
    if not auth:
        raise HTTPException(401, "Missing Authorization header")
    try:
        return await verifier.verify(auth)
    except Exception as e:
        raise HTTPException(401, str(e))


# -- IdP discovery / delegation ---------------------------------------------


async def _discover_idp_approval_endpoint() -> str | None:
    """Fetch the IdP's discovery doc once and cache its approval_endpoint (if any).

    Rewrites the advertised URL through IDP_BASE_URL so it's reachable in
    local dev, mirroring the verifier's provider_urls override pattern.
    """
    global _idp_approval_endpoint, _idp_discovery_checked
    if _idp_discovery_checked:
        return _idp_approval_endpoint
    _idp_discovery_checked = True
    advertised = None
    try:
        resp = await _client().get(f"{IDP_BASE_URL}/.well-known/agentid-configuration")
        resp.raise_for_status()
        advertised = resp.json().get("approval_endpoint")
    except Exception as e:
        print(f"[discovery] could not fetch IdP config: {e}")
    if advertised:
        from urllib.parse import urlparse

        path = urlparse(advertised).path or "/agentid/approvals"
        _idp_approval_endpoint = f"{IDP_BASE_URL.rstrip('/')}{path}"
    mode = "delegated (Model 3)" if _idp_approval_endpoint else "local (Model 1)"
    print(f"[discovery] approval mode: {mode}")
    if _idp_approval_endpoint:
        print(f"[discovery] IdP approval endpoint: {_idp_approval_endpoint}")
    return _idp_approval_endpoint


async def _delegate_to_idp(approval: ApprovalRequest) -> None:
    endpoint = await _discover_idp_approval_endpoint()
    assert endpoint is not None
    payload: dict[str, Any] = {
        "hub_id": HUB_URL,
        "agent_id": approval.agent_id,
        "summary": approval.summary,
        "facts": approval.facts,
        "payload": approval.hub_payload,
        "ttl_seconds": int(APPROVAL_TTL.total_seconds()),
    }
    resp = await _client().post(endpoint, json=payload)
    resp.raise_for_status()
    data = resp.json()
    approval.delegated = True
    approval.idp_approval_id = data["approval_id"]
    print(
        f"[delegate] IdP stored approval {data['approval_id']} "
        f"(local id {approval.approval_id})"
    )


async def _poll_idp_for_decision(approval: ApprovalRequest) -> None:
    endpoint = await _discover_idp_approval_endpoint()
    if endpoint is None or approval.idp_approval_id is None:
        return
    poll_url = endpoint.rstrip("/") + f"/{approval.idp_approval_id}"
    try:
        resp = await _client().get(poll_url)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(f"[poll] IdP poll failed: {e}")
        return

    status = data.get("status")
    if status not in ("approved", "denied"):
        return
    decision_jwt = data.get("decision_jwt")
    if not decision_jwt:
        return

    claims = await _verify_decision_jwt(decision_jwt, approval.agent_id)
    if claims is None:
        return

    if claims["decision"] == "approved":
        ctx = claims.get("ctx", {}) or {}
        constraints = _build_grant_constraints(ctx)
        grant_id = f"gnt_{secrets.token_hex(5)}"
        now = _now()
        grant = Grant(
            grant_id=grant_id,
            approval_id=approval.approval_id,
            agent_id=approval.agent_id,
            resource=approval.resource,
            action=approval.action,
            constraints=constraints,
            approved_by=claims.get("decided_by", "principal"),
            approved_at=now,
            expires_at=now + GRANT_TTL,
        )
        grants[grant_id] = grant
        approval.status = "approved"
        approval.grant_id = grant_id
        approval.approved_at = now
        approval.approved_by = grant.approved_by
        print(
            f"[poll] IdP approved {approval.approval_id} → grant {grant_id} "
            f"(constraints={constraints})"
        )
    else:
        approval.status = "denied"
        approval.denial_reason = claims.get("note") or "Denied by principal"
        print(f"[poll] IdP denied {approval.approval_id}: {approval.denial_reason}")


def _build_grant_constraints(ctx: dict[str, Any]) -> dict[str, Any]:
    """Derive local grant constraints from the JWT ctx echo.

    ctx is the hub's original opaque payload, echoed back by the IdP. The
    principal's decision is binary — all enforcement knobs (amount caps,
    path matching, currency) come from what the hub originally requested.
    This is also the hub's replay cap: the signed grant can only be used
    for the action it was issued for, with the amount/path originally
    submitted.
    """
    constraints: dict[str, Any] = {}
    requested_amount = ctx.get("amount")
    if isinstance(requested_amount, (int, float)) and not isinstance(
        requested_amount, bool
    ):
        constraints["max_amount"] = requested_amount
        if "currency" in ctx:
            constraints["currency"] = ctx["currency"]
    if "path" in ctx:
        constraints["path"] = ctx["path"]
    return constraints


async def _verify_decision_jwt(token: str, expected_agent_id: str) -> dict | None:
    try:
        unverified = pyjwt.decode(token, options={"verify_signature": False})
        issuer = unverified.get("iss", "")
        from urllib.parse import urlparse

        provider_domain = urlparse(issuer).netloc if "://" in issuer else issuer
        keys = await verifier._fetch_jwks(provider_domain)  # noqa: SLF001
        kid = pyjwt.get_unverified_header(token).get("kid")
        if not kid:
            print("[verify] decision JWT missing kid")
            return None
        if kid not in keys:
            keys = await verifier._fetch_jwks(provider_domain, force_refresh=True)  # noqa: SLF001
        public_key = keys.get(kid)
        if public_key is None:
            print(f"[verify] no public key for kid={kid}")
            return None
        claims = pyjwt.decode(
            token,
            public_key,
            algorithms=["ES256", "EdDSA"],
            audience=HUB_URL,
            options={"require": ["exp", "iss", "aud", "sub"]},
        )
    except Exception as e:
        print(f"[verify] decision JWT verification failed: {e}")
        return None

    if claims.get("type") != "approval_decision":
        print(f"[verify] wrong token type: {claims.get('type')}")
        return None
    if claims.get("sub") != expected_agent_id:
        print(
            f"[verify] sub mismatch: expected {expected_agent_id}, got {claims.get('sub')}"
        )
        return None
    return claims


def _notify_principal(approval: ApprovalRequest, principal_claim: dict) -> None:
    if approval.delegated:
        print(
            f"[notify → portal] IdP will surface {approval.approval_id} "
            f"to {approval.principal_id}"
        )
        return
    endpoint = principal_claim.get("notification_endpoint")
    target = endpoint or f"console://principal/{approval.principal_id}"
    print(
        f"\n[notify → {target}] "
        f"{approval.action} — {approval.details} "
        f"(approve: {HUB_URL}/agentid/approvals/{approval.approval_id}/approve)\n"
    )


# -- Shared approval / grant helpers ---------------------------------------


async def _start_approval(
    agent,
    *,
    resource: str,
    action: str,
    details: dict,
    reason: str,
    summary: str,
    facts: list[dict[str, Any]],
) -> ApprovalRequest:
    approval_id = f"apr_{secrets.token_hex(5)}"
    expires = _now() + APPROVAL_TTL
    # hub_payload is what the IdP echoes back in the decision JWT's ctx.
    # Embed resource/action so we can correlate; embed details so we can
    # apply hub-side policy (replay caps, path matching) from the JWT.
    hub_payload = {"resource": resource, "action": action, **details}
    approval = ApprovalRequest(
        approval_id=approval_id,
        agent_id=agent.agent_id,
        agent_name=agent.agent_name,
        principal_id=agent.principal.get("id", ""),
        resource=resource,
        action=action,
        details=details,
        reason=reason,
        expires_at=expires,
        summary=summary,
        facts=facts,
        hub_payload=hub_payload,
    )
    if await _discover_idp_approval_endpoint() is not None:
        try:
            await _delegate_to_idp(approval)
        except Exception as e:
            print(f"[delegate] failed, falling back to local: {e}")
    approvals[approval_id] = approval
    _notify_principal(approval, agent.principal)
    return approval


def _approval_response(
    approval: ApprovalRequest, threshold_note: str = ""
) -> JSONResponse:
    content = {
        "status": "approval_required",
        "approval_id": approval.approval_id,
        "resource": approval.resource,
        "action": approval.action,
        "details": approval.details,
        "poll_url": f"/agentid/approvals/{approval.approval_id}",
        "expires_at": _iso(approval.expires_at),
        "approval_via": "idp" if approval.delegated else "hub",
    }
    if threshold_note:
        content["threshold_exceeded"] = threshold_note
    return JSONResponse(status_code=202, content=content)


def _consume_grant(
    x_aip_grant: str | None, agent, action: str, amount: float | None = None
) -> Grant | None:
    """Validate and consume a presented grant for *action*. Returns the grant if valid.

    Raises 403 if presented but invalid. Returns None if no grant was presented
    (caller decides whether that's OK for the request).
    """
    if not x_aip_grant:
        return None
    grant = grants.get(x_aip_grant)
    if not grant:
        raise HTTPException(403, "Unknown grant")
    if grant.agent_id != agent.agent_id:
        raise HTTPException(403, "Grant was not issued to this agent")
    if grant.action != action:
        raise HTTPException(403, f"Grant not valid for action: {grant.action}")
    if grant.used:
        raise HTTPException(403, "Grant already used (single-use)")
    if _now() > grant.expires_at:
        raise HTTPException(403, "Grant expired")
    max_amount = grant.constraints.get("max_amount")
    if max_amount is not None and amount is not None and amount > max_amount:
        raise HTTPException(
            403, f"Amount {amount} exceeds grant max_amount {max_amount}"
        )
    grant.used = True
    return grant


# -- Action endpoints -------------------------------------------------------


class BookFlightRequest(BaseModel):
    destination: str = Field(min_length=1)
    amount: float = Field(gt=0)
    refundable: bool = False


@app.post("/api/book-flight")
async def book_flight(
    body: BookFlightRequest,
    request: Request,
    x_aip_grant: str | None = Header(default=None),
):
    agent = await get_agent(request)
    principal_id = agent.principal.get("id", "")
    balance = wallet_balance.setdefault(principal_id, STARTING_BALANCE)
    action = "flight.book"

    grant = _consume_grant(x_aip_grant, agent, action, amount=body.amount)
    if grant is not None or body.amount <= REQUIRES_APPROVAL_ABOVE:
        wallet_balance[principal_id] = balance - body.amount
        return {
            "status": "booked",
            "destination": body.destination,
            "amount": body.amount,
            "refundable": body.refundable,
            "balance": wallet_balance[principal_id],
            "grant_id": grant.grant_id if grant else None,
        }

    approval = await _start_approval(
        agent,
        resource="/api/book-flight",
        action=action,
        details={
            "amount": body.amount,
            "destination": body.destination,
            "refundable": body.refundable,
            "currency": "USD",
        },
        reason=f"Flight cost exceeds confirmation threshold ({REQUIRES_APPROVAL_ABOVE} USD)",
        summary=f"Book flight to {body.destination} for ${body.amount:,.2f}",
        facts=[
            {"label": "Destination", "value": body.destination},
            {
                "label": "Amount",
                "value": f"${body.amount:,.2f} USD",
                "kind": "money",
            },
            {"label": "Refundable", "value": "Yes" if body.refundable else "No"},
        ],
    )
    return _approval_response(
        approval,
        threshold_note=f"requires_confirmation_above: {REQUIRES_APPROVAL_ABOVE}",
    )


class DeleteFileRequest(BaseModel):
    path: str = Field(min_length=1)


@app.post("/api/delete-file")
async def delete_file(
    body: DeleteFileRequest,
    request: Request,
    x_aip_grant: str | None = Header(default=None),
):
    """Destructive action — always requires approval, regardless of amount.

    Grants are scoped to a specific path via constraints.path set by the
    principal's decision; the hub enforces that here.
    """
    agent = await get_agent(request)
    action = "file.delete"

    grant = _consume_grant(x_aip_grant, agent, action)
    if grant is not None:
        allowed_path = grant.constraints.get("path")
        if allowed_path and allowed_path != body.path:
            raise HTTPException(
                403,
                f"Grant allows deleting {allowed_path}, not {body.path}",
            )
        return {
            "status": "deleted",
            "path": body.path,
            "grant_id": grant.grant_id,
        }

    # No threshold path for destructive actions — always delegate.
    approval = await _start_approval(
        agent,
        resource="/api/delete-file",
        action=action,
        details={"path": body.path},
        reason="Destructive action — always requires principal approval",
        summary=f"Delete file: {body.path}",
        facts=[
            {"label": "Path", "value": body.path},
            {
                "label": "Reversible",
                "value": "No — destructive",
                "kind": "risk",
            },
        ],
    )
    return _approval_response(approval)


class TradeRequest(BaseModel):
    pair: str = Field(min_length=1)  # e.g. "BTC/USD"
    amount: float = Field(gt=0)
    side: str = Field(pattern="^(buy|sell)$")


@app.post("/api/trade")
async def trade(
    body: TradeRequest,
    request: Request,
    x_aip_grant: str | None = Header(default=None),
):
    agent = await get_agent(request)
    principal_id = agent.principal.get("id", "")
    balance = wallet_balance.setdefault(principal_id, STARTING_BALANCE)
    action = "trade.execute"

    grant = _consume_grant(x_aip_grant, agent, action, amount=body.amount)
    if grant is not None or body.amount <= REQUIRES_APPROVAL_ABOVE:
        if body.side == "buy":
            wallet_balance[principal_id] = balance - body.amount
        else:
            wallet_balance[principal_id] = balance + body.amount
        return {
            "status": "executed",
            "pair": body.pair,
            "side": body.side,
            "amount": body.amount,
            "balance": wallet_balance[principal_id],
            "grant_id": grant.grant_id if grant else None,
        }

    approval = await _start_approval(
        agent,
        resource="/api/trade",
        action=action,
        details={
            "amount": body.amount,
            "pair": body.pair,
            "side": body.side,
            "currency": "USD",
        },
        reason=f"Trade amount exceeds confirmation threshold ({REQUIRES_APPROVAL_ABOVE} USD)",
        summary=f"{body.side.upper()} ${body.amount:,.2f} of {body.pair}",
        facts=[
            {"label": "Pair", "value": body.pair},
            {"label": "Side", "value": body.side},
            {
                "label": "Amount",
                "value": f"${body.amount:,.2f} USD",
                "kind": "money",
            },
        ],
    )
    return _approval_response(
        approval,
        threshold_note=f"requires_confirmation_above: {REQUIRES_APPROVAL_ABOVE}",
    )


# -- Grant endpoints (spec 7.6.6) -------------------------------------------


def _expire_if_needed(approval: ApprovalRequest) -> None:
    if approval.status == "pending" and _now() > approval.expires_at:
        approval.status = "expired"


def _serialize_grant(grant: Grant) -> dict:
    return {
        "grant_id": grant.grant_id,
        "resource": grant.resource,
        "action": grant.action,
        "constraints": grant.constraints,
        "approved_by": grant.approved_by,
        "approved_at": _iso(grant.approved_at),
        "expires_at": _iso(grant.expires_at),
    }


@app.get("/agentid/approvals/{approval_id}")
async def poll_grant(approval_id: str, request: Request):
    agent = await get_agent(request)
    approval = approvals.get(approval_id)
    if not approval:
        raise HTTPException(404, "Unknown approval_id")
    if approval.agent_id != agent.agent_id:
        raise HTTPException(403, "Approval belongs to a different agent")

    _expire_if_needed(approval)
    if approval.delegated and approval.status == "pending":
        await _poll_idp_for_decision(approval)

    if approval.status == "pending":
        return {
            "approval_id": approval_id,
            "status": "pending",
            "expires_at": _iso(approval.expires_at),
        }
    if approval.status == "approved" and approval.grant_id:
        grant = grants[approval.grant_id]
        return {
            "approval_id": approval_id,
            "status": "approved",
            "grant": _serialize_grant(grant),
        }
    if approval.status == "denied":
        return {
            "approval_id": approval_id,
            "status": "denied",
            "reason": approval.denial_reason,
        }
    return {"approval_id": approval_id, "status": "expired"}


class ApproveRequest(BaseModel):
    """Principal-side approve for LOCAL mode only (Model 1)."""

    approved_by: str = "principal"
    max_amount: float | None = None


@app.post("/agentid/approvals/{approval_id}/approve")
async def approve(approval_id: str, body: ApproveRequest | None = None):
    approval = approvals.get(approval_id)
    if not approval:
        raise HTTPException(404, "Unknown approval_id")
    if approval.delegated:
        raise HTTPException(
            409,
            "This approval is delegated to the IdP — approve via the portal.",
        )
    _expire_if_needed(approval)
    if approval.status != "pending":
        raise HTTPException(409, f"Approval is {approval.status}")

    body = body or ApproveRequest()
    constraints: dict[str, Any] = {}
    amount = approval.details.get("amount")
    if amount is not None:
        max_amount = min(body.max_amount, amount) if body.max_amount else amount
        constraints["max_amount"] = max_amount
        constraints["currency"] = approval.details.get("currency", "USD")
    if "path" in approval.details:
        constraints["path"] = approval.details["path"]

    grant_id = f"gnt_{secrets.token_hex(5)}"
    now = _now()
    grant = Grant(
        grant_id=grant_id,
        approval_id=approval_id,
        agent_id=approval.agent_id,
        resource=approval.resource,
        action=approval.action,
        constraints=constraints,
        approved_by=body.approved_by,
        approved_at=now,
        expires_at=now + GRANT_TTL,
    )
    grants[grant_id] = grant
    approval.status = "approved"
    approval.grant_id = grant_id
    approval.approved_at = now
    approval.approved_by = body.approved_by

    return {
        "approval_id": approval_id,
        "status": "approved",
        "grant": _serialize_grant(grant),
    }


class DenyRequest(BaseModel):
    reason: str = "Denied by principal"


@app.post("/agentid/approvals/{approval_id}/deny")
async def deny(approval_id: str, body: DenyRequest | None = None):
    approval = approvals.get(approval_id)
    if not approval:
        raise HTTPException(404, "Unknown approval_id")
    if approval.delegated:
        raise HTTPException(
            409,
            "This approval is delegated to the IdP — deny via the portal.",
        )
    _expire_if_needed(approval)
    if approval.status != "pending":
        raise HTTPException(409, f"Approval is {approval.status}")

    body = body or DenyRequest()
    approval.status = "denied"
    approval.denial_reason = body.reason
    return {"approval_id": approval_id, "status": "denied", "reason": body.reason}


@app.get("/agentid/approvals")
async def list_grants(principal_id: str | None = None, status: str | None = None):
    items = []
    for approval in approvals.values():
        _expire_if_needed(approval)
        if principal_id and approval.principal_id != principal_id:
            continue
        if status and approval.status != status:
            continue
        items.append(
            {
                "approval_id": approval.approval_id,
                "agent_id": approval.agent_id,
                "agent_name": approval.agent_name,
                "principal_id": approval.principal_id,
                "resource": approval.resource,
                "action": approval.action,
                "details": approval.details,
                "reason": approval.reason,
                "status": approval.status,
                "expires_at": _iso(approval.expires_at),
                "delegated": approval.delegated,
            }
        )
    return {"approvals": items}


# -- Discovery --------------------------------------------------------------


@app.get("/api/whoami")
async def whoami(request: Request):
    agent = await get_agent(request)
    return {
        "agent_id": agent.agent_id,
        "agent_name": agent.agent_name,
        "principal": agent.principal,
        "capabilities": agent.capabilities,
        "balance": wallet_balance.get(agent.principal.get("id", ""), STARTING_BALANCE),
    }


@app.get("/.well-known/agentid-hub")
async def hub_discovery():
    return {
        "service_id": HUB_URL,
        "trusted_providers": [IDP_PROVIDER],
        "local_mode": False,
        "agentid_version": "1.0",
    }
