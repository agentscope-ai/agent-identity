# Hub Integration Guide

How to make a service speak the AgentID protocol — from "publish your identity" up to "accept agents and verify their tokens."

This is the doc to read **first** if you're integrating a new service. The design docs in `design/` cover the *why*; this covers the *what to actually do*.

## Who this is for

You're integrating a service that wants to participate in AgentID. The protocol's core unit is the **hub** — a service that both publishes a verifiable identity and accepts agents authenticated by trusted IdPs. Identity and acceptance are two halves of one JWS handshake: the issuer side proves who you are, the verifier side checks who your peers are. Either half on its own is degenerate — publishing a key without ever verifying tokens is "I exist" with no use; verifying tokens without a published identity makes you unaddressable. So Level 1 bundles them.

This bundling is deliberate. Treating identity and acceptance as separate capabilities is the architectural mistake we critique in competing protocols: identity that nothing verifies against, and acceptance that anyone can claim. The two only make sense together.

Activity emission and (when shipped) approval gating layer on top of a working hub.

| Level | What you do | Reasonable effort |
|---|---|---|
| **Hub (identity + acceptance)** | Publish your hub identity (manifest + JWKS) AND accept Bearer-JWT-authenticated agents from trusted IdPs. The minimum to participate as both attestation issuer and peer verifier. The DojoZero shape. | About a week |
| **Activity emission** | Above, plus emit signed activity events to an aip-activity service for audit and cross-hub reputation. Most production hubs land here. | +2–3 days |
| **Approval gating** *(preview)* | Above, plus gate high-risk actions through IdP-delegated approval (§7.6 thin grants, Model 3 — see `design/2026-04-23-approval-scenarios.en.md`). Designed; not yet shipped end-to-end in the SDK. | TBD |

Levels 2 and 3 build on Level 1. Pick the lowest level that meets your needs; you can grow into more later.

## Prerequisites

- Python 3.10+ with `agent-id-service-sdk >= 0.4.2` installed.
- A FastAPI / Starlette application. Other Python frameworks are reachable with thin adapters; non-Python stacks need to wait for the sidecar (see the deferred-work doc).
- A real (or local-dev) hostname for your service, with the eTLD+1 you want to use as your namespace. Example: `api.dojozero.live` → namespace `dojozero`.
- An Ed25519 keypair (we'll generate one in step 1).

---

## Level 1 — Hub (identity + acceptance)

Goal: be a working hub. Publish your identity (manifest + JWKS) so peers can verify you, AND accept agents presenting Bearer JWTs from IdPs you trust. Both halves of the JWS handshake live here.

### 1.1 Mint a hub keypair

```bash
python -m agent_id_service_sdk.keygen --kid prod-hub-key-1 --out /run/secrets/hub-key.pem
```

Outputs:
- A PEM file at the path (mode 0600). Treat as a secret — load via your secret manager.
- A public JWK printed to stdout. You'll publish this at the JWKS endpoint.

The `kid` is your choice. Convention: `<env>-hub-key-N` so rotation later is unambiguous. There's only one key per deployment today; rotation tooling lands when the spec defines it.

### 1.2 Configure the hub

```python
# myhub/config.py
import os

HUB_SERVICE_ID = "https://api.myservice.com"      # public origin, no trailing slash
HUB_NAMESPACE = "myservice"                        # must match service_id's eTLD+1
HUB_KID = "prod-hub-key-1"
HUB_PRIVATE_KEY_PEM = open(os.environ["HUB_KEY_PEM_PATH"]).read()

# Trust list — IdPs whose tokens you'll accept at the verifier side.
# Tokens from issuers not in this list are rejected. Add as you onboard
# new IdPs; never auto-trust on first sight.
TRUSTED_PROVIDERS = [
    "qwenpaw.ai",
    # "openclaw.ai",
    # "internal-idp.mycompany.com",
]
```

For IdPs that aren't reachable at the conventional `https://<provider_domain>/.well-known/...` path (e.g., local dev), add a `provider_urls` mapping when constructing the Verifier in §1.4.

### 1.3 Mount the well-known endpoints

The SDK gives you `build_manifest`, `sign_manifest`, and `public_key_to_jwk`. You wire two FastAPI routes that publish what they produce.

```python
# myhub/agentid_routes.py
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from fastapi import APIRouter
from fastapi.responses import PlainTextResponse
from agent_id_service_sdk.manifest_signing import (
    build_manifest, sign_manifest, public_key_to_jwk,
)
from myhub.config import (
    HUB_SERVICE_ID, HUB_NAMESPACE, HUB_KID, HUB_PRIVATE_KEY_PEM,
)

router = APIRouter()

# Cache once at module load — the manifest is static per deployment.
_PRIVATE_KEY = load_pem_private_key(
    HUB_PRIVATE_KEY_PEM.encode(), password=None,
)
_PUBLIC_JWK = public_key_to_jwk(_PRIVATE_KEY.public_key(), kid=HUB_KID)

_MANIFEST = build_manifest(
    service_id=HUB_SERVICE_ID,
    namespace=HUB_NAMESPACE,
    categories_url=f"{HUB_SERVICE_ID}/.well-known/agent-id-activity-categories",
    jwks_url=f"{HUB_SERVICE_ID}/.well-known/agent-id-jwks",
)
_SIGNED_MANIFEST = sign_manifest(_MANIFEST, private_key=_PRIVATE_KEY, kid=HUB_KID)


@router.get("/.well-known/agent-id-jwks")
async def jwks():
    return {"keys": [_PUBLIC_JWK]}


@router.get("/.well-known/agent-id-activity-manifest")
async def manifest():
    # Manifest is a JWS compact-serialized string.
    return PlainTextResponse(_SIGNED_MANIFEST, media_type="application/jose")
```

Mount in your app:

```python
# myhub/main.py
from fastapi import FastAPI
from myhub.agentid_routes import router as agentid_router

app = FastAPI()
app.include_router(agentid_router)
```

### 1.4 Mount the verifier as an auth dependency

The same `Verifier` class that signs your activity envelopes (Level 2) also handles inbound JWT verification. Construct one instance and reuse it for both:

```python
# myhub/agentid.py
from agent_id_service_sdk import Verifier
from myhub.config import (
    HUB_SERVICE_ID, HUB_KID, HUB_PRIVATE_KEY_PEM, TRUSTED_PROVIDERS,
)

verifier = Verifier(
    trusted_providers=TRUSTED_PROVIDERS,
    audience=HUB_SERVICE_ID,
    # Hub signing — needed once you reach Level 2 (activity emission).
    # Safe to wire now even if you haven't enabled emission yet.
    hub_signing_key=HUB_PRIVATE_KEY_PEM,
    hub_signing_kid=HUB_KID,
    hub_service_id=HUB_SERVICE_ID,
)
```

Wrap it in a FastAPI dependency:

```python
# myhub/auth.py
from fastapi import Header, HTTPException, Request
from myhub.agentid import verifier


async def get_agent(
    request: Request,
    authorization: str | None = Header(default=None),
):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Authorization: Bearer <token> required")
    try:
        return await verifier.verify_token(
            authorization[7:],
            request_context={"route": request.url.path},
        )
    except Exception as exc:  # narrow this; see SDK errors module
        raise HTTPException(401, f"Token verification failed: {exc}") from exc
```

### 1.5 Use it in your routes

```python
from fastapi import Depends, HTTPException
from myhub.auth import get_agent


@app.post("/some-agent-action")
async def agent_action(
    body: SomeRequest,
    agent = Depends(get_agent),
):
    # agent.agent_id, agent.principal, agent.issuer, etc. are all verified.
    # The token's audience matched HUB_SERVICE_ID; the issuer is in your trust list.
    if "myservice:write" not in agent.scopes:
        raise HTTPException(403, "scope required: myservice:write")
    # ... your logic ...
```

### 1.6 Smoke test (publish + verify)

**Publish side** — peers can fetch and verify your identity:

```bash
curl https://api.myservice.com/.well-known/agent-id-activity-manifest
# → eyJhbGciOiJFZERTQSIsImtpZCI6...   (JWS compact form)

curl https://api.myservice.com/.well-known/agent-id-jwks
# → {"keys":[{"kty":"OKP","crv":"Ed25519","x":"...","kid":"prod-hub-key-1"}]}
```

From any other process, fetching the signed manifest succeeds:

```python
from agent_id_service_sdk import HubManifestFetcher

fetcher = HubManifestFetcher()
manifest = await fetcher.fetch("https://api.myservice.com")
# raises HubManifestSignatureError if the signature doesn't match the JWKS
```

**Verify side** — your service rejects unsigned and accepts properly-issued tokens:

```bash
# Missing token → 401
curl -X POST https://api.myservice.com/some-agent-action
# → {"detail":"Authorization: Bearer <token> required"}

# Token from an issuer not in TRUSTED_PROVIDERS → 401
curl -X POST -H "Authorization: Bearer <bogus-token>" https://api.myservice.com/some-agent-action
# → {"detail":"Token verification failed: ..."}

# Token from a trusted IdP, scope satisfied → your handler runs
```

That's a Level-1 hub. ~80 lines of integration code, about a week to ship if you're wiring it into a new service. The hard parts (envelope signing, trust list, JWS verification) are all in the SDK; you write configuration and a route dependency.

---

## Level 2 — Activity emission

Goal: in addition to being a hub, your service emits *signed* activity events to an aip-activity service so that audit, reputation, and cross-hub correlation work.

### 2.1 Define your categories

Activity events fall into three tiers (per `design/2026-05-04-activity-discovery.en.md`):

- **Tier-1** — universal lifecycle events: `session.start`, `session.end`, `model.call`, `tool.use`, `auth.deny`, `transfer.value`, etc. Spec-defined; you don't get to redefine these.
- **Tier-2** — your hub's own categories, namespaced. `myservice.payment_settled`, `myservice.dataset_accessed`. You define the schema.
- **Tier-3** — opaque events. No schema. Use sparingly; aip-activity stores but doesn't aggregate them.

For Level 2 you need to publish a **categories doc** advertising your Tier-2 entries (Tier-1 needs no advertisement; it's spec-defined).

### 2.2 Publish the categories doc

The categories doc and per-category JSON Schemas are served as **plain JSON** today (the SDK doesn't yet sign them — relying on the manifest's signed `categories_url` as the trust anchor). This will likely tighten in a future spec rev; treat the unsigned form as a current implementation choice, not a permanent guarantee.

```python
# myhub/agentid_routes.py (continued)
from fastapi.responses import JSONResponse

_CATEGORIES_DOC = {
    "service_id": HUB_SERVICE_ID,
    "namespace": HUB_NAMESPACE,
    "categories": [
        {
            "category": "myservice.payment_settled",
            "schema_version": "1.0.0",
            "schema_url": f"{HUB_SERVICE_ID}/.well-known/agent-id-activity-schemas/payment_settled/1.0.0",
            "schema_format": "json-schema",
            "deprecated": False,
            "sensitive_fields": ["amount", "counterparty_id"],
        },
    ],
}


@router.get("/.well-known/agent-id-activity-categories")
async def categories():
    return JSONResponse(_CATEGORIES_DOC)


@router.get("/.well-known/agent-id-activity-schemas/{category}/{version}")
async def schema(category: str, version: str):
    # Static JSON Schema files; load from your repo.
    schema_dict = load_schema(category, version)  # your responsibility
    return JSONResponse(schema_dict)
```

JSON Schema for a payment-settled category looks like:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["payment_id", "amount", "currency"],
  "properties": {
    "payment_id": {"type": "string"},
    "amount": {"type": "number", "minimum": 0},
    "currency": {"type": "string", "pattern": "^[A-Z]{3}$"},
    "counterparty_id": {"type": "string"},
    "memo": {"type": "string", "maxLength": 200}
  }
}
```

Schema design tips:
- Keep payloads small — these become reputation signals, not full audit records.
- Mark sensitive fields in the categories doc, not the schema. aip-activity reads `sensitive_fields` to enforce per-privacy-level redaction.
- Version with semver. Multiple versions can coexist for migration windows; `deprecated: true` signals "stop using, will be removed."

### 2.3 Wire the emitter

The same `Verifier` instance you constructed in §1.4 also exposes `report_event()`, which queues an event, signs it as a HubJWS envelope, and posts to the upstream activity service. Add the activity-related options to that constructor:

```python
# myhub/agentid.py — extend the §1.4 Verifier
import os
from agent_id_service_sdk import Verifier
from myhub.config import (
    HUB_SERVICE_ID, HUB_KID, HUB_PRIVATE_KEY_PEM, TRUSTED_PROVIDERS,
)

ACTIVITY_ORIGIN = os.environ["MYHUB_ACTIVITY_ORIGIN"]   # e.g. https://activity.dojozero.live

verifier = Verifier(
    trusted_providers=TRUSTED_PROVIDERS,
    audience=HUB_SERVICE_ID,

    # Hub signing — already required at Level 1; reused here for envelopes.
    hub_signing_key=HUB_PRIVATE_KEY_PEM,
    hub_signing_kid=HUB_KID,
    hub_service_id=HUB_SERVICE_ID,

    # Activity-specific options:
    activity_endpoint=f"{ACTIVITY_ORIGIN}/agentid/activity",
    service_name="myhub",

    # Privacy posture (design §5.0). Conservative default; override per category.
    hub_privacy_claim={
        "default_level": "summary",
        "category_overrides": {
            "myservice.payment_settled": "full",   # full payload visible to aip-activity
        },
    },
)
```

Emit an event from your application code:

```python
from agent_id_service_sdk import VerifiedAgent

# Build a VerifiedAgent from whoever caused this event. For agent-driven
# actions, you already have the verified token claims; for hub-internal
# events, construct a minimal one with the hub's own identity.
agent = VerifiedAgent(
    agent_id="agentid:qwenpaw.ai:agent_xxx",  # the agent that caused this
    agent_name="...",
    principal={"id": "user_123"},
    issuer="qwenpaw.ai",
    expires_at=...,
    raw_claims={},
)

await verifier.report_event(
    category="myservice.payment_settled",
    agent=agent,
    payload={
        "payment_id": "pay_abc123",
        "amount": 49.99,
        "currency": "USD",
        "counterparty_id": "merchant_xyz",
    },
    session_id="checkout_session_abc",
    outcome="success",
)
```

The Verifier's emitter runs in a background asyncio task; `report_event` returns as soon as the event is queued. Failures are logged, not raised — the design treats activity emission as best-effort by default.

### 2.4 Smoke test

Watch your aip-activity server's logs after triggering an event. You should see:

```
INFO: 127.0.0.1 - "POST /agentid/activity HTTP/1.1" 202 Accepted
INFO: ingested event_id=... category=myservice.payment_settled ...
```

If you see `401 envelope verification failed`, something is mismatched between what you sign and what the receiver expects — see footguns below.

### 2.5 Tier-1 lifecycle events

Beyond your custom Tier-2 categories, emit Tier-1 events so aip-activity can build cross-hub reputation about your acceptance behavior:

- `session.start` when an agent is admitted (registration, first request, etc.).
- `session.end` when an agent leaves (unregistration, timeout).
- `auth.deny` when a token fails verification — lets reputation systems detect token-stuffing or impersonation attempts.

The SDK has helpers for these on the same `Verifier` instance (`report_session_start`, `report_session_end`). Wire them where the corresponding lifecycle events occur in your application — typically in your auth dependency for `auth.deny`, and at agent registration / cleanup paths for the session events.

That's a Level-2 hub. The hard parts (envelope signing, replay cache, JWS construction) are all in the SDK; you write configuration and category schemas.

---

## Level 3 — Approval gating *(preview)*

Goal: gate high-risk actions through human-in-the-loop approval, where the decision is delegated to the principal's IdP rather than implemented per-hub.

**Status: designed, not yet shipped end-to-end in the SDK.** This section is a placeholder so the level structure is honest about what's coming. Don't build against this surface yet — the wire shape may change.

The design lives in `design/2026-04-23-approval-scenarios.en.md`. Two models are described:

- **Hub-local approvals** — the hub itself runs the approval queue and presents decisions to the principal. Reference implementation in `examples/demo-hub/approve.py` and `hub.py`. Workable today for single-tenant deployments.
- **IdP-delegated approvals (Model 3)** — the hub forwards the approval request to the principal's IdP, which runs the workflow (presenting it through whatever channel the IdP already owns — corporate SSO, family-account console, bank-grade auth) and returns a signed decision. The Rita/Acme scenario is the canonical example. This is the differentiated mode and the one the Level-3 chapter will document once shipped.

If you have an integration that needs approval gating before the SDK lands the full Model 3 flow, the hub-local model is your option — talk to us so we can scope the right shape together.

---

## Common footguns

In rough order of how often we've hit them:

### `aud` is the activity service's *origin*, not the full URL

When signing an outbound HubJWS envelope, the `aud` claim must be the activity origin (e.g. `https://activity.example.com`), **not** the full POST URL (`https://activity.example.com/agentid/activity`). The receiver's `expected_aud` is the origin and the strings must match exactly.

The SDK's emitter handles this for you (since v0.4.2). If you're implementing in another language: strip path/query before signing.

### Namespace must match `service_id`'s eTLD+1

`service_id: https://api.dojozero.live` → `namespace: dojozero`. Not `dojozero.live`, not `api.dojozero`, not `mycompany`.

The SDK uses Mozilla's Public Suffix List via `tldextract` to enforce this. Edge cases:

- **Localhost dev** is whitelisted (any namespace works for `localhost:port` service_ids).
- **Subdomains and PSL entries** can surprise you. `api.example.co.uk` → eTLD+1 is `example.co.uk` so namespace must be `example`. If you deploy behind a CDN that puts you on a Vercel preview URL or Cloudflare workers domain, the eTLD+1 may be the CDN's domain. Use a custom domain in production.

### Manifest, categories, and JWKS must be on the same origin

All of `service_id/.well-known/*` should resolve to the same hub identity. If you serve categories from a CDN at a different origin, the manifest's signature still verifies (signature is content-bound), but tooling that walks the manifest tree (`manifest.categories_url → fetch`) will fail eTLD+1 ownership checks if the CDN is on a different domain.

Workaround: keep `.well-known/*` on the canonical service domain. Static content (per-category JSON Schemas) can live anywhere since they're referenced by absolute URL from the categories doc.

### Privacy claim semantics

The hub's `hub_privacy_claim` controls how aip-activity processes your events:

- `default_level: "full"` — full payload stored
- `default_level: "summary"` — payload reduced to non-sensitive fields per the categories doc's `sensitive_fields`
- `default_level: "existence"` — only event metadata, no payload
- `default_level: "none"` — event dropped entirely (rare; use for category-level kill switches)

`category_overrides` is the per-category override. Almost everyone wants `summary` as default and `full` for specific high-signal categories.

### The replay cache is in-memory only

aip-activity dedups envelope `jti`s for 120 seconds. Today this is a single-process in-memory cache. If you horizontally scale aip-activity, you need either sticky sessions per hub origin, or a Redis-backed cache (the SDK supports a `replay_cache` injection point but Redis isn't shipped). For DojoZero's scale this hasn't bitten yet; budget for it if you go multi-instance.

### Categories doc lookup happens once, then cached

`HubManifestFetcher` caches manifest + categories with TTL (1h default). When you publish a new category version, deployed agents pick it up on the next TTL expiry — not instantly. For dev iteration, restart your aip-activity (or use a short TTL via `cache_ttl_seconds` in the constructor).

### Signing key load order

If you bake `_SIGNED_MANIFEST` at module load time (as in the snippet above), changing `HUB_SERVICE_ID` requires a service restart. That's usually fine — these values are deployment-fixed — but don't write code that reads them dynamically expecting the manifest to update.

For local dev where you hop between `localhost:8080` and `localhost:8081`, load lazily (function returning a freshly-signed manifest) or restart between switches.

---

## What this guide doesn't cover yet

These are real gaps; they'll get their own sections once the underlying work lands:

- **Skill discovery.** A future spec extension lets hubs publish operational instructions (skills) for agents via the manifest. Not implemented today; design discussion in `design/2026-05-04-activity-discovery.en.md` (TODO add §3.4).
- **Key rotation.** No tooling yet. Rotate by deploying new key alongside old in JWKS, signing new artifacts with new `kid`, retiring old after cache TTLs expire — manual process today.
- **Non-Python frameworks.** Flask/Django adapters and a sidecar binary for non-Python stacks are deferred. See `design/2026-05-01-deferred-work.md`.
- **Federated trust (`attested_by`).** The manifest field is reserved but verification flow isn't implemented. Today every hub is its own trust anchor.
- **Multiple keys in JWKS.** The current SDK keygen produces one key; the JWKS endpoint can publish multiple but the lifecycle (rotation, retirement) isn't tooled.

---

## Reference implementation

DojoZero (`packages/dojozero/src/dojozero/gateway/`) is a complete Level-2 hub. Specifically:

- `_hub_publisher.py` — Level 1 (manifest + JWKS signing)
- `_hub_routes.py` — Level 1 routes mounted on the dashboard server
- `_agentid.py` — Level 1 (Verifier construction with all options wired)
- `_server.py` — Level 1 (agent registration, Bearer JWT verification via `get_agent_id` dependency)
- `_activity.py` — Level 2 (Tier-1 emission helpers: `emit_session_start`, `emit_model_call`, `emit_tool_use`, `emit_auth_deny`, etc.)

DojoZero carries a lot of code that isn't required for AgentID compliance (betting broker, data hub, Ray runtime, CLI). Filter accordingly when reading.

---

## When in doubt

- **The SDK is the contract.** If a footgun in this doc contradicts the SDK's behavior, the SDK wins and the doc needs an update — please file an issue.
- **The design docs are the *why*.** When you hit "but why does it work this way?", `design/2026-05-04-activity-discovery.en.md` and `design/2026-03-25-agentid.en.md` have the rationale.
- **Real questions go to the channel.** Adoption issues are how this guide gets better — flag the parts that didn't help.
