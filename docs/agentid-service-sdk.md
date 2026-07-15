# AgentID Service SDK (IDA side)

`agent-id-service-sdk` lets an **Agent Identity Connected App (IDA)** verify
the AgentID JWTs that agents present. An IDA is a resource server such as an
API gateway or application backend. The SDK checks the signature against the
IdP's published keys, the issuer, the audience, and expiry, and returns the
caller's identity.

This is the IDA-facing half. Agents obtain tokens with
[`agent-id-client-sdk`](./agentid-client-sdk.md).

> This guide tracks the ModelScope-aligned SDK. For the underlying protocol
> change list see [`modelscope-alignment.md`](./modelscope-alignment.md).

---

## Install

```bash
pip install agent-id-service-sdk
# optional setup-time helper if you register the IDA app from Python:
pip install agent-id-client-sdk
# or, from this monorepo:
uv pip install -e agent-id-service-sdk
uv pip install -e agent-id-client-sdk
```

Runtime deps: `httpx`, `cryptography`, `pyjwt[crypto]`, `tldextract`.

The service SDK is the runtime dependency for token verification. The client SDK
is **not** required to serve requests. It appears below only because the Python
setup helper `ModelScopeProvider.create_hub_app(...)` lives in
`agent_id_client_sdk.providers.modelscope` today. If you register the IDA app
in the ModelScope console or call `POST /hub_apps` directly, skip
`agent-id-client-sdk`.

---

## Prerequisite: register the IDA → get a `client_id`

ModelScope is the **central authority** for IDA identity. The IDA does **not**
self-advertise a `.well-known` manifest or JWKS for token authentication.
Instead you register the IDA once and ModelScope issues a `client_id`, which
becomes the **`aud`** every agent must target and the verifier must enforce.

### A. ModelScope console

In the ModelScope console, go to **Agent Identity → Identity Interconnection**
and choose **Create Application**. Fill in the IDA application name and homepage
/ service endpoint, submit, and save the returned `client_id` (for example
`hub_4abb08`). That `client_id` is the audience agents must request tokens for,
and the value your IDA must pass as `Verifier(audience=...)`.

The console may also offer a domain **Verify** action. That is optional for
token authentication; see the note below.

### B. Python helper or direct OpenAPI

Use this when scripting IDA registration. It needs a ModelScope AccessToken and
is equivalent to calling `POST /hub_apps` directly.

```python
from agent_id_client_sdk.providers.modelscope import ModelScopeProvider

provider = ModelScopeProvider("<modelscope-access-token>",
                              base_url="https://www.modelscope.cn/openapi/v1")
ida_app = provider.create_hub_app(app_name="MyIDA",
                                  app_homepage="https://ida.example.com")
print(ida_app.client_id)   # e.g. hub_4abb08  ← this is your audience
```

> ModelScope's optional `POST /hub_apps/endpoints/validate` probes for a
> `/.well-known/manifest`; since the IDA is passive it won't pass. Register via
> `POST /hub_apps` directly and skip that pre-check — the `client_id` is issued
> regardless.

> **Domain verification (the console "Verify" / `endpoints/validate`) is
> optional — not required for token auth.** The `/.well-known/manifest` it
> probes is for (a) the **verified IDA trust badge** (proving you own the
> Service Endpoint domain) and (b) **activity reporting** (the IDA's published
> signing key) — *not* for issuing or verifying tokens. Confirmed against
> pre-prod (2026-06-29): an IDA was created and its `client_id` used to issue +
> verify real tokens with `Verify` having failed. If your IDA is passive
> (no manifest), add one only if you later wire activity reporting or want the
> verified IDA status.

> ✅ **Pre-prod live (verified 2026-06-26).** `POST /hub_apps` answers with the
> ModelScope envelope (`InvalidAuthentication` without a token); supply
> `Authorization: Bearer <ModelScope AccessToken>` to register.

### Verified pre-prod endpoints (2026-06-26)

From `GET https://pre.modelscope.cn/openapi/v1/agent_id/.well-known/agentid-configuration`:

| Field | Value |
| --- | --- |
| `issuer` | `https://pre.modelscope.cn/openapi/v1` (host `pre.modelscope.cn` → `trusted_providers`) |
| `jwks_uri` | `https://pre.modelscope.cn/openapi/v1/agent_id/.well-known/agentid-jwks` (→ `jwks_urls`) |
| `token_endpoint` | `https://pre.modelscope.cn/openapi/v1/agent_id/token` |
| signing alg | `EdDSA` (advertised as a JSON **string**, not an array — non-standard, but irrelevant since we pin `jwks_urls` and bypass discovery) |
| JWKS kids | `idp-key-001`, `idp-key-002` (both `OKP`/`Ed25519`, `use=sig`) |

---

## New IDA onboarding checklist

For a fresh IDA, the minimal path to start serving ModelScope AgentID agents is:

1. Register the IDA in the ModelScope console (**Agent Identity → Identity
   Interconnection → Create Application**), or via `create_hub_app(...)` /
   direct `POST /hub_apps`; save the returned `client_id`.
2. Configure one `Verifier` with the matching ModelScope environment:
   `trusted_providers`, `audience=<client_id>`, `jwks_urls`, and
   `dpop_mode="disabled"`.
3. Wire the verifier into every protected route. Reject requests without
   `Authorization: Bearer <jwt>` and authorize business actions from
   `verified.agent_id`.
4. Confirm your agents already have ModelScope AgentID identities. Agent
   provisioning is covered by [`agentid-client-sdk.md`](./agentid-client-sdk.md).
5. Give agent operators the IDA API base URL, the IDA `client_id` audience, the
   ModelScope IdP base URL, and the required auth format:
   `Authorization: Bearer <jwt>`.
6. Keep environments consistent. For pre-prod, use `pre.modelscope.cn` and
   `https://pre.modelscope.cn/openapi/v1` everywhere. For prod, use
   `www.modelscope.cn` and `https://www.modelscope.cn/openapi/v1` everywhere.
   Mixing pre-prod and prod values will fail issuer, JWKS, or audience checks.

If you register through the Python helper or OpenAPI, the ModelScope AccessToken
is a setup-time management credential. Keep it out of agent runtime config and
do not ask agents to send it to your IDA.

---

## Verify a token

```python
from agent_id_service_sdk import Verifier

verifier = Verifier(
    trusted_providers=["www.modelscope.cn"],   # issuer host(s) to trust
    audience="hub_4abb08",                      # the registered IDA client_id
    # The verifier auto-discovers at https://{domain}/.well-known/agentid-configuration,
    # but ModelScope serves discovery under /openapi/v1/agent_id/... and the domain
    # root returns its web-app HTML (200) — so pin the JWKS URL directly:
    jwks_urls={
        "www.modelscope.cn":
            "https://www.modelscope.cn/openapi/v1/agent_id/.well-known/agentid-jwks",
    },
    # ModelScope tokens carry no cnf.jkt — never expect DPoP on this path.
    dpop_mode="disabled",
)

verified = await verifier.verify(authorization_header)  # "Bearer <jwt>"
print(verified.agent_id)     # sub: agent_id:modelscope:agent_xxx
print(verified.issuer)       # iss
print(verified.expires_at)   # exp (datetime)
```

`verify` raises on failure: `ProviderUntrustedError` (issuer not in
`trusted_providers`), `TokenExpiredError`, `SignatureInvalidError`,
`TokenInvalidError` (bad audience, malformed, etc.).

### What gets checked

1. **Issuer** — the JWT `iss` host is in `trusted_providers` (matched by domain).
2. **Signature** — verified against the IdP's JWKS (fetched from `jwks_urls`,
   cached `cache_ttl` seconds).
3. **Audience** — `aud` equals `audience` (the registered `client_id`).
4. **Expiry** — `exp` valid within `clock_skew_seconds`.

### Minimal claims

ModelScope JWTs are minimal. On the returned `VerifiedAgent`, **`agent_id`,
`issuer`, `expires_at`, `raw_jwt`, and `raw_claims` are populated**; the richer
fields (`principal`, `capabilities`, `scopes`, `delegation`, `model_info`,
`agent_token_version`) are empty/default on this path. Build authorization on
`agent_id` — don't depend on principal/scopes being present.

---

## Minimal FastAPI wiring

The verifier is transport-agnostic; in HTTP services, keep one verifier instance
and use it in an auth dependency:

```python
from fastapi import Depends, FastAPI, Header, HTTPException
from agent_id_service_sdk import AgentIDError, Verifier

app = FastAPI()

verifier = Verifier(
    trusted_providers=["www.modelscope.cn"],
    audience="hub_4abb08",
    jwks_urls={
        "www.modelscope.cn":
            "https://www.modelscope.cn/openapi/v1/agent_id/.well-known/agentid-jwks",
    },
    dpop_mode="disabled",
)


async def get_agent(authorization: str | None = Header(default=None)):
    if not authorization:
        raise HTTPException(401, "Authorization: Bearer <jwt> required")
    try:
        return await verifier.verify(authorization)
    except AgentIDError:
        raise HTTPException(401, "AgentID token verification failed")


@app.get("/agents/whoami")
async def whoami(agent=Depends(get_agent)):
    return {
        "agent_id": agent.agent_id,
        "issuer": agent.issuer,
        "expires_at": agent.expires_at.isoformat() if agent.expires_at else None,
    }


@app.post("/work")
async def do_work(payload: dict, agent=Depends(get_agent)):
    # Authorize from agent.agent_id. Do not trust a caller-supplied agent_id field.
    return {"accepted_for": agent.agent_id}
```

If your service is not FastAPI, the same rule applies: extract the full
`Authorization` header, call `await verifier.verify(header)`, reject failures
with 401, and use only the returned `VerifiedAgent` as the caller identity.

---

## Constructor reference (the fields that matter here)

| Param | Value for ModelScope |
| --- | --- |
| `trusted_providers` | `["www.modelscope.cn"]` (prod) / `["pre.modelscope.cn"]` |
| `audience` | the registered IDA `client_id`, e.g. `"hub_4abb08"` |
| `jwks_urls` | `{domain: ".../agent_id/.well-known/agentid-jwks"}` — pins JWKS, skips discovery |
| `dpop_mode` | `"disabled"` |
| `cache_ttl` | JWKS cache seconds (default 3600) |
| `clock_skew_seconds` | exp/iat tolerance (default 30) |
| `provider_urls` | discovery base override (local dev only) |

Activity-reporting params (`activity_endpoint`, `hub_signing_key`, …) are **not
used** on the ModelScope path — reporting is deferred.

---

## Status / gaps

- ✅ Verify path: issuer/audience/exp/signature, `jwks_urls` discovery bypass,
  `dpop_mode="disabled"`, minimal-claims handling.
- ✅ Pre-prod discovery + JWKS reachable; live IDA `client_id` issuance and token
  verification verified.
- ⏳ Activity reporting / approvals — deferred (ModelScope IdP exposes neither).
