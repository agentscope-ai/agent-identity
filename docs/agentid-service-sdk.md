# AgentID Service SDK (Hub side)

`agent-id-service-sdk` lets a **hub** (resource server — e.g. the DojoZero
gateway) verify the AgentID JWTs that agents present. It checks the signature
against the IdP's published keys, the issuer, the audience, and expiry, and
returns the caller's identity.

This is the hub-facing half. Agents obtain tokens with
[`agent-id-client-sdk`](./agentid-client-sdk.md).

> This guide tracks the ModelScope-aligned SDK. For the underlying protocol
> change list see [`modelscope-alignment.md`](./modelscope-alignment.md).

---

## Install

```bash
pip install agent-id-service-sdk
# or, from this monorepo:
uv pip install -e agent-id-service-sdk
```

Runtime deps: `httpx`, `pyjwt[crypto]`.

---

## Prerequisite: register the hub → get a `client_id`

ModelScope is the **central authority** for hub identity. The hub does **not**
self-advertise a `.well-known` manifest or JWKS. Instead you register the hub
once and ModelScope issues a `client_id`, which becomes the **`aud`** every
agent must target and the verifier must enforce.

```python
from agent_id_client_sdk.providers.modelscope import ModelScopeProvider

provider = ModelScopeProvider("<modelscope-access-token>",
                              base_url="https://www.modelscope.cn/openapi/v1")
hub = provider.create_hub_app(app_name="Dojo",
                              app_homepage="https://dojo.example.com")
print(hub.client_id)   # e.g. hub_4abb08  ← this is your audience
```

> ModelScope's optional `POST /hub_apps/endpoints/validate` probes for a
> `/.well-known/manifest`; since the hub is passive it won't pass. Register via
> `POST /hub_apps` directly and skip that pre-check — the `client_id` is issued
> regardless.

> **Domain verification (the console "Verify" / `endpoints/validate`) is
> optional — not required for token auth.** The `/.well-known/manifest` it
> probes is for (a) the **verified-hub trust badge** (proving you own the
> Service Endpoint domain) and (b) **activity reporting** (the hub's published
> signing key) — *not* for issuing or verifying tokens. Confirmed against
> pre-prod (2026-06-29): a hub was created and its `client_id` used to issue +
> verify real tokens with `Verify` having failed. Dojo's gateway is passive
> (no manifest); add one only if you later wire activity reporting or want the
> verified-hub status.

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

## Verify a token

```python
from agent_id_service_sdk import Verifier

verifier = Verifier(
    trusted_providers=["www.modelscope.cn"],   # issuer host(s) to trust
    audience="hub_4abb08",                      # the registered client_id
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

## Constructor reference (the fields that matter here)

| Param | Value for ModelScope |
| --- | --- |
| `trusted_providers` | `["www.modelscope.cn"]` (prod) / `["pre.modelscope.cn"]` |
| `audience` | the registered hub `client_id`, e.g. `"hub_4abb08"` |
| `jwks_urls` | `{domain: ".../agent_id/.well-known/agentid-jwks"}` — pins JWKS, skips discovery |
| `dpop_mode` | `"disabled"` |
| `cache_ttl` | JWKS cache seconds (default 3600) |
| `clock_skew_seconds` | exp/iat tolerance (default 30) |
| `provider_urls` | discovery base override (local dev only) |

Activity-reporting params (`activity_endpoint`, `hub_signing_key`, …) are **not
used** on the ModelScope path — reporting is deferred.

---

## Using it inside DojoZero (gateway)

The gateway builds the verifier from environment via
`dojozero.gateway._agentid.agentid_verifier_from_env()`:

| Env var | Meaning |
| --- | --- |
| `DOJOZERO_AGENTID_TRUSTED_PROVIDERS` | comma-separated issuer hosts, e.g. `pre.modelscope.cn` |
| `DOJOZERO_AGENTID_AUDIENCE` | the registered hub `client_id` (required) |
| `DOJOZERO_AGENTID_JWKS_URLS` | JSON `{domain: jwks_url}` to pin JWKS |
| `DOJOZERO_AGENTID_PROVIDER_URLS` | JSON `{domain: base_url}` discovery override |
| `DOJOZERO_AGENTID_CACHE_TTL_SECONDS` | default 3600 |
| `DOJOZERO_AGENTID_CLOCK_SKEW_SECONDS` | default 30 |

Both `TRUSTED_PROVIDERS` and `AUDIENCE` must be set or AgentID auth stays off
(the gateway logs and returns `None`). With a verifier configured, the gateway
**requires** a Bearer token and rejects the legacy `X-Agent-ID` header (closes
the impersonation gap). Install the optional dependency:
`pip install dojozero[agentid]`.

> ✅ **Validated live (2026-06-29):** hub `hub_748233` (registered via the
> console — *Identity Interconnection*) used as `DOJOZERO_AGENTID_AUDIENCE`; a
> real ModelScope token verified through the gateway register path **and** at the
> dashboard's `GET /api/agents/whoami` (deployment-level verification, no trial).

### Enabling AgentID on a deployment

The env above is **deployment-level, read once at startup**: the dashboard server
builds one `Verifier` (`agentid_verifier_from_env()`) and shares it across `GET
/api/agents/whoami` **and every trial gateway it launches**. So:

- **Opt-in / all-or-nothing** — unset → AgentID OFF (legacy GitHub / api-key auth
  unchanged); set → *every* trial under that server is AgentID-gated.
- **One audience per server** — `DOJOZERO_AGENTID_AUDIENCE` is a single hub
  `client_id`, so all trials verify against the same hub. Run a second server to
  host a different hub.
- **Restart to change** — the verifier is built at startup, not per request.

Minimal config (the three that matter; the rest default):

```bash
DOJOZERO_AGENTID_TRUSTED_PROVIDERS=pre.modelscope.cn          # prod: www.modelscope.cn
DOJOZERO_AGENTID_AUDIENCE=hub_748233                          # your hub client_id, NOT a URL
DOJOZERO_AGENTID_JWKS_URLS={"pre.modelscope.cn":"https://pre.modelscope.cn/openapi/v1/agent_id/.well-known/agentid-jwks"}
```

Where to set it depends on the deploy target: docker-compose loads the repo-root
`.env` (`DojoZeroDeploy/.env.example` documents the block); the Aone build takes it
from the platform's env injection (`APP-META/.../app/bin/setenv.sh` documents the
keys). Either way the image must ship the `[agentid]` extra (`agent-id-service-sdk`).

---

## Status / gaps

- ✅ Verify path: issuer/audience/exp/signature, `jwks_urls` discovery bypass,
  `dpop_mode="disabled"`, minimal-claims handling.
- ✅ DojoZero gateway wiring (`agentid_verifier_from_env`, Bearer-required) +
  dashboard-level `/api/agents/whoami` (verifies with no trial running).
- ✅ Pre-prod discovery + JWKS reachable; live `client_id` `hub_748233` verified.
- ⏳ Activity reporting / approvals — deferred (ModelScope IdP exposes neither).
