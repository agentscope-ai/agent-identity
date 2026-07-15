# AgentID Client SDK (Agent side)

`agent-id-client-sdk` lets an **agent** obtain a short-lived AgentID JWT from the
ModelScope Agent IdP and attach it to requests to an Agent Identity Connected
App (IDA), such as the DojoZero gateway. The agent holds an Ed25519 private
key; the IdP holds the matching public key it registered earlier and issues
JWTs in exchange for a signed request.

This is the agent-facing half. The IDA verifies these tokens with
[`agent-id-service-sdk`](./agentid-service-sdk.md).

> This guide tracks the ModelScope-aligned SDK. For the underlying protocol
> change list see [`modelscope-alignment.md`](./modelscope-alignment.md).

---

## Install

```bash
pip install agent-id-client-sdk
# or, from this monorepo:
uv pip install -e agent-id-client-sdk
```

Runtime deps: `httpx`, `cryptography`, `pyjwt`. Registration (the `providers/`
layer) also uses `httpx`.

---

## Concepts

| Object | Role |
| --- | --- |
| `Identity` | The agent's credential: `agent_id`, `kid`, Ed25519 private key, and `idp_url`. Signs token requests. Never makes management calls. |
| `Client` | Async HTTP client that turns an `Identity` into tokens and attaches `Authorization: Bearer <jwt>` to requests, with caching + 401-retry. |
| `providers/` | **Setup-time only.** Vendor control plane (register the agent, create an IDA app). Needs a ModelScope AccessToken. The runtime path never imports it. |

Two distinct phases — keep them separate:

1. **Provision (once, at setup):** generate a keypair, register the public key
   with ModelScope → get an `agent_id`. Requires a ModelScope AccessToken.
2. **Run (every request):** load the saved `Identity`, sign, get a JWT, call the
   IDA. No AccessToken involved — only the agent's private key.

---

## 1. Provision an identity (once)

The agent identity is created by registering an Ed25519 public key with
ModelScope. Two ways:

### A. ModelScope console (recommended for end users)

In the ModelScope console, go to **Agent Identity → Identity management** and
create an agent. The console shows an `openssl` command that generates `agent.pem`
(Ed25519) locally plus the public key as a JWK — run it, paste the JWK into the
console, and submit. You get back an `agent_id` (pre-prod format
`agent_id:modelscope:agent_xxx`) and your chosen `kid`. Keep `agent.pem` private;
it never leaves your host.

The matching **IDA** (the token audience) is registered separately under **Agent
Identity → Identity Interconnection** → "Create Application", which mints a
`client_id` (e.g. `hub_xxxxxx`). Domain verification there is optional.

### B. Programmatic, via the provider layer

Use this when scripting fleet provisioning. It needs a **ModelScope
AccessToken** (a high-privilege management credential — keep it off the agent
host).

```python
from agent_id_client_sdk.providers import provision_agent
from agent_id_client_sdk.providers.modelscope import ModelScopeProvider

provider = ModelScopeProvider(
    access_token="<modelscope-access-token>",
    base_url="https://www.modelscope.cn/openapi/v1",   # prod
)

# Generates an Ed25519 keypair, registers the PUBLIC key, and saves the
# profile to ~/.agentid/agents/my-agent/ (agent.json + private_key).
registered, private_key = provision_agent(provider, "my-agent")
print(registered.agent_id)   # agent_id:modelscope:agent_xxxx
```

Only the public JWK is uploaded; the private key stays local. `provision_agent`
saves `idp_url` (the OpenAPI base) into the profile so the runtime client knows
where to fetch tokens.

> ✅ **Pre-prod live (verified 2026-06-26).** Management/token plane on
> `https://pre.modelscope.cn/openapi/v1` is reachable — `POST /agent_id/token`
> answers with the ModelScope envelope and `POST /hub_apps` / `POST /agent_ids`
> require `Authorization: Bearer <ModelScope AccessToken>`. Prod base is
> `https://www.modelscope.cn/openapi/v1`.

---

## 2. Load the identity (every run)

```python
from agent_id_client_sdk import Identity

# From a saved profile dir (~/.agentid/agents/<name>/):
identity = Identity.from_profile("my-agent")

# Or from environment variables:
#   AGENTID_AGENT_ID, AGENTID_AGENT_KID,
#   AGENTID_AGENT_PRIVATE_KEY (hex 32-byte seed), AGENTID_IDP_URL
identity = Identity.from_env()

# Or from a zip bundle (agent.json + private_key, read in-memory):
identity = Identity.from_zip("my-agent.zip")
```

> **ModelScope `idp_url` must be explicit.** A `agent_id:modelscope:…` id carries
> no API host to derive from. The profile / `AGENTID_IDP_URL`
> must carry the real OpenAPI base (e.g. `https://www.modelscope.cn/openapi/v1`).
> `provision_agent` does this for you; if you build `Identity(...)` by hand, pass
> `idp_url=` yourself.

---

## 3. Get tokens and call the IDA

The **audience** is the IDA's registered ModelScope **`client_id`** (e.g.
`hub_4abb08`) — *not* an origin URL. Get this from whoever runs the IDA.

```python
from agent_id_client_sdk import Client

client = Client(identity, default_audience="hub_4abb08")  # dpop defaults off

# Raw token (cached; refreshed ~60s before expiry):
token = await client.get_token()

# Or let the client attach the header for you:
resp = await client.post(
    "https://ida.example.com/api/agents/register",
    json={"agent_id": identity.agent_id},
)
resp.raise_for_status()
```

`Client` caches per-audience tokens, refreshes ~60s before expiry, and on a
`401` invalidates the cache and retries once.

> **DPoP is off on the ModelScope path.** ModelScope tokens carry no `cnf.jkt`;
> construct `Client(identity, ...)` with the default `dpop=False`. (The `dpop=True`
> path and `sign_dpop_proof` remain for self-hosted IdPs that opt in — e.g.
> ref-idp with `REF_AGENT_IDP_DPOP_ENABLED=1`.)

---

## Token flow (what happens under the hood)

`Client.get_token(audience)`:

1. `timestamp = int(now)` (Unix epoch seconds; IdP allows ±60s skew).
2. Sign `"{agent_id}|{kid}|{audience}|{timestamp}"` with Ed25519 →
   **base64url, no padding** (`Identity.sign_token_request`).
3. `POST {idp_url}/agent_id/token` with
   `{agent_id, kid, audience, timestamp, signature}`.
4. Unwrap the ModelScope envelope
   `{success, request_id, data:{access_token, token_type, expires_in, jti}}`.
   `expires_in` is a **relative** TTL in seconds, anchored to the request time.

The issued JWT is minimal: `iss, sub (=agent_id), aud (=client_id), iat, exp,
jti`. No `principal`, `scopes`, `delegation`, or `cnf`.

---

## Configuration reference

| Env var | Used by | Meaning |
| --- | --- | --- |
| `AGENTID_AGENT_ID` | `Identity.from_env` | `agent_id:modelscope:agent_xxx` |
| `AGENTID_AGENT_KID` | `Identity.from_env` | Key id chosen at registration |
| `AGENTID_AGENT_PRIVATE_KEY` | `Identity.from_env` | Hex-encoded 32-byte Ed25519 seed |
| `AGENTID_IDP_URL` | `Identity.from_env` | OpenAPI base, e.g. `https://www.modelscope.cn/openapi/v1` |
| `AGENTID_HOME` | profile store | Profile root (default `~/.agentid`) |

---

## Using it inside DojoZero

The DojoZero client SDK (`dojozero-client`) wraps this transparently: its
`GatewayTransport` accepts an `agentid_client` + `agentid_audience` and attaches
the Bearer header on every gateway call. See the agent-side connect-to-Dojo
skill for the end-user flow.

The `dojozero-agent` CLI exposes it directly (opt-in; GitHub-PAT / API-key still
work):

```bash
dojozero-agent config --agentid-agent-id <agent_id> --agentid-kid <kid> \
  --agentid-key <agent.pem> --agentid-idp-url <idp_url> --agentid-audience <client_id>
```

then `dojozero-agent start <trial>` connects via AgentID.

---

## Status / gaps

- ✅ Runtime path (sign → `/agent_id/token` → Bearer attach), base64url sig,
  int timestamp, envelope unwrap, per-audience cache + 401-retry.
- ✅ Provider layer (`ModelScopeProvider`, `provision_agent`) for registration.
- ✅ Pre-prod base reachable (token endpoint live; verified 2026-06-26).
- ✅ Console registration UX (above) + full token→verify run against pre-prod —
  validated live 2026-06-29 (`agent_id:modelscope:agent_…`, audience `hub_748233`).
- ✅ DojoZero CLI exposure (`dojozero-agent config --agentid-*`).
- ✅ Live SDK provisioning (`provision_agent` / `create_hub_app`) — validated
  against pre-prod 2026-06-29 (registers + round-trips + self-cleans; covered by
  the skip-by-default `test_modelscope_live.py` integration test).
