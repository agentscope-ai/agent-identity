# ModelScope AgentID Quickstart

The minimal ModelScope-shaped loop — **provision → token → verify** — run fully
offline against a local `ref-idp` reference IdP. No network, no ModelScope
AccessToken, no IP allowlist. Swap `IDP_BASE` / `PROVIDER_HOST` /
`ACCESS_TOKEN` in [`quickstart.py`](quickstart.py) for the live ModelScope IdP
and the SDK calls are identical.

## Run

```bash
# from the repo root — install the two SDKs + the local mirror
pip install -e ref-idp/ agent-id-client-sdk/ agent-id-service-sdk/

# start the local reference IdP on :8000
( cd ref-idp && uvicorn ref_idp.main:app --port 8000 & )

# run the quickstart
python examples/modelscope-quickstart/quickstart.py
```

> Use a fresh DB. If you've run an older `ref-idp` before, an existing
> `ref_idp.db` may have a stale schema — delete it (or start `ref-idp` from a
> clean working dir) before launching.

Expected output:

```
1. register a hub app → client_id (the audience the agent mints for)
   client_id = hub_xxxxxx
2. provision an agent (keygen + register the public JWK)
   agent_id  = aip:localhost:agent_xxxxxxxxxxxx
   kid       = ...
3. agent mints a short-lived JWT for the hub audience
   token (390 chars): ...
4. hub verifies the JWT against the IdP's JWKS
   verified agent_id = aip:localhost:agent_xxxxxxxxxxxx

✓ provision → token → verify OK against local ref-idp.
```

## What it maps to

| Step | SDK call | ModelScope endpoint |
|------|----------|---------------------|
| register hub | `providers.modelscope.ModelScopeProvider.create_hub_app` | `POST /openapi/v1/hub_apps` → `client_id` (the audience) |
| provision agent | `providers.provision_agent` | `POST /openapi/v1/agent_ids` |
| mint token | `Client.get_token` (`agent-id-client-sdk`) | `POST /openapi/v1/agent_id/token` |
| verify token | `Verifier.verify` (`agent-id-service-sdk`) | JWKS at `…/agent_id/.well-known/agentid-jwks` |

> Against the local reference IdP the agent_id is `aip:localhost:…`; the live
> ModelScope IdP issues `agent_id:modelscope:…`. The SDK signs it verbatim, so
> the runtime path is identical. ref-idp's control plane accepts any non-empty
> bearer as the dev AccessToken; ModelScope needs your account AccessToken.
