# IDA Integration Guide

This guide shows how to make a service accept AgentID-authenticated requests.
The service role is an **Agent Identity Connected App (IDA)**: it receives
`Authorization: Bearer <jwt>` from agents, verifies the JWT against trusted
IdPs, and authorizes work from the verified agent identity.

Chinese version: [ida-integration.zh.md](./ida-integration.zh.md)

For the IDA-side SDK API, see [agentid-service-sdk.md](./agentid-service-sdk.md).
For the agent-side flow, see [agentid-client-sdk.md](./agentid-client-sdk.md).

The configuration examples use the live ModelScope IdP as a reference IdP
implementation. AgentID does not assume ModelScope is the only IdP; configure
your verifier for the IdP issuers you choose to trust.

## What You Build

An IDA integration has four runtime responsibilities:

1. Decide which IdP issuers you trust.
2. Configure the expected JWT audience for your IDA.
3. Verify every protected request before running business logic.
4. Authorize from the verified `agent_id`, not from caller-supplied fields.

With the live ModelScope IdP, the audience is the IDA application's registered
`client_id`, for example `hub_4abb08`. Other IdP implementations may define a
different audience convention; configure the verifier to match the issuer you
accept.

Activity reporting and approval workflows are outside this guide. They are not
required for Layer 0 identity and token verification.

## Prerequisites

- Python 3.10+.
- `agent-id-service-sdk` installed.
- An IDA audience value. For ModelScope, register the IDA in **Agent Identity →
  Identity Interconnection → Create Application** and save the returned
  `client_id`.
- A trust configuration for each IdP you accept: issuer host and JWKS URL.

```bash
pip install agent-id-service-sdk
```

## Configure the Verifier

Create one `Verifier` at application startup and reuse it for protected routes.
This example accepts tokens from the live ModelScope IdP:

```python
from agent_id_service_sdk import Verifier

verifier = Verifier(
    trusted_providers=["www.modelscope.cn"],
    audience="hub_4abb08",  # IDA application's registered client_id
    jwks_urls={
        "www.modelscope.cn":
            "https://www.modelscope.cn/openapi/v1/agent_id/.well-known/agentid-jwks",
    },
    dpop_mode="disabled",
)
```

Configuration notes:

- `trusted_providers` is the list of issuer hosts your IDA accepts.
- `audience` must match the `aud` claim in incoming JWTs.
- `jwks_urls` pins the issuer's public-key endpoint.
- `dpop_mode="disabled"` is the correct setting for the current ModelScope JWT
  path because those tokens do not carry `cnf.jkt`.

## Protect HTTP Routes

In HTTP services, pass the full `Authorization` header to `verify()`:

```python
from fastapi import Depends, FastAPI, Header, HTTPException
from agent_id_service_sdk import AgentIDError

app = FastAPI()


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
    # Authorize from the verified identity, not from payload["agent_id"].
    return {"accepted_for": agent.agent_id}
```

For WebSocket, gRPC, MCP, or other transports, extract the raw JWT and call
`verify_token(raw_jwt)`.

## What the Verifier Checks

`Verifier` rejects a token unless all required checks pass:

- The `iss` host is in `trusted_providers`.
- The JWT signature verifies against the issuer's JWKS.
- The `aud` claim equals the configured `audience`.
- The token is within its valid time window.

For the current ModelScope JWT path, expect minimal claims. Build authorization
around `agent.agent_id`, `agent.issuer`, and your own application policy. Do not
assume `principal`, `scopes`, or `delegation` are present unless the issuer you
trust documents and signs those claims.

## Give Agents the Right Values

Agent operators need the following values to call your IDA:

- Your API base URL.
- Your IDA audience value. For ModelScope, this is the registered `client_id`.
- The IdP base URL agents should request tokens from.
- The required request format: `Authorization: Bearer <jwt>`.

Example agent-side setup:

```python
from agent_id_client_sdk import Client, Identity

identity = Identity.from_profile("my-agent")
client = Client(identity, default_audience="hub_4abb08")

response = await client.post("https://ida.example.com/work", json={"task": "run"})
response.raise_for_status()
```

## Production Checklist

- Keep IdP issuer host, JWKS URL, and audience from the same environment.
- Never ask agents to send a ModelScope AccessToken to your IDA. AccessTokens are
  setup-time management credentials only.
- Reuse one verifier instance so JWKS caching works.
- Return `401` for authentication failures and `403` for authenticated agents
  that are not authorized for a business action.
- Log verification failures without logging full JWTs.
- Add tests for missing token, untrusted issuer, bad audience, expired token,
  and successful verification.
