# agent-id-service-sdk

AgentID Service SDK — for Agent Identity Connected App (IDA) services and APIs to verify AgentID JWTs issued by the ModelScope Agent IdP (`modelscope.cn`).

## Installation

```bash
pip install agent-id-service-sdk
```

## Quick Start

```python
from agent_id_service_sdk import Verifier

verifier = Verifier(
    trusted_providers=["www.modelscope.cn"],
    audience="hub_4abb08",  # the IDA application's registered client_id
    jwks_urls={
        "www.modelscope.cn":
            "https://www.modelscope.cn/openapi/v1/agent_id/.well-known/agentid-jwks",
    },
    dpop_mode="disabled",
)

# HTTP (REST)
agent = await verifier.verify(request.headers["Authorization"])  # "Bearer <jwt>"

# WebSocket / gRPC / MCP — use verify_token() with the raw JWT
agent = await verifier.verify_token(raw_jwt_string)

print(f"Agent: {agent.agent_id}, Issuer: {agent.issuer}")
```

## Features

- **Transport-agnostic** — `verify()` for HTTP headers, `verify_token()` for raw JWTs (WebSocket, gRPC, MCP)
- **ModelScope aligned** — verifies minimal AgentID JWTs issued by the ModelScope IdP
- **Key rotation resilience** — Automatically refetches JWKS when an unknown `kid` is encountered
- **Clock skew tolerance** — Configurable leeway (default 30s) for JWT expiry checks
- **JWKS caching** — Caches provider public keys with configurable TTL (default 1 hour)

## Configuration

```python
verifier = Verifier(
    trusted_providers=["www.modelscope.cn"],
    audience="hub_4abb08",
    jwks_urls={
        "www.modelscope.cn":
            "https://www.modelscope.cn/openapi/v1/agent_id/.well-known/agentid-jwks",
    },
    dpop_mode="disabled",
    cache_ttl=3600,            # JWKS cache TTL in seconds (default: 1 hour)
    clock_skew_seconds=30,     # Clock skew tolerance (default: 30s)
)
```

## Documentation

See the [service SDK guide](https://github.com/agentscope-ai/agent-identity/blob/main/docs/agentid-service-sdk.md) or the [AgentID](https://github.com/agentscope-ai/agent-identity) repository for full documentation.
