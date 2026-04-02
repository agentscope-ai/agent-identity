# aip-identity-verify

Agent Identity Protocol verification library — for hubs and services to verify AI agent JWT tokens.

## Installation

```
pip install aip-identity-verify
```

## Quick Start

```python
from aip_identity_verify import AIPVerifier

verifier = AIPVerifier(
    trusted_providers=["copaw.ai"],
    audience="https://my-hub.example.com",
)

# In your request handler:
agent = await verifier.verify(request.headers["Authorization"])
print(f"Agent: {agent.agent_id}, Principal: {agent.principal}")
```

## Features

- **Multi-algorithm support** — Verifies JWTs signed with ES256 (ECDSA P-256) or EdDSA (Ed25519)
- **Key rotation resilience** — Automatically refetches JWKS when an unknown `kid` is encountered
- **Clock skew tolerance** — Configurable leeway (default 30s) for JWT expiry checks
- **JWKS caching** — Caches provider public keys with configurable TTL (default 1 hour)
- **Activity reporting** — Built-in `AIPActivityReporter` for sending activity logs back to the IdP

## Configuration

```python
verifier = AIPVerifier(
    trusted_providers=["copaw.ai", "other-idp.example.com"],
    audience="https://my-hub.example.com",
    cache_ttl=3600,            # JWKS cache TTL in seconds (default: 1 hour)
    clock_skew_seconds=30,     # Clock skew tolerance (default: 30s)
    provider_urls={            # Optional: override base URLs (e.g. for local dev)
        "localhost": "http://localhost:8000",
    },
)
```

## Documentation

See the [Agent Identity Protocol](https://github.com/agentscope-ai/agent-identity) repository for full documentation.
