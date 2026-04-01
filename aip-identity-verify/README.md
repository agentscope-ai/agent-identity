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

## Documentation

See the [Agent Identity Protocol](https://github.com/agentscope-ai/agent-identity) repository for full documentation.
