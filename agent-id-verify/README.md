# agent-id-verify

Agent Identity Protocol verification library — for hubs and services to verify AI agent JWT tokens.

## Installation

```
pip install agent-id-verify
```

## Quick Start

```python
from agent_id_verify import AIPVerifier

verifier = AIPVerifier(
    trusted_providers=["copaw.ai"],
    audience="https://my-hub.example.com",
)

# In your request handler:
agent = await verifier.verify(request.headers["Authorization"])
print(f"Agent: {agent.agent_id}, Principal: {agent.principal}")
```

## Documentation

See the [Agent Identity Protocol](https://github.com/copaw/agent-identity) repository for full documentation.
