# agent-id-client-sdk

AgentID Client SDK — agent-side library for AI agents to authenticate with identity providers and hubs.

## Installation

```
pip install agent-id-client-sdk
```

## Quick Start

```python
from agent_id_client_sdk import AIPIdentity, AIPClient

# Load agent identity from disk
identity = AIPIdentity.from_profile("my-agent")
client = AIPClient(identity)

# Make authenticated requests
response = await client.get("https://hub.example.com/api/data")
```

## Documentation

See the [AgentID](https://github.com/agentscope-ai/agent-identity) repository for full documentation.
