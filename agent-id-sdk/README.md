# agent-id-sdk

Agent Identity Protocol SDK — client library for AI agents to authenticate with identity providers and hubs.

## Installation

```
pip install agent-id-sdk
```

## Quick Start

```python
from agent_id_sdk import AIPIdentity, AIPClient

# Load agent identity from disk
identity = AIPIdentity.from_file("my-agent")
client = AIPClient(identity)

# Make authenticated requests
response = await client.get("https://hub.example.com/api/data")
```

## Documentation

See the [Agent Identity Protocol](https://github.com/copaw/agent-identity) repository for full documentation.
