# aip-identity-sdk

Agent Identity Protocol SDK — client library for AI agents to authenticate with identity providers and hubs.

## Installation

```
pip install aip-identity-sdk
```

## Quick Start

```python
from aip_identity_sdk import AIPIdentity, AIPClient

# Load agent identity from disk
identity = AIPIdentity.from_profile("my-agent")
client = AIPClient(identity)

# Make authenticated requests
response = await client.get("https://hub.example.com/api/data")
```

## Documentation

See the [Agent Identity Protocol](https://github.com/agentscope-ai/agent-identity) repository for full documentation.
