# agent-id-client-sdk

AgentID Client SDK — agent-side library for AI agents to obtain AgentID JWTs
from protocol-compatible IdPs and interact with Agent Identity Connected App
(IDA) services. The package includes a ModelScope provider adapter for the live
ModelScope IdP.

Chinese version: [README.zh.md](README.zh.md)

## Installation

```bash
pip install agent-id-client-sdk
```

## Quick Start

```python
from agent_id_client_sdk import Client, Identity

# Load agent identity from a saved profile, env vars, or a zip bundle.
identity = Identity.from_profile("my-agent")

# The audience is the IDA application's registered client_id.
client = Client(identity, default_audience="hub_4abb08")

token = await client.get_token()
response = await client.get("https://ida.example.com/api/data")
response.raise_for_status()
```

## Documentation

See the client SDK guide:
[English](https://github.com/agentscope-ai/agent-identity/blob/main/docs/agentid-client-sdk.md) /
[Chinese](https://github.com/agentscope-ai/agent-identity/blob/main/docs/agentid-client-sdk.zh.md).

For broader context, see the [AgentID](https://github.com/agentscope-ai/agent-identity)
repository.
