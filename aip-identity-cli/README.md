# aip-identity-cli

CLI tool for managing AI agent identities using the Agent Identity Protocol.

## Installation

```
pip install aip-identity-cli
```

## Quick Start

```bash
# Initialize with an identity provider
aip init --provider https://copaw.ai

# Create an agent identity
aip agent create --name my-agent

# List agents
aip agent list

# Get a token for testing
aip agent token --name my-agent --audience https://hub.example.com
```

## Documentation

See the [Agent Identity Protocol](https://github.com/agentscope-ai/agent-identity) repository for full documentation.
