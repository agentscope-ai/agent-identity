# agent-id-cli

AgentID CLI — manage AI agent identities from the command line.

## Installation

```
pip install agent-id-cli
```

## Quick Start

```bash
# Initialize with an identity provider
agent-id init --provider https://qwenpaw.ai

# Create an agent identity
agent-id agent create --name my-agent

# List agents
agent-id agent list

# Get a token for testing
agent-id agent token --name my-agent --audience https://service.example.com
```

## Documentation

See the [AgentID](https://github.com/agentscope-ai/agent-identity) repository for full documentation.
