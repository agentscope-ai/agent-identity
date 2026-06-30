# agent-id-cli

> ⚠️ **Parked / not maintained.** This CLI targets the **legacy native IdP API**
> (`/agentid/*`) and does **not** work with ModelScope (the de-facto standard,
> `/openapi/v1/agent_id/*`) or the current `ref-idp` — it would 404. It is kept
> for reference only and will **not** receive new releases.
>
> A ModelScope-aware rewrite is planned: a thin CLI over `ModelScopeProvider` +
> `agent-id-client-sdk` (`agent create` / `hub create` / `token` / `verify`),
> provider-agnostic via `--idp-url` so it also drives `ref-idp` in CI.
>
> **For ModelScope provisioning today:** use the ModelScope console, or
> `agent_id_client_sdk.providers` (programmatic). See
> [`docs/agentid-client-sdk.md`](../docs/agentid-client-sdk.md).

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
