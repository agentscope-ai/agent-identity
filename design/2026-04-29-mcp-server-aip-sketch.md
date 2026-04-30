# MCP Server + AIP — design sketch

Status: design sketch, not yet implemented. Captured here so the framing
isn't lost; a runnable example under `examples/mcp-server-aip/` can be
built from this when we're ready.

The question this answers: *"how does our AIP fit in front of an MCP
server?"* The four pieces an MCP operator actually has to think about:

1. token transport (where does the AIP JWT ride in?)
2. per-tool scope check (which capability gate covers which tool?)
3. sensitive-tool approval (when does the principal get pulled in?)
4. activity reporting (`tool.use` events to aip-activity)

The natural transport for a first cut is FastAPI + JSON-RPC framed the
way MCP's streamable HTTP transport does it. Swapping in the official
`mcp` Python SDK is a mechanical change — the AIP plumbing stays put;
see [Plugging into the real MCP SDK](#plugging-into-the-real-mcp-sdk).

---

## Three integration patterns

### A — Native library

The MCP server links `aip-identity-verify` directly. Verifier validates
the agent JWT on every request, reports `tool.use` after each call, and
triggers the approval flow for sensitive tools.

Best when: you control the MCP server and can ship a Python (or any
language with an AIP verifier) dependency.

### B — OAuth-aligned (MCP Authorization spec)

MCP's official authorization profile uses `WWW-Authenticate` to point the
client at an authorization server, then expects an OAuth bearer token on
every request. With AIP this means: the IdP doubles as the AS, the agent
token *is* the bearer, and the MCP server's resource-server check is
`AIPVerifier.verify`. Almost identical wire shape to Pattern A; the
difference is the discovery handshake.

Best when: you want to align with MCP's spec rather than inventing a
hub-specific transport.

### C — Sidecar proxy

For MCP servers you can't modify (vendor-supplied, legacy). Run an AIP
proxy in front: it terminates AIP, adds whatever native auth the upstream
expects, and forwards. This is the shape Mintlify's "AIP Proxy"
advocates and what Aembit's MCP Identity Gateway ships as a product.

Best when: the upstream is closed-source.

A first runnable example would target Pattern A. The token-handling,
scope-mapping, and reporting logic is the same code that would run
inside a Pattern C proxy — only the downstream call changes.

---

## Token transport

The agent puts the AIP JWT on the initial HTTP request that opens the
MCP session:

```
POST /mcp                              ← MCP streamable HTTP transport
Authorization: AIP <jwt>
Content-Type: application/json

{"jsonrpc":"2.0","id":1,"method":"initialize", ...}
```

The verifier validates the token once, caches the resolved `AIPAgent`
against the session id MCP returns in `Mcp-Session-Id`, and uses that
identity for every subsequent request on the session. Re-validation
happens on session reopen, not per call.

For SSE transport the same `Authorization` header rides on the SSE
`GET`. For stdio (local subprocess) MCP, AIP doesn't apply — the
trust boundary is the OS user, not the network.

Why `AIP` and not `Bearer`: `Bearer` collides with vanilla OAuth on the
same endpoint. The MCP spec leaves the auth scheme open; using a distinct
scheme name lets the same MCP server accept both vanilla OAuth and AIP
without ambiguity. If you're going Pattern B (the MCP authorization
profile), use `Bearer` and let the discovery doc disambiguate.

---

## Scope → tool mapping

AIP `capabilities` are the protocol-level grant. MCP `tools` are the
product-level handle. The MCP server owns the mapping:

```python
TOOL_SCOPES = {
    "search_docs":   {"read"},
    "create_issue":  {"write"},
    "delete_repo":   {"admin"},        # also triggers approval
}
```

On each `tools/call`, the server intersects `agent.capabilities` with
`TOOL_SCOPES[tool_name]`. Missing capability → JSON-RPC error
`-32001 access_denied` with a structured `data` field naming the
required scope (so the agent can request it).

Capabilities live as freeform strings in the JWT; a Pattern-A MCP server
adopts whichever vocabulary the issuing IdP uses (`read|write|admin`,
`mcp:fs.read|fs.write|fs.delete`, anything). The server, not the
protocol, decides the mapping.

---

## Sensitive-tool approval

Tools tagged `sensitive=True` short-circuit before execution: the server
calls the hub-local approval flow (or delegates to the IdP if the
discovery doc advertises `approval_endpoint`). The MCP response is
`-32002 approval_required` with the `approval_id` and `poll_url` —
mechanically the same shape as the demo-hub's 202 approval response,
adapted to JSON-RPC.

The agent polls the approval (out-of-band HTTP, not over MCP), gets a
grant, and retries the `tools/call` with `params._meta.aip_grant =
"<grant_id>"`. The MCP server validates the grant (binding,
single-use, expiry, action match) and proceeds.

A first cut would use local approvals only; delegation to the IdP
follows the same shape as `demo-hub` — see `examples/demo-hub/hub.py`.

---

## Activity reporting

Every `tools/call` emits a `tool.use` event after execution:

```python
await verifier.report_event(
    category="tool.use",
    agent=agent,
    session_id=mcp_session_id,
    outcome="success" if ok else "failure",
    payload={
        "tool_name": tool_name,
        "args_hash": sha256(json.dumps(args, sort_keys=True)),
        "duration_ms": elapsed_ms,
        "success": ok,
    },
)
```

Optionally also `session.start` / `session.end` bracketing the MCP
session so the aggregator produces clean session rows.

Privacy: tool arguments are *not* sent in the clear — `args_hash` is
sha256 over the canonicalized JSON. If there's legitimate need for
specific fields (model name, latency), put them in `payload` against
the Tier 1 schema. Free-form per-tool extras go in `ext` and get
dropped at `privacy_level ≤ summary` per the protocol.

If the MCP server has its own per-tool taxonomy worth tracking
cross-session, register a hub namespace (Tier 2):

```yaml
# aip-activity/app/schemas/hubs/mcp_demo.yaml
service_id: http://localhost:8002
namespace: mcp_demo
category_schemas:
  mcp_demo.long_tool_call:
    fields:
      tool_name: {type: string}
      latency_bucket: {type: string}
    required: [tool_name, latency_bucket]
```

Then emit `mcp_demo.long_tool_call` alongside the Tier 1 `tool.use`.

---

## What a runnable demo would look like

Once `server.py` exists under `examples/mcp-server-aip/`, the loop is:

```bash
# 1. Start the IdP (terminal 1)
cd ~/dev/aip-idp && make backend

# 2. Start aip-activity (terminal 2)
cd ~/dev/aip-activity && uvicorn app.main:app --port 8002

# 3. Start the MCP server (terminal 3)
cd ~/dev/agent-identity/examples/mcp-server-aip
ACTIVITY_API_KEY=local-dev-key uvicorn server:app --port 8003

# 4. Drive it (terminal 4)
TOKEN=$(aip agent token --name demo-agent --audience http://localhost:8003)
curl -X POST http://localhost:8003/mcp \
  -H "Authorization: AIP $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

curl -X POST http://localhost:8003/mcp \
  -H "Authorization: AIP $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"search_docs","arguments":{"query":"AIP"}}}'
```

The activity should appear under the agent on the portal's
`/portal/activity` page within a minute (aggregator idle window).

---

## Plugging into the real MCP SDK

Starting with FastAPI-on-JSON-RPC keeps the AIP integration legible
without a runtime dependency on `mcp`. To switch:

```python
from mcp.server import Server
from mcp.server.streamable_http import StreamableHTTPServerTransport

server = Server("mcp-aip-demo")

@server.call_tool()
async def call_tool(name: str, args: dict, ctx: Context):
    agent = await _get_session_agent(ctx)         # cached at initialize time
    _check_scope(agent, name)                     # unchanged
    if TOOLS[name].sensitive:
        await _trigger_approval(agent, name, args)
    result = await TOOLS[name].run(args)
    await verifier.report_event(...)              # unchanged
    return result
```

The verifier hooks land in the same three places (initialize, call_tool,
post-call). The transport layer is the only difference.

---

## Out of scope for this sketch

- Multi-session connection upgrades (SSE long-poll). Pattern A handles
  it the same way; a first cut can use single request/response for
  brevity.
- Tool-result redaction at `privacy_level=existence`. The hub already
  redacts `payload`/`ext`; redacting tool *output* to the agent is
  out of MCP scope and a separate policy decision.
- Pattern B's full discovery handshake. The MCP authorization spec is
  a moving target as of April 2026; defer until it stabilizes.
