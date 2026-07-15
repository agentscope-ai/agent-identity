# ModelScope AgentID — 之竹's deliverables (7.1)

Tracking the AgentID/ModelScope integration deliverables owned by 之竹
(张羿磊). Each item links its artifact and lists the gaps still blocked on
external inputs. **Fill the ⏳ gaps as they become available.**

> 其天's items (generic agent-side AgentID skill; IDA-side verify skill) are
> tracked separately and are **not** in this list.

| # | Item | Artifact | Status |
| - | --- | --- | --- |
| 1 | AgentID **Client SDK** doc (agent side) | [`agentid-client-sdk.md`](./agentid-client-sdk.md) | ✅ console + CLI flows filled; validated live |
| 2 | AgentID **Service SDK** doc (IDA 接入) | [`agentid-service-sdk.md`](./agentid-service-sdk.md) | ✅ IDA registration + verified endpoints |
| 3 | Agent-side **connect-to-Dojo Skill** (AgentID auth) | DojoZero `skills/dojozero-{player,predictor}/SKILL.md` → "Option C" | ✅ real `dojozero-agent config --agentid-*` flow (DojoZero #251) |
| 4 | **Product doc** | _TBD_ | ⏳ not started |

## Open gaps (the "fill in as available" list)

Most original gaps closed during the **2026-06-29 live E2E** against
pre.modelscope.cn (real agent `agent_id:modelscope:agent_…` + IDA audience `hub_748233`):

- ✅ **Live endpoints** (discovery / JWKS / `agent_id/token` / `hub_apps`,
  resolved 2026-06-26; issuer `https://pre.modelscope.cn/openapi/v1`).
- ✅ **IDA `client_id`** — registered via the console (Identity Interconnection);
  `hub_748233` used as the verifier audience end-to-end.
- ✅ **Agent registration console UX** — filled into Client SDK doc §1.A.
- ✅ **DojoZero CLI exposure** — `dojozero-agent config --agentid-*` shipped
  (DojoZero #251); `connect_trial` authenticated a real token through the gateway.
- ✅ **Live SDK provisioning** (`provision_agent` / `create_hub_app`) — validated
  against pre-prod 2026-06-29; covered by a skip-by-default integration test
  (`agent-id-client-sdk/tests/test_modelscope_live.py`).
- ⏳ **Product doc (item 4).** AgentID value story (passwordless agent identity,
  central IDA registry, short-lived tokens) with Dojo as the reference. Not started.

## Done / not blocked

- ✅ SDK runtime + provider/verifier code + ref-idp IDA enforcement (PRs:
  agent-identity #2, DojoZero #251).
- ✅ Client / Service SDK docs (this folder), with the live console + CLI flows.
- ✅ Skill "Option C" = the real `dojozero-agent config` flow.
- ✅ Dashboard-level verification (`GET /api/agents/whoami`) — agents authenticate
  with no trial running (DojoZero #251).
