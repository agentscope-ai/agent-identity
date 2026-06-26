# ModelScope AgentID — 之竹's deliverables (7.1)

Tracking the AgentID/ModelScope integration deliverables owned by 之竹
(张羿磊). Each item links its artifact and lists the gaps still blocked on
external inputs. **Fill the ⏳ gaps as they become available.**

> 其天's items (generic agent-side AgentID skill; hub-side verify skill) are
> tracked separately and are **not** in this list.

| # | Item | Artifact | Status |
| - | --- | --- | --- |
| 1 | AgentID **Client SDK** doc (agent side) | [`agentid-client-sdk.md`](./agentid-client-sdk.md) | ✅ drafted, gaps pending |
| 2 | AgentID **Service SDK** doc (hub 接入) | [`agentid-service-sdk.md`](./agentid-service-sdk.md) | ✅ drafted, gaps pending |
| 3 | Agent-side **connect-to-Dojo Skill** (AgentID auth) | DojoZero `skills/dojozero-{player,predictor}/SKILL.md` → "Option C" | 🟡 preview section added; CLI wiring pending |
| 4 | **Product doc** | _TBD_ | ⏳ not started |

## Open gaps (the "fill in as available" list)

- ✅ **Live ModelScope endpoints (resolved 2026-06-26).** The 504 is gone —
  discovery, JWKS, `POST /agent_id/token`, and `POST /hub_apps` all answer with
  200 / proper envelopes on `https://pre.modelscope.cn/openapi/v1`. Confirmed:
  `issuer=https://pre.modelscope.cn/openapi/v1`,
  `jwks_uri=…/agent_id/.well-known/agentid-jwks`, JWKS kids `idp-key-001/002`.
  **Remaining:** a full provision→token→verify run against pre-prod (needs a
  ModelScope AccessToken to register an agent — currently validated only vs
  local ref-idp).
- **Hub `client_id`.** Register the Dojo gateway as a hub app
  (`POST /hub_apps` with an AccessToken) → real `client_id` (the verifier
  `audience`). The JWKS URL is now confirmed (above). Backfill `client_id` into
  the gateway env config.
- **Agent registration UX.** The self-service console flow for an agent to get
  its identity profile (`agent.json` + key) — fill into the Client SDK doc §1.A.
- **DojoZero CLI exposure.** `dojozero-agent config` does not yet expose an
  AgentID-identity option; the transport (`GatewayTransport`) already attaches
  the Bearer token. Once the CLI lands, complete Skill "Option C" and the Client
  SDK doc's "Using it inside DojoZero" section.
- **Product doc (item 4).** Audience/format TBD — likely the AgentID value story
  (passwordless agent identity, central hub registry, short-lived tokens) with
  Dojo as the reference integration. Start once items 1–3 stabilize.

## Done / not blocked

- ✅ SDK runtime + provider/verifier code (shipped in PRs: agent-identity #2,
  DojoZero #251).
- ✅ Client SDK and Service SDK usage docs (this folder).
- ✅ Skill "Option C" preview sections.
