# AgentID Rename — Cross-Repo Migration Plan

**Date**: 2026-04-30
**Status**: Draft — pending stakeholder sign-off on Phase 0
**Scope**: Three repos (`aip-idp`, `agent-identity`, `aip-activity`), three published PyPI packages, deployed preprod service, external wire format.

---

## 1. Goal

Move from "Agent Identity Protocol / AIP" to **AgentID** as the public brand. Reposition the spec from "competing protocol" to **"OIDC-aligned identity profile for AI agents"** — sidestepping the four-way naming collision (Mintlify "Open Agent Identity Protocol", Sunil Prakash's `draft-prakash-aip` + shipping ref impl, `draft-singla-agent-identity-protocol`, ours) and aligning with the standards center of gravity (OpenID AIIM, NIST NCCoE).

The rename touches three repos, three published PyPI packages, a deployed preprod service, and an external wire format. Goal is to migrate without breaking integrators and without shipping a half-renamed state.

## 2. External surface inventory (sticky things we have to manage)

| Layer | Current | Where |
|---|---|---|
| **PyPI packages (published)** | `aip-identity-sdk` v0.1.7, `aip-identity-verify` v0.1.5, `aip-identity-cli` v0.1.3 | `agent-identity/` |
| **JWT claim** | `aip_version` (in claims, discovery doc, events) | `aip-idp`, `agent-identity/ref-idp`, `agent-identity/examples/demo-hub`, `agent-identity/aip-identity-verify`, `aip-activity` |
| **HTTP headers** | `X-AIP-Token`, `X-AIP-Grant` | spec body, `aip-activity`, `agent-identity/examples/demo-hub` |
| **HTTP routes** | `/aip/auth/register`, `/aip/agents`, `/aip/token`, `/aip/activity`, `/aip/services`, `/aip/activity/{id}/summary` | `aip-idp`, `agent-identity/ref-idp`, `aip-activity` |
| **DB tables** | `aip_principal`, `aip_agent`, `aip_agent_key`, `aip_oauth_state`, `aip_approval`, `aip_activity_session` | `aip-idp`, `aip-activity` |
| **SLS topics** | `aip_activity`, `aip_activity_session` | `aip-activity` |
| **Spec doc title** | "Agent Identity Protocol (AIP)" | `agent-identity/design/` (canonical EN+ZH), `aip-idp/design/` (ZH duplicate) |

## 3. What's already aligned (no work needed)

- Domain: `agent-id.live` and `pre.agent-id.live`
- Top-level repo: `agent-identity`
- IdP deploy package name: `dail-agent-id` (internal Alibaba, never used "AIP")
- The PyPI brand `agent-id-*` is fully unclaimed (verified 2026-04-30: 404 on `agent-id`, `agent-id-client-sdk`, `agent-id-service-sdk`, `agent-id-verify`, `agent-id-cli`)

## 4. What does NOT change (out of scope)

- Domain names — they already match
- Database column data — table renames only, no schema/data changes
- HTTP request/response bodies — claim names are the only payload churn
- Reference IdP's user-facing flows — unchanged, just new labels
- The frontend portal's React structure — text replacements only

## 5. Phasing strategy

Sequenced by **reversibility cost** — cheap and reversible first, irreversible last. Every additive change ships before any removal; every removal waits behind a soak window.

**Pattern: introduce new surface alongside old → migrate clients across → remove old.**

## 6. Phase-by-phase plan

### Phase 0 — Decision lock & memory (1 day)

- Confirm with stakeholders: **AgentID** brand, `agent-id-*` PyPI form, "OIDC-aligned identity profile" positioning.
- Update memory files (`project_aip_naming_collision.md`, `project_agent_identity_landscape.md`) with the rename decision so future agent sessions have it.
- Cut migration tracking branch in each repo: `agentid-rename` in all three.

**Done when:** decision documented, branches exist.

---

### Phase 1 — Spec reframe, English-only (1–2 days)

Smallest possible diff that delivers the new framing. Three text changes only:

1. Title: `# Agent Identity Protocol (AIP)` → `# AgentID — An Identity Profile for AI Agents`
2. Scope line in header: rephrase to "OIDC-aligned identity profile…"
3. Principle #1: sharpen to "AgentID is a profile of OIDC, not a competing protocol."

**Files:** `agent-identity/design/2026-03-25-agent-identity-protocol.en.md`

**Done when:** PR open, framing reviewed, no body text touched yet.

---

### Phase 2 — Publish new PyPI packages (additive, no deprecation) (2–3 days)

Publish under the new names with same code, no warnings yet:

- `agent-id-client-sdk` v0.1.0 — copy of `aip-identity-sdk` v0.1.7 with import path `agent_id_client_sdk`
- `agent-id-service-sdk` v0.1.0 — copy of `aip-identity-verify` v0.1.5 with import path `agent_id_service_sdk`
- `agent-id-cli` v0.1.0 — copy of `aip-identity-cli` v0.1.3 with import path `agent_id_cli`

Note: `agent-id-service-sdk` (not `agent-id-verify` or `agent-id-hub`) because the package does both verification AND activity reporting, and "service" disambiguates from the IdP (where "hub" sounded like a singular central thing and "verify" hid the activity-reporting half). The `-sdk` suffix marks it as a developer library, not a running service.

Repo layout in `agent-identity`: keep old subdirs, add new ones (`agent-id-client-sdk/`, `agent-id-service-sdk/`, `agent-id-cli/`). Old packages keep building from their dirs, new packages from new dirs. This avoids forcing internal consumers to migrate immediately.

**Done when:** `pip install agent-id-client-sdk` works, both old and new published, internal CI uses new names, demo-agent and demo-hub still work on old names.

---

### Phase 3 — Spec body sweep + ZH translation (3–5 days)

After Phase 1 framing is approved:

- Mechanical replace in EN spec: `AIP` → `AgentID`, `AIP token` → `AgentID token`, `Agent Identity Protocol` → `AgentID`. Watch for false positives (`aip_*` claim names, `X-AIP-*` headers, `aip_*` table names — those rename in Phase 6 only).
- Translate updated EN to ZH; replace existing ZH file.
- Remove the duplicate ZH from `aip-idp/design/`; replace with a one-line README pointing at canonical location in `agent-identity/design/`.
- Sweep adjacent docs in `agent-identity/design/`: `2026-03-31-idp-implementation-guide.zh.md`, `2026-04-23-approval-scenarios.{en,zh}.md`, `2026-04-02-qwenpaw-integration.md`, `Commercialization.md`.
- Sweep all three READMEs and Makefiles for "AIP" mentions.
- File renames (last step of phase): `2026-03-25-agent-identity-protocol.en.md` → `2026-03-25-agentid.en.md` (use `git mv` so blame survives).

**Done when:** spec doc reads as AgentID throughout, ZH mirrored, duplicate removed, adjacent docs consistent.

---

### Phase 4 — Wire-protocol hard cutover (1 week)

**Decision (2026-04-30):** no external integrators rely on the legacy
`/aip/*` wire format; rollout of IdP and clients is co-deployed and
under our control. So Phase 4 is a hard cutover, not a dual-emit window.
Every emitter and receiver flips to the new names in one coordinated
deployment.

#### Wire-format rename mapping

| Surface | Old | New |
|---|---|---|
| JWT claim | `aip_version` | `agentid_version` |
| HTTP header | `X-AIP-Token` | `X-AgentID-Token` |
| HTTP header | `X-AIP-Grant` | `X-AgentID-Approval` |
| HTTP auth scheme | `Authorization: AIP <token>` | `Authorization: Bearer <token>` (OAuth 2.0 standard) |
| URL path | `/aip/auth/register` | `/agentid/auth/register` |
| URL path | `/aip/agents` | `/agentid/agents` |
| URL path | `/aip/token` | `/agentid/token` |
| URL path | `/aip/activity` | `/agentid/activity` |
| URL path | `/aip/services` | `/agentid/services` |
| URL path | `/aip/approvals` | `/agentid/approvals` |
| Discovery | `.well-known/aip-configuration` | `.well-known/agentid-configuration` |
| Discovery | `.well-known/aip-jwks` | `.well-known/agentid-jwks` |

#### Implementation pattern

- **JWT claim**: emit only `agentid_version`. Drop `aip_version`.
- **HTTP headers**: accept only `X-AgentID-*`. Drop `X-AIP-*`.
- **HTTP auth scheme**: accept only `Bearer`. Drop the custom `AIP` scheme.
- **HTTP routes**: mount only `/agentid/*`. Drop `/aip/*`.
- **Discovery**: serve only `.well-known/agentid-configuration` and
  `.well-known/agentid-jwks`. Drop the legacy paths.

#### Cliff for old PyPI users

Anyone pinned to `aip-identity-sdk@0.1.7` (or earlier) will hit 404s
when calling the upgraded IdP. The Phase 7 bridge release of the old
package re-exports from `agent-id-client-sdk` so `pip install aip-identity-sdk`
keeps working transparently — but pre-bridge versions are dead. Since
only a couple of internal projects use the old packages and we control
their deployment, this is acceptable.

**Files touched:** `aip-idp/app/core/aip_jwt.py` and route modules,
`aip-activity/app/auth.py` + routes, `agent-identity/agent-id-service-sdk`,
`agent-identity/ref-idp/ref_idp/{routes,crypto/jwt.py}`,
`agent-identity/examples/demo-hub`. Old `aip-identity-verify` is left
frozen — it becomes a bridge stub in Phase 7.

**Done when:** all clients and servers speak `/agentid/*` /
`X-AgentID-*` / `Bearer` / `agentid_version` exclusively, and nothing
emits or accepts the legacy names.

---

### Phase 5 — Switch internal callers to new package names (1 week)

With Phase 4 hard-cutover, emitter/receiver wire-format dual-emit is
moot. Phase 5 narrows to package-import migration:

- `demo-agent`, `demo-hub`, `ref-idp` updated to use `agent-id-client-sdk` /
  `agent-id-service-sdk` imports.
- `aip-activity` updates dep from `aip-identity-verify` to `agent-id-service-sdk`.
- Frontend portal: text-replace `AIP` → `AgentID` in user-visible strings.

**Done when:** all internal code imports the new package names; the old
`aip-identity-*` packages still build but no internal caller pulls them.

---

### Phase 6 — Internal renames (low external visibility, opportunistic) (3–5 days)

These don't affect external surface — internal cleanup only:

- DB tables: Alembic migration to rename `aip_principal` → `agentid_principal`, etc. Single migration per repo, on the rename branch. **Test rollback path explicitly before applying to preprod.**
- SLS topics: start writing to `agentid_activity` / `agentid_activity_session`. Keep old topic for read-only historical access; do not migrate historical data.
- Internal Python symbols: `aip_jwt.py` → `agentid_jwt.py`, `app/tests/aip/` → `app/tests/agentid/`, etc. Mechanical sed-style sweep, run tests after.
- `aip-idp` signing key file: `idp_signing_key.pem` (already neutral, no rename needed).

**Done when:** no `aip_*` symbols remain in active code paths (tests, models, routes, modules); old DB table names dropped after migration verified.

---

### Phase 7 — Bridge release of old PyPI packages (1 day)

Per the deprecation pattern:

- `aip-identity-sdk` v0.2.0 — `DeprecationWarning` at import + re-exports from `agent_id_client_sdk`, runtime dep on `agent-id-client-sdk`.
- Same for `aip-identity-verify` v0.2.0 → re-exports from `agent_id_service_sdk`, runtime dep on `agent-id-service-sdk`.
- Same for `aip-identity-cli` v0.2.0 → re-exports from `agent_id_cli`, runtime dep on `agent-id-cli`.
- README of each old package: lead with "**DEPRECATED — use agent-id-client-sdk/hub/cli**".

Bridge `__init__.py` template:

```python
import warnings
warnings.warn(
    "aip-identity-sdk is renamed to agent-id-client-sdk. "
    "Install agent-id-client-sdk; this package will stop receiving updates.",
    DeprecationWarning,
    stacklevel=2,
)
from agent_id_client_sdk import *  # noqa: F401,F403
```

**Done when:** old packages installable but warn loudly; new packages canonical.

---

### Phase 8 — Repo renames (cosmetic, end of migration) (1 day)

- `aip-idp` → `agent-id-idp` (verify with deploy team that internal `dail-agent-id` deploy name still load-bearing; if so, repo can stay)
- `aip-activity` → `agent-id-activity`
- `agent-identity` — no rename
- GitHub redirects work, CI configs updated, internal docs updated.

**Done when:** repo URLs match brand; CI green on new names.

---

### Phase 9 — Soak + final cleanup (T+3 months from Phase 7)

With Phase 4 having been a hard cutover, there's no dual-emit code to
strip. Phase 9 narrows to PyPI yank + final paint:

- Yank old PyPI versions (yank is reversible — pinned deps still resolve,
  unpinned `pip install` skips them).
- Final commits: clean repos, no `AIP` references except in changelog.

**Done when:** `grep -r "aip" --include='*.py'` returns only changelog /
history hits.

---

## 7. Risks and rollback

| Risk | Mitigation |
|---|---|
| External integrator pinned to `aip-identity-sdk` and missed deprecation | Bridge release re-exports work; warning printed; PyPI README screams. |
| Live preprod breaks during DB rename | Phase 6 runs in scheduled maintenance window; Alembic downgrade tested before upgrade. |
| Old PyPI users (pinned to aip-identity-* < bridge release) hit 404s | Accepted — only a couple of internal projects use these and we coordinate their rollout. Phase 7 bridge release covers everyone who upgrades. |
| Spec terminology drifts between EN and ZH | Phase 3 translates ZH only after EN is final; do not maintain in parallel. |
| Memory of "AIP" in old logs / SLS topics | Accept it. Historical data stays under old topic names; new data goes new topic. Don't migrate. |
| `agent-id-client-sdk` PyPI name squatted before we publish | Verified clear 2026-04-30; reserve immediately at start of Phase 2 (publish a v0.0.0 placeholder if needed). |

## 8. Definition of done (overall)

- All three repos build, test, deploy under new names.
- `pip install agent-id-client-sdk` and `agent-id-service-sdk` are the documented install path.
- Spec at `agent-identity/design/` reads as "AgentID — Identity Profile for AI Agents" throughout, EN and ZH consistent.
- `pre.agent-id.live` runs the renamed IdP without functional change to external behavior except added new endpoints/headers.
- Old PyPI packages yanked but historical installs still resolve.
- No `AIP` / `aip_*` references in active code outside changelogs.

## 9. Suggested calendar pacing

| Week | Phases |
|---|---|
| Week 1 | Phase 0–2 (decisions, spec reframe, new PyPI publishes) |
| Week 2–3 | Phase 3 (doc sweep + ZH) |
| Week 4 | Phase 4 (dual-emit) |
| Week 5 | Phase 5 (switch emitters/clients) |
| Week 6 | Phase 6 (internal renames) |
| Week 7 | Phase 7–8 (bridge releases, repo renames) |
| Month 4 | Phase 9 (soak cleanup) |

Total active work: ~6 weeks. Total wallclock through Phase 9: ~3 months.

## 10. References

- Memory: `project_aip_naming_collision.md` — four-way naming collision detail
- Memory: `project_agent_identity_landscape.md` — wider competitive landscape
- Memory: `project_auth0_genai.md` — Auth0/Okta competitive framing
- Memory: `reference_repos.md` — repo paths and key locations
