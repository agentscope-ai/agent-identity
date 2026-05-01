# AgentID — deferred work after the 2026-05-01 rebrand

> **Status:** post-rebrand backlog. None of these are blockers; they're
> tracked here so future-us doesn't lose them.

## 1. Polyglot SDKs

**Today:** Python only — `agent-id-client-sdk`, `agent-id-service-sdk`,
`agent-id-cli`. Adequate for internal Alibaba consumers; weak as a
positioning artifact for "open standard for AI agents."

**Plan when adoption matters:**
- **TypeScript SDK first.** Largest agent-runtime ecosystem; biggest
  gap. Mirror the Python public surface: `Identity`, `Client`, `Verifier`.
  Build off the spec doc (no Python re-implementation).
- **Go second.** Server-side service operators tend to be Go-heavy.
  Same scope as service-sdk: JWT verification + activity reporting.
- Defer Rust/Java until concrete demand.

**What this requires from us:** the spec doc has to be precise enough
that a non-Python implementer can build from it. Test that by writing
the TS SDK from spec only, no peeking at Python source. Treat any
"figure it out from the Python" leakage as a spec gap.

## 2. Hub double-authentication simplification

**Today:** `aip-activity` ingest requires *two* secrets per request:
- `Authorization: Bearer <hub-key>` — per-hub static API key for tenant
  scoping.
- `X-AgentID-Token: <agent JWT>` — the agent's signed token, forwarded
  by the hub, for principal-policy extraction.

This works but has costs:
- Hubs maintain two secrets (their hub key + the agent's forwarded JWT).
- Hub keys are long-lived and out-of-band; rotating them is friction.
- Mental model is muddied: "is this request authenticated by the hub
  or the agent?"

**Alternative design (not yet decided):**

Drop the static hub key. Identify the hub from the JWT's `aud` claim:

- The hub installs `agent-id-service-sdk` and configures it with a
  declared `audience` value.
- The hub forwards the agent's JWT to `aip-activity` as before, but with
  no separate hub key.
- `aip-activity` verifies the JWT, reads `aud`, looks up that audience
  in its hub registry to determine tenant.

Pros: one secret instead of two; hub identity is derived from
already-signed material; nothing new to rotate.

Cons: any service that knows a hub's `aud` and intercepts an agent JWT
could submit events as that hub. Today the hub key prevents that
(intercepting the JWT alone doesn't grant write access). Trade-off is
real.

Mitigation if we go this route: require the hub to sign a "submission
attestation" with its own key (separate from the agent's), proving
posession and not just observation of the JWT. Adds complexity but
preserves the security property.

**Verdict for now:** keep the two-secret model. The simplification is
attractive but the security trade-off needs more thought. Revisit when
adding new hubs becomes operationally painful.

## 3. Internal symbols still using AIP

The brand rebrand swept user-facing surfaces. A few internal artifacts
still carry "AIP" in their names; left alone because they're not
externally visible:

- Database constraint defaults (postgres internal; renamed via alembic
  in this session).
- Test fixture identifiers like `aip:test.aip.example` — wait, these
  are gone now. Just verifying this list is real and not stale.
- The literal string `aip` appears in URL `agent-id.live` (which we
  *don't* want to change). And in the gitlab repo path `aip-idp` (held
  per Phase 8).
- Demo-hub local routes were `/aip/grants/*`; renamed to
  `/agentid/approvals/*` in this session.

If anything new shows up post-rebrand, log it here.

## 4. Spec doc additions worth doing in a focused PR

Deliberately *not* bundled with the rename to keep review surface
manageable:

- **`agentid_version` contract section.** What does the value mean?
  When does it bump? Compat policy. Today the value is `"1.0"` in spec
  examples but `"0.1"` in code. That mismatch alone is worth resolving.
- **"Approvals are binary by design" section.** Document that approve/
  deny + optional note is the entire surface; finer-grained per-approval
  parameter tuning belongs in delegation scope (§7.4), not at each
  approval. Closes a recurring "why no scoped approvals?" question.

## 5. Class name aliases removal

`agent-id-client-sdk` and `agent-id-service-sdk` v0.2.0 ship with
back-compat aliases:
```python
AIPIdentity = Identity
AIPClient = Client
AIPVerifier = Verifier
# ... etc.
```

These should disappear in v1.0. Track removal as a v1.0 todo.

## 6. ENV var legacy

The 2026-05-01 sweep renamed all `AIP_*` env vars to `AGENTID_*`.
There's no back-compat; `AIP_HOME` (etc.) no longer works. If any
deployment still has the old vars set, they'll be silently ignored.
Coordinate with internal users to update their config files when
deploying the post-rebrand build.

## 7. CLI command aliases

The CLI command is `agent-id` (was `aip`). No alias for the old name.
Internal users with shell scripts using `aip` need to update them.
Easy to add an alias if requested:
```toml
[project.scripts]
agent-id = "agent_id_cli.main:app"
aip = "agent_id_cli.main:app"  # legacy alias
```
