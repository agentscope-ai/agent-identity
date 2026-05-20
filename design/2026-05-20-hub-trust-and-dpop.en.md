# Hub Trust Tiers + DPoP — Sender-Constrained Tokens

**Date**: 2026-05-20
**Status**: Draft — Phase A landed in code; design doc captures the wider proposal, B in flight, C deferred.
**Scope**: Refines `2026-03-25-agentid.en.md` §3 (architecture), §6 (token issuance), §7.4 (approval triggers), §7.6 (approval workflow). Extends `2026-05-04-activity-discovery.en.md` §5 (hub envelope auth) to hub → IdP traffic. Companion to those docs; doesn't supersede.

---

## 1. Why now

Two structural gaps surfaced as the first adopters wired up:

**Gap 1 — Hub identity at the IdP boundary is unattested.** `/agentid/approvals` accepts `hub_id` as a free-form body field; anyone with the network path to the IdP can POST a fake approval prompt into a principal's portal claiming to be from `https://api.dojozer0.live` (zero-character typo). The principal's portal can't tell real from fake. The IdP has cryptographic primitives for verifying hubs already (§5.0 HubJWS in `aip-activity`), but they're scoped to the activity ingest path — every other hub → IdP endpoint is on the bearer-token rails, which here means *no rails at all*.

**Gap 2 — Agent JWTs are bearer tokens.** Whoever holds a valid JWT can use it. JWTs travel widely (HTTP headers, logs, telemetry, stack traces, distributed traces, IPC) and leak through any of those surfaces. Today a leak == full identity compromise for the TTL window, scoped only to the audience the JWT was issued for. RFC 9449 (DPoP) defines a structural fix used by FAPI 2.0 and the post-2020 OAuth ecosystem; AgentID needs the same.

**Gap 3 — The approval workflow leans on hub policy with no way for the IdP or principal to participate.** §7.4 of the main spec gestures at `requires_confirmation_above` as a delegation-claim field but no one populates it. Hubs hardcode `REQUIRES_APPROVAL_ABOVE = 500.0` constants. Principals get no say; IdP operators get no say. The wiring exists in the JWT but is dead code.

This doc resolves all three under one design: hubs become *trust-listed* by the IdPs that issue tokens for them, hub manifests publish a small approval policy DSL the IdP composes into JWT claims, and JWTs gain a `cnf.jkt` binding so leaked tokens can't be replayed.

## 2. Unifying insight

Same pattern as `2026-05-04-activity-discovery.en.md`: a cryptographic primitive plus a curated human-trust layer on top. Three artifacts that the rest of the doc fleshes out:

| Primitive | Curated layer |
|---|---|
| Hub publishes a JWS-signed manifest (§3 — already shipped for activity); IdP fetches, verifies, caches | IdP operator decides which hubs to elevate from `self_onboarded` to `verified`, or block (§3) |
| Hub manifest declares `approval_policy` in a small DSL (§4) | IdP composes it with principal preferences into the JWT `delegation` claim (§4) |
| JWT carries `cnf.jkt` thumbprint of the agent's pubkey (§5); per-request DPoP proof binds to that thumbprint | None — purely cryptographic, no human-curation layer needed |

Both #1 and #2 reuse the existing manifest plumbing — no new well-known endpoints, no new fetch infrastructure. #3 is a small additive change to JWT issuance and a new SDK module on the resource-server side.

## 3. Hub trust tiers

### 3.1 Three states

The IdP maintains a per-IdP trust list (table `agentid_trusted_hub`). Each row has a `status`:

| Status | How it got there | What it gates |
|---|---|---|
| `verified` | Operator-curated. Manual promotion via portal; future: `attested_by` chain verification | Token issuance proceeds; portal shows ✓ badge; high-security deployments can require this tier |
| `self_onboarded` | Auto-discovered on first sight (e.g., first `POST /agentid/token` with audience `https://X`). Manifest fetched + JWS verified, namespace ownership checked. **Not** human-reviewed | Token issuance proceeds; portal shows plain entry, surfaces "not yet reviewed" to principals |
| `blocked` | Operator action. Known bad actors, abuse incidents, compliance demands | Token issuance refused (403); approval submission refused (403); portal surfaces "blocked" |

`blocked` ↔ `self_onboarded` transitions and `self_onboarded` → `verified` transitions are operator-driven; auto-discovery never *demotes* a hub. (See §3.4 transition matrix.)

### 3.2 Why per-IdP, not central

Each IdP keeps its own list. Browsers ship per-vendor CA trust stores; we ship per-IdP hub trust lists. Same property: no global registry, no single chokepoint, no veto.

Implications:
- An agent at IdP-A and an agent at IdP-B can have *different* reachable hub sets. Adopters should expect this. (Same as Firefox vs Chrome having different CA stores.)
- Federation belongs at the `attested_by` layer (§3.5), not at a shared trust list.

### 3.3 Self-onboarding flow

```
agent → POST /agentid/token { audience: https://api.newhub.live, ... }
    ↓
IdP checks agentid_trusted_hub.hub_origin = audience
    ↓
unknown + AGENTID_AUTO_DISCOVER_HUBS=true (or dev mode):
    ↓
IdP fetches https://api.newhub.live/.well-known/agent-id-activity-manifest
    ↓
verifies JWS sig against keys at manifest.jwks_url
verifies manifest.service_id == audience
verifies namespace ownership (eTLD+1 rule from activity-discovery §6)
    ↓
INSERT (hub_origin, status='self_onboarded', approval_policy, ...) → trust list
    ↓
proceed to compose delegation claim + issue JWT
```

Auto-discovery is **off by default in prod** (operators opt in via `AGENTID_AUTO_DISCOVER_HUBS=true`) and **on in dev mode** for ergonomic local demos.

SSRF guard rails (mandatory):
- `https://` only outside dev mode.
- Reject IP literals (no `169.254.169.254`, no `[::1]`, etc.). Hostnames only.
- Reject paths — `service_id` MUST be an origin (`scheme://host[:port]`).
- Response size cap on the manifest fetch (default 64KB).
- Network timeout (default 5s).

### 3.4 Transitions

| From → To | Trigger | Notes |
|---|---|---|
| (none) → `self_onboarded` | Auto-discovery succeeds on first sight, or explicit `POST /agentid/hubs/discover` (Phase C) | Idempotent — refresh just updates the cached manifest fields |
| `self_onboarded` → `verified` | Operator action via portal (Phase B-late / C) | Sets `verified_at`, optionally records `attester_principal_id` |
| `*` → `blocked` | Operator action | Records `notes` for audit |
| `blocked` → `self_onboarded` | Operator action (unblock) | Doesn't restore `verified` — the operator has to deliberately re-promote |
| `verified` → `self_onboarded` | Not auto. Manual operator action only | Refresh cycles MUST NOT silently demote — would create attack via brief outage |

### 3.5 Federation via `attested_by` (deferred)

Each hub manifest can declare `attested_by: "agentid:<idp>:org_xxx"` — an org-principal that vouches for the hub. In v1 this is **informational only**. v2 (deferred until a second IdP adopts) will let IdPs trust hubs whose `attested_by` chains to an org-principal registered at a *trusted attester IdP* — federation without bilateral hub registration.

Until then, every IdP maintains its own `verified` set. That's fine for the current adopter set (Dail-IdP only).

### 3.6 Trust-list API for downstream services

The hub trust list is **operator-curated state** that other services in the AgentID stack need access to — specifically `aip-activity`, which must refuse event ingest from hubs the IdP doesn't recognise (otherwise random domains publishing manifests can pollute the activity / reputation graph).

The IdP exposes the trust list on a public, no-auth endpoint:

```
GET /agentid/hubs/public
   → 200 {
       "trusted_origins": [
         "https://api.dojozero.live",
         "https://acme-trading.example.com"
       ],
       "served_at": "2026-05-20T10:00:00Z"
     }
```

Returns the union of `verified` + `self_onboarded` rows; `blocked` rows are excluded. Only the origin is returned — no status tier, no notes, no attester chain — so the endpoint is safe to leave unauthenticated (hub origins are public information anyway; they appear as JWT `aud` claims on every request).

Downstream services (in v0.5: `aip-activity`) poll this endpoint and cache the result. The polling pattern, not a shared database, is the deliberate choice:

- **Schema/deployment decoupling.** Migrations and releases on the IdP side don't gate the activity service. A shared-DB design couples both lifecycles.
- **Failure-mode independence.** IdP outages don't take down activity ingest; the activity service serves stale-but-valid cache during incidents.
- **Federation-ready.** When v2 supports multiple trust sources, `aip-activity` just polls multiple URLs. No schema gymnastics.

Polling consumer obligations (`aip-activity` reference implementation):

- Refresh every 5 minutes; cache TTL 10 minutes (2× refresh interval).
- Configured via `AGENTID_IDP_TRUST_LIST_URL`. **Unset** = enforcement disabled (back-compat for deployments not running the IdP-side trust feature).
- After HubJWS verifies, before any further processing: refuse 403 if `envelope.iss` is not in the cached set.
- Fail-closed when cache is empty AND enforcement is enabled (cold-start protection); fail-open behaviour is **not** offered — operators opt in to enforcement deliberately.

Operator UX is unchanged: promotions / blocks happen in the IdP portal; the activity service follows within one refresh cycle.

## 4. Hub manifest extensions

### 4.1 New optional fields

Existing manifest fields (`service_id`, `namespace`, `categories_url`, `jwks_url`, `attested_by`, `aip_version`) are unchanged. Phase A adds four optional fields to the same manifest:

```json
{
  "service_id":     "https://api.dojozero.live",
  "namespace":      "dojozero",
  "categories_url": "https://api.dojozero.live/.well-known/agent-id-activity-categories",
  "jwks_url":       "https://api.dojozero.live/.well-known/agent-id-jwks",
  "aip_version":    "0.1",
  "attested_by":    "agentid:dail-idp.live:org_dojozero_a1b2",

  "display_name":               "DojoZero",                       // NEW (§4.1)
  "dpop_supported":             true,                              // NEW (§5)
  "approval_modes_supported":   ["local", "delegated"],            // NEW (§4.2)
  "approval_mode_default":      "delegated",                       // NEW (§4.2)
  "approval_policy": { ... }                                       // NEW (§4.3)
}
```

All five fields are optional. A manifest without any of them is still valid — the IdP defaults are conservative (no policy gating, no DPoP advertised).

### 4.2 Approval modes (§7.6 routing)

Hubs declare which `approval_routing.mode` values they implement:

- `"local"` — the hub owns the approval state and surfaces approvals via its own portal (Model 1 in §7.6.1-6).
- `"delegated"` — the hub forwards the decision step to the IdP's portal (Model 3 in §7.6.7).
- Both — the hub supports either, IdP picks per principal preference.

`approval_mode_default` carries the hub's preferred mode when the principal has no explicit preference (Phase C). For Phase B it's informational; the existing discovery-doc fallback (IdP advertising `approval_endpoint` → delegated; absent → local) still applies until per-principal preferences land.

### 4.3 Approval policy DSL v1

The DSL is deliberately small. Three top-level keys, all optional:

```json
{
  "always_require": [
    "data.delete",
    "transfer.value:counterparty_unknown"
  ],
  "thresholds": {
    "transfer.value": { "amount_usd": 500, "currency": "USD" },
    "trade":          { "amount_usd": 500 }
  },
  "never_require": []
}
```

**Semantics:**

- `always_require`: list of action names. Match is exact-string. Listed actions ALWAYS require approval, regardless of params. Hub-only field — the IdP refuses to compose principal-published `always_require` extra entries (out of scope for v1; principals add to `never_require` instead).
- `thresholds`: per-action numeric checks. For each action, each *numeric* sub-key is a threshold; if the corresponding param exceeds it, approval is required. Non-numeric sub-keys (`currency`, `region`) are context metadata in v1 — they scope the threshold's applicability but don't enforce on their own. v2 may add per-constraint operators.
- `never_require`: principal-only field (hubs declaring this get a logged warning and the field is dropped). Lists actions the principal opts out of approving. Defeated by any source's `always_require` — hub-mandated approvals are non-negotiable.

**Composition rule (most restrictive wins):**

```
always_require  = union(hub_policy.always_require, principal_prefs.always_require)
thresholds      = per-action per-key min over all numeric values from all sources
never_require   = principal_prefs.never_require, minus anything in the merged always_require
```

The composed object becomes the JWT's `delegation` claim. The hub-side SDK helper `evaluate_approval_needed(action, params, delegation)` does the symmetric runtime check.

**Extension surface.** Unknown top-level keys in the manifest's `approval_policy` are preserved through composition into the delegation claim. Hubs that want to advertise hub-flavored extensions (`dojozero_max_concurrent_bets`, `acme_region_lock`) can do so without IdP code changes. Consumer hubs read their own extensions from the claim at runtime.

### 4.4 Manifest signing

Manifest signing is unchanged from `2026-05-04-activity-discovery.en.md` §3.1. The new fields ride inside the same JWS payload. Ed25519 / ES256 only.

## 5. HubJWS on every hub → IdP endpoint

§5.0 of `activity-discovery` specified HubJWS for `POST /agentid/activity`. Phase A extends that scheme to hub → IdP traffic — specifically `POST /agentid/approvals` and `GET /agentid/approvals/{id}`.

### 5.1 Required for

| Endpoint | Reason |
|---|---|
| `POST /agentid/approvals` (submit) | Phishing prevention — must prove the caller really is the hub claimed in `body.hub_id` |
| `GET /agentid/approvals/{id}` (poll) | Decision-JWT harvesting prevention — must prove the caller really is the hub that submitted |
| `POST /agentid/hubs/discover` (Phase C) | Self-registration must be authenticated to prevent registry pollution |

Existing JWT-bearer endpoints (`POST /agentid/token`, IdP discovery doc, JWKS) are *agent-facing*, not hub-facing, and stay on their existing rails.

### 5.2 Verifier obligations (mirrors §5.0)

Identical to the activity-side `authenticate_hub_envelope`:

1. Parse `Authorization: HubJWS <jws>`.
2. Extract `iss` from claims; resolve hub manifest + JWKS via `HubManifestFetcher`.
3. Verify JWS signature, `body_sha256`, `aud == <IdP origin>`, `iat` within skew, `jti` not in replay cache.
4. On success, `iss` is the authenticated hub. Endpoints additionally require body fields like `hub_id` to match `iss`.
5. Endpoints additionally check the hub's trust-tier status — `blocked` rejects.

The IdP reuses `HubManifestFetcher` and `verify_envelope` from `agent-id-service-sdk` — same implementation as `aip-activity`. The SDK's name predates this expansion of consumers; v1.0 spec rev may rename to `agent-id-protocol-sdk`.

## 6. DPoP — sender-constrained tokens

### 6.1 Profile

AgentID's DPoP profile is RFC 9449, with the algorithm set narrowed to match the rest of the protocol:

- `alg`: `EdDSA` (Ed25519) **MUST** be supported. `ES256` (ECDSA P-256) MAY be supported. Other algorithms forbidden.
- DPoP key: the agent's existing IdP-registered key (the one used to sign `POST /agentid/token` requests). No separate ephemeral key in v1. (v2 may add ephemeral DPoP keys with the registered key as a "root" for blast-radius separation — see §9 open questions.)
- `cnf.jkt`: RFC 7638 SHA-256 thumbprint of the canonical Ed25519 JWK form of the agent's public key. Issued on every `POST /agentid/token` response when the agent's key is hexadecimally well-formed; absent only when the stored key is malformed (defensive — shouldn't happen past registration).

### 6.2 Three operating modes (resource-server side)

The hub-side Verifier ships a `dpop_mode` parameter:

| Mode | Accepts `Bearer` | Accepts `DPoP` | Behavior |
|---|---|---|---|
| `"disabled"` (default) | yes | rejected | Legacy bearer-only. Back-compat for hubs that haven't migrated |
| `"optional"` | yes | yes (verified when present) | Phase A-B default for participating hubs |
| `"required"` | rejected | yes (mandatory) | Phase C. Token MUST carry `cnf.jkt`; request MUST present `DPoP` header |

The phasing is deliberate: Phase A adds the IdP-side `cnf.jkt` claim and the SDK-side primitives; Phase B turns on hub `dpop_mode="optional"` so adopters can opt in incrementally; Phase C flips the default to `required` once adopters confirm.

### 6.3 Verifier checks (RFC 9449 §4.3 mapped)

For each DPoP-scheme request:

1. Standard JWT validation (signature, `aud`, `exp`, `iss` in `trusted_providers`).
2. Token has `cnf.jkt`. If missing while `dpop_mode="required"`: reject.
3. `DPoP` header is a JWS with `typ: "dpop+jwt"` and an `alg` in the accepted set.
4. JWS header's `jwk` carries only public components (no `d`, no private members).
5. SHA-256 thumbprint of that `jwk` equals `cnf.jkt`. **This is the load-bearing check** — defeats stolen-token replay.
6. JWS signature verifies against the embedded `jwk`.
7. `htm` (case-insensitive) matches actual request method.
8. `htu` (with query/fragment stripped, scheme+host lowercased) matches actual request URL.
9. `iat` within skew window (default ±60s).
10. `ath` claim (when present) equals `base64url(sha256(access_token))`.
11. `jti` not in replay cache; insert with TTL (default 120s).

### 6.4 Why DPoP, not mTLS

We considered RFC 8705 (mTLS-bound tokens). DPoP wins for AgentID specifically:

- AgentID already has the key infrastructure DPoP needs (Ed25519 keypairs registered at IdPs via `aip agent create`). mTLS would require building a parallel PKI — CA, cert issuance, rotation, CRL/OCSP.
- AgentID adopters are diverse (cloud SaaS, on-prem, embedded). mTLS cert provisioning at scale is operationally heavy. DPoP is "one HTTP header per request."
- DPoP is the choice the post-2020 OAuth ecosystem made for the same reasons (FAPI 2.0 lists both as acceptable; new deployments overwhelmingly pick DPoP).

We may revisit mTLS-bound tokens if a regulated adopter (banking, healthcare) explicitly requires TLS-layer binding. The current SDK abstractions don't preclude it.

### 6.5 What DPoP does NOT fix

Worth naming so the threat model stays honest:

- **Private-key compromise.** If the agent's long-lived registered key is stolen (filesystem access, KMS bypass), the attacker has full identity — DPoP doesn't help. Mitigations live one layer up: HSM/KMS-backed signing, key rotation, anomaly detection. See `2026-05-XX-key-compromise-recovery.md` (deferred).
- **TLS-layer adversaries.** A peer that has broken TLS can still observe + tamper with traffic. DPoP defends against *token leak*, not active MITM. HTTPS remains required.
- **Hub-side compromise.** DPoP proves the request came from the holder of the agent's key, not from a specific user agent or device. A compromised hub still sees plaintext.

## 7. JWT claim shape (Phase A + B combined)

The composed agent JWT carries the following claims (additions to the pre-v0.5 set marked NEW):

```json
{
  "iss":     "https://idp.dail.agent-id.live",
  "sub":     "agentid:dail-idp.live:agent_abc123",
  "aud":     "https://api.dojozero.live",
  "iat":     1747750000,
  "exp":     1747753600,
  "agentid_version": "0.1",
  "agent_name":      "trader-bot-3",
  "principal":       { "type": "human", "id": "...", "name": "Alice" },
  "capabilities":    [...],
  "scopes":          {...},
  "privacy":         { "level": "summary", "category_policy": {...} },

  "cnf":             { "jkt": "<RFC 7638 thumbprint>" },          // NEW (§6)
  "delegation":      {                                              // NEW (§4)
    "always_require": ["file.delete"],
    "thresholds": { "transfer.value": {"amount_usd": 500} }
  }
}
```

Old clients ignore unknown claims; new clients use them. JWT itself is JWS-signed by the IdP as before.

## 8. Migration path

### 8.1 Phase A — Backward-compatible additions (done, May 2026)

- Trust-tier table + CRUD landed in `aip-idp` (`alembic j5e6f7a8b9c0`).
- `cnf.jkt` added to every issued JWT.
- DPoP module + Verifier integration in `agent-id-service-sdk` (`dpop_mode="optional"` default).
- DPoP per-request signing in `agent-id-client-sdk` (default off; opt-in via `Client(identity, dpop=True)`).
- HubJWS auth required on `POST` and `GET /agentid/approvals`. Phishing hole closed.
- Hub auto-discovery module (gated; not yet hooked into token endpoint).
- Demo hub publishes JWKS + JWS-signed manifest with `approval_policy`, signs HubJWS on IdP calls.

**Nothing breaks for existing adopters.** Old bearer-only flows continue working.

### 8.2 Phase B — Wire it up (in progress)

- Approval-policy composer in `aip-idp/app/core/approval_policy.py`.
- `/agentid/token` looks up audience hub, runs auto-discovery if enabled, composes `delegation` claim, refuses blocked hubs.
- `evaluate_approval_needed` helper + `merge_hub_floor` in service SDK.
- Demo hub reads `delegation` claim instead of hardcoded threshold; manifest's `approval_policy` matches the in-process floor (single source of truth).
- v0.5 design doc published (this document).
- Trusted Hubs portal endpoints + UI (in flight).
- **`GET /agentid/hubs/public` exposed; `aip-activity` polls it and refuses ingest from non-listed hubs (§3.6).** Closes the "any domain with a manifest can pollute the activity stream" hole.
- DojoZero coordination: adopt new SDK versions, publish manifest with `approval_policy`, enable DPoP at hub side.

### 8.3 Phase C — Enforcement (≥ Q3 2026)

- Resource-server `dpop_mode="required"` becomes default for verified hubs.
- `Bearer` scheme marked deprecated in spec; sunset 6 months out.
- Per-(principal, hub) preferences in portal + new table; `compose_delegation_claim` populates `principal_prefs` parameter.
- Operator-facing flow for promoting `self_onboarded` → `verified`, with criteria (KYB-light, manifest review, audit trail).
- `attested_by` federation reading (verify a second IdP's attestation as a path to verified-tier).
- `compute_kid` legacy helper retired; all `kid`s become RFC 7638 thumbprints.

### 8.4 What stays out of scope

- Spec-level cross-IdP shared trust list. Per-IdP lists by design (§3.2).
- mTLS-bound tokens (RFC 8705). Defer unless adopter forces it (§6.4).
- Approval-policy DSL v2 with per-constraint operators / regions / time-of-day. Defer until a v1 limitation actually blocks an adopter.
- Ephemeral DPoP keys distinct from the agent's registered key. Defer; current design uses the registered key directly.
- Shared-DB coupling between `aip-idp` and `aip-activity` for trust-list state. Per §3.6 — API-sync is the deliberate design, not shared DB.

## 9. Open questions

- **Should `dpop_mode="optional"` ship as the default Verifier configuration once Phase B is complete?** Current default is `"disabled"` for back-compat. Once the SDK has been out for one minor version and adopters have had time to test, flipping the default to `"optional"` would let every hub opportunistically gain DPoP without explicit opt-in. **Lean: yes, flip in v0.6.**

- **What's the right shape for principal `always_require` additions in Phase C?** v0.5 has the principal expressing preferences as `never_require` (waive selectively) and `thresholds` (tighten). Should the principal also be able to *add* `always_require`? Use case: a cautious principal wants approval for every transfer regardless of amount. We could surface this as `always_require: ["transfer.value"]`, but it conflicts with the v1 rule "only the hub publishes `always_require`." **Lean: allow it, with a portal warning that turns the agent fully manual.**

- **`approval_modes_supported` semantics when the hub publishes both modes.** Default picker should be the IdP's discovery-doc `approval_endpoint` (delegated if advertised). But once per-principal preferences exist, the principal should be able to choose per-hub. The composition needs to know whether the hub supports the principal's preferred mode and fall back gracefully. **Defer to Phase C.**

- **Should `verified` promotion require an `attested_by` chain?** Today it's a free-form operator action. Requiring an attester would force a structured trust path but adds adoption friction. **Lean: no for v0.5; revisit in v1.0 spec rev.**

- **Replay cache backing for multi-instance deployments.** SDK ships `InMemoryReplayCache`; production multi-replica IdPs / hubs need Redis. The interface is a duck-typed Protocol — adopters can swap. We should ship a `RedisReplayCache` adapter in `agent-id-service-sdk` once any adopter actually needs it. **Defer; document the swap point.**

- **Does the SDK package need renaming?** `agent-id-service-sdk` now has three consumer classes (hubs as signers, hubs as verifiers, IdPs as verifiers). The name reflects only the first. **Lean: rename to `agent-id-protocol-sdk` in v1.0 alongside the spec rev. Pre-v1.0 not worth the churn.**

## 10. Decisions to lock before code

The first three are locked in Phase A — listed here for the spec rev. The rest gate Phase B / C.

**Locked (Phase A):**

1. **`cnf.jkt` format**: RFC 7638 standard SHA-256 thumbprint, base64url no padding. Not the AgentID-historical `sha256(pubkey)[:16]`.

2. **DPoP key**: the agent's existing registered key, not a separate ephemeral DPoP key.

3. **Trust tier strictness on `/agentid/token`**: lenient. Unknown audiences pass through without delegation claim when auto-discovery fails (logged warning). Only `blocked` refuses outright. Strict mode is a future option, not a v0.5 default.

4. **Trust enforcement at activity ingest**: strict. `aip-activity` polls `aip-idp`'s `/agentid/hubs/public` endpoint, caches the result, refuses events from hubs outside the cached set. Opt-in via `AGENTID_IDP_TRUST_LIST_URL`; unset = enforcement disabled for back-compat (§3.6).

5. **Inter-service coupling for trust state**: API-sync, not shared DB. Operators manage trust list in the IdP portal; downstream services poll. Rationale and tradeoffs in §3.6.

**Pending decisions (Phase B):**

4. **DSL extension semantics for hub-flavored fields.** v0.5 passes them through opaquely. Should consumer hubs see them in the `delegation` claim with a documented namespace (e.g., `extensions: {dojozero: {...}}`)? Or scattered at top level? **Pending review.**

5. **Auto-discovery default in dev mode.** Currently *implicitly* on when `DAIL_AGENT_IDP_DEV_MODE=true`. Worth making explicit in spec language? **Pending.**

**Pending decisions (Phase C):**

6. **Verified-tier promotion criteria.** Out of protocol but needs documented standard so operators don't ad-hoc it.

7. **`dpop_mode="required"` rollout date.** Tie to a v0.6 SDK release? To a calendar date? Tie to specific high-stakes adopters reaching parity? **Pending.**

## 11. References

- `2026-03-25-agentid.en.md` — main spec. This doc proposes revisions to §3, §6, §7.4, §7.6.
- `2026-05-04-activity-discovery.en.md` — hub manifest + HubJWS envelope (§5.0). This doc extends both.
- `2026-04-23-approval-scenarios.en.md` — narrative grounding for §7.6 approval scenarios.
- RFC 7517 — JSON Web Key (JWK).
- RFC 7638 — JWK Thumbprint. Used for `cnf.jkt`.
- RFC 7800 — Proof-of-Possession Key Semantics for JWTs. Defines the `cnf` claim shape.
- RFC 8705 — OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens. Considered, rejected (§6.4).
- RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession (DPoP). The DPoP profile in §6.
- FAPI 2.0 Security Profile — OpenID Foundation. Requires sender-constrained tokens; AgentID aligns.

## 12. Spec rev plan

This doc folds into `2026-03-25-agentid.en.md` at the next major spec rev (v0.5 release), with the following section edits:

- **§3 Architecture** — Hub trust tiers introduced as IdP-side metadata; agent ↔ IdP ↔ hub triangle annotated to show per-IdP trust list.
- **§6 Token issuance** — `cnf.jkt` and `delegation` claims added to the canonical JWT shape; DPoP profile section added.
- **§7.4 Approval triggers** — Hardcoded threshold language replaced with the DSL composition rule. Refer to `app/core/approval_policy.py` as canonical implementation.
- **§7.6 Approval workflow** — `approval_modes_supported` / `approval_mode_default` integrated into Model 1 / Model 3 selection logic.
- **New §10 — Sender-Constrained Tokens (DPoP)** — Lifted from §6 of this doc.
- **New §11 — Hub Trust Tiers** — Lifted from §3 of this doc.

After spec rev, this doc moves to `design/` as a historical record (status: `landed`).
