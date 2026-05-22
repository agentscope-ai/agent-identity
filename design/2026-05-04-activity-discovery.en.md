# Activity Discovery — Decentralized Hub Schemas

**Date**: 2026-05-04
**Status**: Draft — proposal, not yet folded into main spec
**Scope**: Replaces the interim YAML-PR registration flow in `aip-activity` with a `.well-known/`-based discovery protocol. Refines `2026-03-25-agentid.en.md` §8.2 and supersedes `2026-05-01-deferred-work.md` §2.

---

## 1. Why now

Two unresolved tensions in Layer 2 (Activity Attestation), surfaced by DojoZero — adopter #1 and the first product that emits Tier-2 events into `pre.agent-id.live`.

**Tension 1: spec vs implementation drift.** §8.2 of the main spec already says hubs host their own schemas at a `summary_schema_url`. The shipped `aip-activity` instead loads schemas from `app/schemas/hubs/<namespace>.yaml` checked into the `aip-activity` repo. Adopter teams negotiate their schemas via PR review, redeploy gates each schema change, and the schema lives in someone else's repo. That makes the `aip-activity` team a bottleneck for every adopter and contradicts the "decentralized trust" design principle in §2. The `.example` template at `aip-activity/app/schemas/hubs/dojozero.example.yaml` is in fact the AIP team's draft of DojoZero's contract — sketched before we asked DojoZero. That asymmetry is the symptom; the cause is that schema discovery was never speced past the URL hint.

**Tension 2: session-summary vs event-stream.** §8.3 specifies one signed report per agent session, with aggregate fields (`games_played`, `final_balance`). The `agent-id-service-sdk` `Verifier` instead emits per-event Tier-1/Tier-2 events (`auth.verify`, `transfer.value`, `session.start/end`, plus hub-namespaced custom events). Both designs have a place. Neither has been ratified. DojoZero is wiring four Tier-1 categories (`auth.deny`, `session.start`, `session.end`, `transfer.value`) and wants two Tier-2 (`dojozero.bet_decision`, `dojozero.trial_outcome`) and is the right time to lock this down.

This doc resolves both.

## 2. Unifying insight

Activity-schema trust is structurally identical to JWT-key trust — a problem AIP Layer 0 already solved.

> "How do we trust a claim that comes from a service we may have never heard of before?"

For *identity* keys: signed JWT + JWKS at `/.well-known/agent-id-jwks` + cached lazy fetch + trust anchored in `trusted_providers`.

For *schemas*: signed manifest + categories at `/.well-known/agent-id-activity-*` + cached lazy fetch + trust anchored in the principal registry.

**Hubs are first-class AIP principals.** Their identity already lives in the IdP. Use that identity to anchor the contract about what events they emit. No new trust model, no new mental model — same `/.well-known/` pattern adopters already implement for keys.

## 3. The three discovery artifacts

### 3.0 Hubs are peer principals to IdPs

Worth saying first because the protocol audience will assume the wrong
thing otherwise: **hubs are first-class principals in their own right,
peer to IdPs — not registered agents.** The spec's architecture
triangle (§3 of `2026-03-25-agentid.en.md`) is Agent ↔ IdP ↔ Hub. Three
roles, distinct trust anchors:

| Role | Trust anchor | Key publication |
|---|---|---|
| **IdP** | Its domain + its JWKS | `https://<idp-domain>/.well-known/agent-id-jwks` |
| **Hub** | Its domain + its JWKS | `https://<hub-domain>/.well-known/agent-id-jwks` |
| **Agent** | Registered at an IdP | Public key sent during registration |

Hubs do **not** register at IdPs. An IdP at `pre.agent-id.live` doesn't
register itself as an agent at some other IdP either; it just publishes
its JWKS at its own `.well-known/` and that's its identity. Hubs work
the same way — domain ownership + self-published keys is the trust
anchor, no agent-registration flow.

This means hubs do not have an AgentID-formatted `principal_id`. Their
identifier is their `service_id` (a URL). When the spec needs to refer
to a hub as a principal, it does so by URL.

A hub publishes three resources on its own domain:

```
https://<hub-domain>/.well-known/agent-id-activity-manifest
https://<hub-domain>/.well-known/agent-id-activity-categories
https://<hub-domain>/.well-known/agent-id-activity-schemas/<category>/<version>
```

Plus the JWKS endpoint hubs already need:

```
https://<hub-domain>/.well-known/agent-id-jwks
```

### 3.1 The manifest

```json
{
  "service_id": "https://api.dojozero.live",
  "namespace": "dojozero",
  "categories_url": "https://api.dojozero.live/.well-known/agent-id-activity-categories",
  "jwks_url": "https://api.dojozero.live/.well-known/agent-id-jwks",
  "attested_by": "agentid:pre.agent-id.live:org_dojozero_a1b2c3d4",
  "aip_version": "0.1"
}
```

| Field | Required | Meaning |
|---|---|---|
| `service_id` | yes | Public origin (URL). The hub's identity. The eTLD+1 of this URL determines namespace ownership (§6). MUST equal the JWT `aud` of every event the hub emits. |
| `namespace` | yes | Tier-2 prefix this hub claims. Must be consistent with `service_id` per §6. |
| `categories_url` | yes | Where to fetch the category catalog. Typically same origin; MAY be a CDN/mirror. |
| `jwks_url` | yes | The hub's own JWKS. `aip-activity` fetches manifest-signing keys here. Same shape as an IdP's JWKS endpoint. |
| `attested_by` | optional | An org-Principal AgentID (registered at any trusted IdP) that takes accountability for this service. Provides a chain "this hub is operated by this human/org" without making the hub itself an agent. v1 is purely informational; v2 may use it for federated trust (see §5). |
| `aip_version` | yes | Manifest schema version. |

The manifest is **JWS-signed** by a key in `jwks_url` — Ed25519 or
ES256, same algorithms the rest of AIP uses. Signature covers a
canonical (RFC 8785) form of the body. TLS already protects fetch
integrity, but the JWS lets `aip-activity` cache the manifest and
verify it later without re-fetching.

There is no `principal_id` field. The hub *is* its `service_id`; its
keys live at `jwks_url`; that's the whole identity story. The
`attested_by` field is the only place an AgentID-formatted principal
appears, and it's optional, denoting org accountability.

#### 3.1.1 JWKS shape

The document at `jwks_url` is a standard **JWK Set** (RFC 7517 §5)
containing the hub's manifest-signing keys. Two key types are accepted,
matching the manifest signing algorithms:

- **Ed25519 (EdDSA)** per RFC 8037 §2:
  `{"kty": "OKP", "crv": "Ed25519", "kid": <id>, "x": <b64url-no-pad of the 32-byte raw public key>}`
- **ECDSA P-256 (ES256)** per RFC 7518 §6.2:
  `{"kty": "EC", "crv": "P-256", "kid": <id>, "x": <b64url>, "y": <b64url>}`

`kid` MUST be present on every key and MUST match the `kid` header of
the JWS the hub publishes at `/.well-known/agent-id-activity-manifest`.
Base64url encoding is RFC 7515 §2 — URL-safe alphabet, no padding. No
fields beyond what's spec'd here are inspected by `aip-activity`;
adopters MAY include standard JWK metadata (`use`, `alg`, `key_ops`)
but they have no protocol meaning at the manifest layer.

A non-Python implementer can produce a valid JWKS with any JOSE library
or `openssl genpkey -algorithm ed25519` plus base64url encoding of
`openssl pkey -pubout -outform DER` — there is nothing AIP-specific
about the encoding.

### 3.2 The categories doc

```json
{
  "service_id": "https://api.dojozero.live",
  "namespace": "dojozero",
  "categories": [
    {
      "category": "dojozero.bet_decision",
      "schema_version": "1.0.0",
      "schema_url": "https://api.dojozero.live/.well-known/agent-id-activity-schemas/bet_decision/1.0.0",
      "schema_format": "json-schema",
      "deprecated": false,
      "introduced_at": "2026-05-04T00:00:00Z",
      "sensitive_fields": ["market_hash"]
    },
    {
      "category": "dojozero.bet_decision",
      "schema_version": "0.9.0",
      "schema_url": "...",
      "schema_format": "json-schema",
      "deprecated": true,
      "deprecated_at": "2026-05-04T00:00:00Z",
      "sunset_at": "2026-08-04T00:00:00Z",
      "sensitive_fields": ["market_hash"]
    }
  ],
  "served_at": "2026-05-04T12:00:00Z"
}
```

Each entry is a `(category, schema_version)` tuple — multiple versions per category coexist for migration windows (§7).

### 3.3 The schema docs

Each `schema_url` returns standard JSON Schema (Draft 2020-12). Pinned URL = pinned version; the activity service caches by URL.

> JSON Schema is verbose but it's the lingua franca, it has client tooling in every language we'd care about, and `schema_format` leaves the door open for CUE/Protobuf in v2 if a hub wants binary efficiency. Ship JSON Schema, don't look back.

## 4. The validation flow

When `aip-activity` receives an event with category `dojozero.bet_decision@1.0.0`:

1. **Token verify** (existing): get verified `iss`, `aud`, `sub` from the JWT. The `aud` is the hub's `service_id`.
2. **Hub trust check.** The `service_id` (= JWT `aud`) MUST be in `aip-activity`'s `trusted_hub_origins` config (§5). If not: 403, hub not trusted.
3. **Hub manifest resolution.** Cache key: `service_id`. TTL: 1h (configurable, mirrors JWKS TTL).
   - On hit: use cached manifest.
   - On miss: GET `<service_id>/.well-known/agent-id-activity-manifest`. Fetch the hub's JWKS at `manifest.jwks_url`. Verify the manifest's JWS signature against a key in that JWKS. Verify `manifest.service_id == <aud>` (no spoofing). Verify the namespace ownership rule (§6). Cache the parsed manifest + the JWKS.
4. **Categories doc resolution.** Cache key: `service_id`. TTL: 1h.
   - On miss: GET `manifest.categories_url`. Cache the parsed catalog.
5. **Schema resolution.** Cache key: `(category, schema_version)`. Long-lived TTL (12–24h) since pinned versions are immutable.
   - On miss: GET `entry.schema_url`. Parse as JSON Schema. Cache.
6. **Validate payload** against the resolved JSON Schema. Reject (422) on shape mismatch.
7. **Store with metadata**: `category`, `schema_version`, `validation_outcome`. Downstream consumers can query by version (`GET /agentid/activity?category=dojozero.bet_decision&schema_version=1.0.0`).

This is **the JWKS pattern with one extra hop** (manifest → categories → schema). All four layers (hub JWKS, manifest, categories, schema) cache. All are refreshed on miss or TTL expiry. None require human action beyond initially adding the hub to `trusted_hub_origins`.

## 5. Hub authentication (subsumes deferred-work §2)

`deferred-work.md §2` flagged that hubs currently authenticate to
`aip-activity` with two secrets — a static hub bearer key plus the
agent's forwarded JWT. With manifest-based discovery, the static hub
key goes away. The replacement uses two cryptographic signatures and
no out-of-band material.

**Model:**

| Layer | Authenticates | Mechanism |
|---|---|---|
| Hub identity | The emitting service | `service_id` (= JWT `aud`) is in `aip-activity`'s `trusted_hub_origins` list. Trust anchor is the hub's domain + its self-published JWKS. |
| Submission proof | Hub possesses (not just observed) the request | The hub signs an *outer envelope* with one of its own keys (Ed25519/ES256, published in its `jwks_url`). Sent as `Authorization: HubJWS <compact-jws>`. |
| Agent identity | The agent itself | Inner agent JWT in `X-AgentID-Token`, verified against the issuing IdP's JWKS as today. |

Both signatures are cryptographic. The hub key is *not* an AgentID —
it's just a key the hub publishes at its own `.well-known/agent-id-jwks`,
structurally identical to how IdPs publish their signing keys. Key
rotation reduces to "publish a new key in your JWKS, sign with it next
time" — the same flow IdPs already do.

The legacy `DAIL_AGENT_ACTIVITY_API_KEYS` mechanism is removed in this
version. Adopters integrating against a v1 `aip-activity` use only the
HubJWS path described here.

### 5.0 Outer envelope wire format

The outer envelope is a standard JWS (RFC 7515) in **compact
serialization**, presented in the `Authorization` header with the
scheme `HubJWS`:

```
Authorization: HubJWS <base64url-header>.<base64url-payload>.<base64url-sig>
```

**JWS protected header:**
```json
{ "alg": "EdDSA", "kid": "<hub-key-id>", "typ": "hub-envelope+jws" }
```

`alg` MUST be `EdDSA` (Ed25519) or `ES256` (ECDSA P-256) — the same
set the manifest signing accepts. `kid` MUST resolve to a key in the
hub's published JWKS at `manifest.jwks_url`.

**JWS payload (claims):**
```json
{
  "iss": "<hub service_id>",        // = manifest.service_id
  "aud": "<aip-activity origin>",   // the receiving service's origin
  "iat": <unix-seconds>,            // when the envelope was signed
  "jti": "<128-bit-random-hex>",    // nonce, unique per request
  "body_sha256": "<lowercase-hex>", // sha256 of the raw request body
  "privacy": {                      // optional; hub's privacy posture
    "default_level": "summary",     //   for events in this request
    "category_overrides": {         //   absent → activity service treats
      "transfer.value": "full"      //   default_level as "summary"
    }
  }
}
```

The `privacy` claim is the hub's policy applied to events in this
request. The hub asserts it within the same envelope it signs — no
separate IdP-issued token needed. This replaces the prior
`X-AgentID-Token` header path for hub-emitted events: the hub *is* its
`service_id` (per §5), so its policy claims travel with its signed
envelope, not as a separately-issued JWT.

`privacy.default_level` MUST be one of `full | summary | existence | none`
(matching the activity service's privacy enforcement levels). When the
claim is omitted the activity service treats the events at
`default_level=summary` — the conservative default.

`category_overrides` is a map of `category → level` for per-category
posture (e.g., a hub may keep `transfer.value` at `full` for audit
while keeping `tool.use` at `summary` for operational privacy).

**Verifier obligations** (`aip-activity`):
1. Parse the JWS, extract `iss` from the payload and `kid` from the
   header. Reject if either is missing or if `iss` is not in
   `trusted_hub_origins`.
2. Resolve the hub's JWKS via `HubManifestFetcher.fetch(iss).jwks_url`,
   look up `kid`. Reject on miss with one forced JWKS refresh.
3. Verify the JWS signature.
4. Compute `sha256(raw_request_body)` (lowercase hex). Reject if it
   doesn't match `body_sha256` in the claims.
5. Reject if `|now - iat| > 60s` (skew window).
6. Reject if `jti` is in the replay cache. Otherwise, insert with a
   120s TTL (slightly larger than the skew window so legitimate retries
   land outside it).
7. On success, the authenticated principal is the value of `iss`. The
   hub's `service_id` becomes the audit identity for everything in the
   request body.

**Signer obligations** (the hub):
1. Compute `sha256(body)` of the JSON request body bytes you're about
   to send (no canonicalization — the verifier hashes the same bytes).
2. Build the claims with `iss = service_id`, `aud = activity_endpoint`,
   `iat = now`, `jti = secrets.token_hex(16)`, `body_sha256 = <hex>`.
3. Sign as compact JWS using the hub's private key + `kid`.
4. Send `POST <activity_endpoint>` with `Authorization: HubJWS <jws>`,
   `Content-Type: application/json`, the body bytes whose hash you
   committed to.

**Retry policy:** retries reuse the same `jti` and `body_sha256`. The
verifier's replay cache becomes the natural idempotency key — a retry
arriving inside the cache window is rejected with 409 (or accepted as a
no-op, implementation choice — `aip-activity` chooses 409 to surface
client-side bugs). Outside the cache window, the request must be
re-signed with a fresh `iat` and `jti`.

**No detached payload, no canonicalization gymnastics, no extra
headers.** Standard JWS, standard JWT-style claims, body integrity via
hash-in-claims rather than signing-the-body-directly. Trades 32 bytes
of overhead for "any JOSE library in any language can implement this."

### 5.1 Hub trust list (the v1 trust mechanism)

`aip-activity` operators configure which hub origins they accept events
from. Same model as `trusted_providers` for IdPs:

```
DOJOZERO_AGENTID_TRUSTED_HUBS=https://api.dojozero.live,https://api.polymarket.live
```

This is the only operator-side decision. It happens once per hub at
deploy time, not per schema or per category. It does not gate schema
evolution, namespace registration, or anything else — it just bootstraps
trust.

For a public `aip-activity` instance hosting many hubs, this list grows
linearly with adopters. That's the same scaling shape as `trusted_providers`
for IdPs — manageable for v1.

### 5.2 Federated trust via `attested_by` (v2)

Once `attested_by` (§3.1) sees real use, the trust list can be replaced
or supplemented by IdP-mediated federation:

> A hub is trusted if its manifest's `attested_by` points to an
> AgentID-issued principal whose IdP is in `trusted_providers`, AND that
> principal has a valid attestation that this `service_id` is operated
> by them.

This pushes hub admission from `aip-activity`-operator action to
IdP-Principal action. Cleaner long-term shape, but it requires
attestation issuance flow at the IdP, which is unbuilt today. Defer to
v2.

This is the option the deferred-work doc lists as an alternative; this
design picks it.

## 6. Namespace ownership

Namespace squatting is the place a decentralized model needs the most
care. The rule:

> A manifest MAY claim Tier-2 namespace `<ns>` if and only if the
> registrable domain (eTLD+1) of `service_id` matches `<ns>`,
> case-insensitive, after underscore/hyphen normalization.

DNS ownership is the trust anchor, not anything inside AIP. ICANN
already arbitrates trademark disputes at the registrable-domain level;
controlling the cert proves controlling the domain; we don't reinvent
any of that.

For DojoZero:
- `service_id` = `https://api.dojozero.live`
- Registrable domain via Public Suffix List = `dojozero.live`
- Bare-name extract = `dojozero`
- Claimed namespace = `dojozero` ✓

For an attacker on a different domain:
- `service_id` = `https://api.evil.com`
- Bare-name extract = `evil`
- Claimed namespace = `dojozero` ✗ rejected

`aip-activity` parses `service_id`, extracts the registrable domain
using a public-suffix-list library, and compares. Any mismatch fails
manifest verification.

**Subdomain flexibility.** Multiple subdomains of the same registrable
domain MAY all serve manifests claiming the same namespace.
`https://api.dojozero.live`, `https://gateway.dojozero.live`, and
`https://canary.dojozero.live` can all claim `dojozero`. They're the
same DNS owner; they get the same namespace.

**Aliases.** A namespace owner MAY register a signed cross-attestation
allowing another `service_id` (typically a related-domain product —
`dojozero-prod.live` ↔ `dojozero.live`) to share the namespace. Spec
the field; defer the implementation. v1 says "register a different
namespace per registrable domain."

**Path-based hubs.** Hubs sharing a domain via path
(`https://platform.example.com/dojozero/`) are **out of scope for v1**.
The eTLD+1 rule doesn't fit them cleanly. v2 can add a manifest-side
challenge mechanism (`aip-activity` POSTs a nonce to
`<service_id>/.well-known/agent-id-namespace-challenge` and verifies the
signed response) if a real adopter needs it. v1 says "subdomain per
hub."

**Conflict resolution.** First trusted manifest wins. A second hub
trying to claim an already-bound namespace via a different `service_id`
is rejected with a clear error. Manual operator override exists in
`aip-activity` for trademark/dispute cases (rare, expected to be near
zero).

**Reserved prefixes.** `aip.*`, `agentid.*`, `tier1.*`, `approval.*`,
and `delegation.*` MUST NOT be claimed as Tier-2 namespaces — even by
a hub at `aip.example.com`. The first three are reserved for protocol
evolution; `approval.*` and `delegation.*` are reserved because they're
Tier-1 categories (per §9.5) and Tier-1 lookup short-circuits Tier-2
namespace resolution. The SDK's `category_tier()` enforces this — a hub
declaring `hub_namespace="approval"` and emitting `approval.requested`
gets tier 1 (not the hub's tier 2), as it should.

## 7. Schema versioning

Each `(category, version)` is immutable. Hubs publish new versions; `aip-activity` stores both for the duration of the migration window.

**Semver semantics:**

- **PATCH** (`1.0.0` → `1.0.1`): documentation only — examples, descriptions. Schema bytes change; validation behavior does not. Optional to consume.
- **MINOR** (`1.0.0` → `1.1.0`): additive — new optional fields, broader enums. Old payloads still validate against new schema. Producers may upgrade independently.
- **MAJOR** (`1.0.0` → `2.0.0`): breaking — required fields added, types changed. Old and new MUST coexist for the migration window.

**Migration window.** When a category version is marked `deprecated`, the hub MUST also set `sunset_at`. After `sunset_at`, the activity service rejects events targeting that version. Default window: **90 days**, hub-tunable up to 365.

**Event envelope.** Every event MUST carry `schema_version`. Activity service stores it. Default version (when emitter doesn't specify) is the latest non-deprecated version on the resolution path — but emitters SHOULD pin explicitly.

## 8. Tier 1 vs Tier 2 vs the session-summary model

Tension 2 from §1: do hubs emit per-event streams or per-session summaries?

**This proposal: both, with clear separation.**

- **Tier 1 (event stream)**: `auth.verify`, `auth.deny`, `session.start`, `session.end`, `transfer.value`, `tool.use`, `model.call`, `data.read`, `data.write`. Server-defined schemas, fixed across hubs, used for cross-hub aggregation.
- **Tier 2 (event stream, hub-namespaced)**: `<ns>.<verb>` shapes. Hub-defined schemas, discovered via §3.
- **Tier 3 (custom.*)**: free-form, no schema, no aggregation guarantees. Escape hatch for fast iteration.
- **Session summaries** (the §8.3 model): become a Tier-2 *convention* — `<ns>.session_summary` with hub-defined fields. Hubs that prefer summaries over event streams (e.g., low-bandwidth integrations, batch hubs) emit one summary per session. Hubs that prefer event streams emit `session.start`/`session.end` plus per-action events. The two coexist; downstream consumers choose what to subscribe to.

This deletes the spec/impl divergence: §8.3's session-summary becomes a recommended Tier-2 pattern, not a mandatory wire format. The shipped per-event SDK is canonical for the event-stream model.

§8 of the main spec gets revised to this framing in the next spec rev.

## 9. Tier-1 schema lockdown

§8 listed the Tier-1 categories but didn't specify their schemas. That's
the gap that turns Tier-1 from "cross-hub aggregation primitive" into
"category name everyone uses differently." This section closes it.

The schemas below are now **shipped in `aip-activity/app/schemas/categories.py`**
(2026-05-04 reconciliation pass). Treat the field-level shapes here as
canonical; the `aip-activity` Pydantic models are the source of truth.
The activity service enforces them on ingest via Tier-1 dispatch.

> **Privacy by default.** A pattern I missed in the first draft of this
> doc but that runs through the actual implementation: identifiers and
> values that could leak content are *hashed or bucketed*, not raw.
> `tool.use.args_hash` (sha256) instead of args. `data.read.resource_id_hash`
> instead of resource_id. `transfer.value.amount_bucket` (`lt_100` /
> `100_1k` / `1k_10k` / `10k_plus`) instead of raw amount. Raw values
> may be carried on the side at `privacy_level=full` and dropped on
> summary. Cross-hub aggregation depends on the bucketed/hashed forms;
> raw forms are for the hub's own consumers only. This is a non-trivial
> design property worth keeping as new Tier-1 schemas land.

The current Tier-1 list
(`agent-id-service-sdk/events.py:TIER1_CATEGORIES`) bundles three
different category kinds, surfaced by the Bucket analysis:

### 9.1 Bucket analysis

| Category | Bucket | Note |
|---|---|---|
| `auth.verify` | Universal lifecycle | Token verified at this audience+route |
| `auth.deny` | Universal lifecycle | Verification failed |
| `session.start` | Universal lifecycle | Agent connected to hub |
| `session.end` | Universal lifecycle | Agent disconnected |
| `transfer.value` | Domain-flavored (financial) | Value moved on agent's behalf |
| `tool.use` | Domain-flavored (action) | Agent invoked a tool |
| `model.call` | Domain-flavored (LLM consumption) | Agent invoked an LLM |
| `data.read` / `data.write` | **Muddy** | Overlaps with `tool.use`; boundary undefined |
| `approval.*` | (missing — should be Tier-1) | See §9.5 |
| `delegation.*` | (missing — should be Tier-1) | See §9.5 |

Bucket meaning:

- **Universal lifecycle** — fires on any agent regardless of hub class.
  Schema is inherent to the protocol; just needs to be made explicit.
- **Domain-flavored** — fires only on hubs in the matching domain
  (financial / agentic / LLM-using). When emitted, MUST be canonical so
  cross-hub aggregation works. Hub-specific richness lives in linked
  Tier-2 events.
- **Muddy** — definition overlaps with another category. Either tighten
  or demote.

The defining property of Tier-1 is **standardized-when-emitted**, not
emitted-everywhere. A hub that has no economy never fires
`transfer.value`; that's expected and correct, not a spec violation.

### 9.2 Bucket A — universal lifecycle categories

Schemas are explicit in `aip-activity/app/schemas/categories.py`.
Envelope fields (`agent_id`, `principal_id`, `audience`, `issuer`,
`kid`, `timestamp`) are universal across all categories — the payloads
below are what's category-specific.

```
auth.verify payload:
  { route, success: bool }

auth.deny payload:
  { route, error_class }
  # error_class is a short code (free-form string by schema, but
  # conventional values are: token_expired, token_invalid,
  # signature_invalid, provider_untrusted, audience_mismatch,
  # principal_revoked). Cross-hub anomaly detection aggregates by this.

session.start payload:
  { session_id, scenario?, attributes? }
  # scenario is a generic kind-of-session label any hub may set
  # ("trial", "chat", "task", "analytics"). Cross-hub queries can
  # filter by it. attributes is an open hub-context dict (drops at
  # privacy_level=summary).

session.end payload:
  { session_id, duration_ms, outcome?, total_tokens?, total_cost_usd?,
    summary? }
  # total_tokens/total_cost_usd are LLM-spend roll-ups — useful
  # cross-hub for any LLM-using agent. summary is an open hub-summary
  # dict (drops at summary).
```

`attributes` and `summary` are open-shape dicts that hubs use to attach
domain-flavoured context without polluting the canonical schema.
DojoZero puts `{ persona, model, sport_type }` in `attributes` and
`{ final_balance, last_observed_sequence, bet_count }` in `summary`.
Cross-hub queries don't depend on these fields; they're informational
and are dropped on `privacy_level=summary`.

### 9.3 Bucket B — canonical schemas

These are the categories Tier-1 most needs to canonicalize. The shape
is "minimal cross-hub fields"; hub-specific richness moves to linked
Tier-2 events via correlation IDs (§9.6).

#### 9.3.1 transfer.value

```
amount_bucket: enum["lt_100", "100_1k", "1k_10k", "10k_plus"]
                                   # required; the privacy-preserving
                                   # form. Cross-hub aggregation reads
                                   # this, not the raw amount.
currency: string                    # required. ISO-4217 ("USD") OR
                                   # hub-defined ("DOJOZERO_USD",
                                   # "POLY_USDC")
direction: enum["out", "in"]        # required; from the agent's
                                   # perspective
amount: float|null                  # raw amount; OPTIONAL. May be
                                   # omitted entirely. If present,
                                   # drops at privacy_level=summary.
purpose: string|null                # free-form short verb; conventional
                                   # values: "stake", "payout", "fee",
                                   # "refund", "trade", "transfer",
                                   # "credit", "debit"
transaction_id: string|null         # hub-unique. The join key for
                                   # linked Tier-2 events and for
                                   # approval.* via request_id.
counterparty_principal_id: string|null  # the other side, if any
linked_tier2: string|null          # the Tier-2 category that carries
                                   # the hub-specific richness (e.g.,
                                   # "dojozero.bet_decision")
```

The `linked_tier2` field lets consumers join a Tier-1 transfer to its
richer Tier-2 sibling without reverse-engineering the relationship.

The amount-bucketing pattern is what makes cross-hub aggregation work
without leaking individual transaction sizes. Bucket whitelist lives in
`AMOUNT_BUCKETS` (`aip-activity/app/schemas/categories.py`); evolves
under the Tier-1 schema-evolution rules in §13.

#### 9.3.2 tool.use

```
tool_name: string                   # required; hub-namespaced
                                   # ("dojozero.place_bet", "mcp.read_file")
args_hash: string                   # required; sha256:<64-hex>
                                   # privacy-preserving hash of args.
                                   # Raw args go in a linked Tier-2.
tool_invocation_id: string          # required; hub-unique. Lets
                                   # model.call and transfer.value
                                   # link via linked_tool_invocation_id
                                   # / linked_transfer_id.
duration_ms: int|null               # >= 0
success: bool|null
linked_transfer_id: string|null     # if this tool.use caused a
                                   # transfer.value, its transaction_id
```

Tool inputs/outputs are NOT in the canonical schema; the `args_hash`
makes the call audit-able without revealing content. Full args go in a
linked Tier-2 event (e.g., `dojozero.tool.place_bet` with the bet
markets/selections).

#### 9.3.3 model.call

```
model: string                       # required. Provider-qualified or
                                   # bare ("claude-haiku-4-5",
                                   # "qwen3-max", or
                                   # "anthropic/claude-haiku-4-5").
                                   # Cross-hub queries normalise as
                                   # needed; spec doesn't mandate.
tokens_in: int                      # required; >= 0
tokens_out: int                     # required; >= 0
latency_ms: int|null
cost_usd: float|null                # USD-only for v1. Currency-flexible
                                   # cost_amount/cost_currency split
                                   # deferred until a hub asks for it.
purpose: string|null                # free-form ("reasoning", "tool",
                                   # "summarisation")
outcome: enum["success", "error", "filtered"]|null
linked_tool_invocation_id: string|null  # if this call ran inside a
                                       # ReAct tool loop
```

**Kept at Tier-1** with explicit caveat: AIP `model.call` is the
agent-protocol *audit shape*. For high-resolution LLM observability,
hubs SHOULD also use OTel-GenAI or provider-native telemetry. The two
coexist; AIP doesn't pretend to be Langsmith. The minimal canonical
shape is enough for cross-hub spend aggregation.

### 9.4 Bucket C — `data.read` / `data.write` (kept simple, narrow rule deferred)

Shipped shape mirrors the privacy-by-default convention:

```
data.read  payload: { resource_kind, resource_id_hash }
data.write payload: { resource_kind, resource_id_hash, op }
                    # resource_id_hash is sha256:<64-hex>
```

**The boundary problem hasn't gone away** — these still overlap
conceptually with `tool.use` for any hub that reads/writes via a tool.
For v1 the spec says "hubs SHOULD only emit `data.*` for
audit-relevant access (PII, regulated corpora); operational reads
stay under `tool.use`." Convention only — not enforced server-side.

The earlier proposal of narrowing via a manifest-declared
`data_namespaces` list (`["pii", "regulated_corpus_X"]`) plus
`{ data_namespace, operation, record_count, sensitivity,
linked_tool_invocation_id }` payload is **deferred** to a Tier-1
schema rev once a real adopter needs it. v1 keeps the simpler shape
shipped today; v2 can layer the narrowing on as a backwards-compatible
minor bump (additive optional fields + manifest field) when there's
a concrete consumer for the cross-hub "all sensitive-data access by
this agent" query.

### 9.5 Missing Tier-1 categories: approval and delegation

The approval workflow (`2026-03-25-agentid.en.md` §7.4) and delegation
model (§4.4) are core to the spec but have no Tier-1 events today. They
belong at Tier-1: universal lifecycle for any agent under any hub,
cross-hub-aggregable, regulator- and auditor-relevant.

Shipped shapes (envelope fields omitted; payload only):

```
approval.requested: { request_id, action, scope?, expires_at? }

approval.granted:   { request_id, granted_scope?, responded_at?, note? }
                    # note drops at privacy_level=summary

approval.denied:    { request_id, reason?, responded_at?, note? }
                    # note drops at summary; reason kept for cross-hub
                    # anomaly detection

delegation.granted: { delegation_id, scope?, capabilities?,
                      granted_to?, expires_at? }

delegation.revoked: { delegation_id, reason?, revoked_at? }
```

These let consumers answer:
- "How often does this agent need human approval?" (regulator).
- "What capabilities are currently delegated to this agent?" (audit).
- "Did the principal explicitly approve this transfer?" — joining
  `approval.granted` to `transfer.value` via `request_id` ↔
  `transaction_id` (spend-cap policy services).

### 9.6 Cross-event linkage rules

The schemas above use four correlation IDs to enable joins across
event categories:

| ID | Emitted in | Used by |
|---|---|---|
| `session_id` | `session.*` | All other events MAY include for session-scoping |
| `transaction_id` | `transfer.value` | Tier-2 product events; `approval.*` join via `request_id` |
| `tool_invocation_id` | `tool.use` | `model.call` (calls within tool exec); Tier-2 tool richness events |
| `request_id` | `approval.*` | `transfer.value` (or other authorized actions) — proves principal approval |
| `delegation_id` | `delegation.*` | Tracks scope changes over time |

Hubs MUST emit these consistently when the correlation exists. The
spec doesn't prescribe how hubs generate the IDs; just that they're
stable, unique within the hub, and emitted on every related event.

This is what turns Tier-1 from "isolated atomic events" into a
**relational stream** — consumers can write joins without per-hub
adapters. Cross-hub queries like "show me every transfer that was
explicitly approved, the model calls leading up to it, and the tool
that executed it" become a one-shot SQL query rather than a
hub-specific integration.

### 9.7 What NOT to canonicalize

Worth being explicit about scope: the Tier-1 schemas are deliberately
*minimal* and *privacy-preserving*. Things that don't go in:

- **Raw identifiers and amounts.** Use the bucketed/hashed forms:
  `amount_bucket` (not raw amount), `args_hash` (not raw args),
  `resource_id_hash` (not raw resource_id). Raw values may be carried
  alongside (e.g., `transfer.value.amount` is optional and present at
  `privacy_level=full`) but they're not what cross-hub aggregation
  reads. This is the **privacy-by-default** convention; new Tier-1
  schemas SHOULD follow it.
- **Domain-specific args / payloads** (bet markets, asset pairs,
  prompt text, file paths). These belong in linked Tier-2 events.
- **Per-provider observability fields** (Anthropic's `stop_reason`,
  OpenAI's `system_fingerprint`). These belong in OTel-GenAI / native
  telemetry, not AIP.
- **Free-form long text** (LLM prompt content, model outputs, tool
  args). The hash patterns above keep the audit trail without
  exposing content; full text goes to OTel for hubs that want it.
- **Hub-specific fields polluting the canonical surface.** Earlier
  iterations had `session.start.{persona, sport, trial_ref_hash}` and
  `session.end.{decisions_made, win_rate_bucket}` — these were
  DojoZero-flavored fields hardcoded into the cross-hub schema. They
  moved to `attributes` / `summary` open dicts during the 2026-05-04
  reconciliation. Future Tier-1 schema revs MUST resist re-introducing
  this pattern; hub-specific richness goes in Tier-2 or in the open
  context dicts.

The Tier-1 surface stays small, privacy-preserving, and stable so
cross-hub aggregation keeps working as the protocol evolves and as new
hubs adopt.

## 10. The interim YAML pattern

`aip-activity/app/schemas/hubs/<ns>.yaml` does not disappear immediately. It becomes the **fallback / static-config mode**:

- Activity service tries manifest discovery first (§4).
- If the manifest URL is unreachable AND a YAML registration exists for the same namespace, fall back to the YAML.
- If both succeed and disagree, manifest wins, log a warning.

YAML mode covers:
- **Local dev** — devs running `aip-activity` against a local hub that doesn't host TLS. They drop a YAML.
- **Network-isolated hubs** — internal Alibaba services that can't expose `.well-known/` publicly.
- **Deprecation transition** — existing YAML adopters get migrated, not yanked.

YAML mode is **opt-in per service operator** and emits a deprecation warning at startup. Schedule for removal: 12 months after manifest discovery ships and the first three adopters migrate.

## 11. Spec changes (against `2026-03-25-agentid.en.md`)

- **§8.2 Hub Registration.** Replace the `POST /aip/services`
  registration call with manifest discovery. Keep `summary_schema_url`
  semantics but generalize it (it's now `categories_url`, with
  multiple categories and versions).
- **§8.3 Activity Report Format.** Reframe as "session-summary
  convention," add cross-reference to Tier-1/Tier-2 event categories.
- **§8.4 Report Signing.** Generalize to "submission envelope signing"
  — applies to both single-event and session-summary submissions.
- **§8.5 Report Validation.** Add the manifest-resolution +
  schema-validation flow from §4 above.
- **New §8.9 Discovery Protocol.** Spell out the three artifacts,
  their fields, and the JWS signature requirement.
- **New §8.10 Tier-1 canonical schemas.** Land §9 of this doc as a
  spec appendix: explicit fields for each Tier-1 category, the
  correlation IDs (§9.6), and the linked-Tier-2 convention. Also
  surfaces the bucket distinction (universal lifecycle vs
  domain-flavored) so future spec readers don't repeat the
  "transfer.value isn't universal" misreading.
- **§7.4 Approval Workflow + §4.4 Delegation.** Cross-reference the
  new Tier-1 categories from §9.5 (`approval.requested`,
  `approval.granted/denied`, `delegation.granted/revoked`).

These edits land as a spec rev once this design is reviewed and
accepted. Until then, the design doc is canonical and the main spec is
annotated with a forward reference.

## 12. Implementation plan

Three repos to touch. Order is reversibility-cost-low to -high (same pattern as `2026-04-30-agentid-rename-plan.md`).

### Phase A — additive (1–2 weeks)

1. **`agent-id-service-sdk`**:
   - Add `HubManifestFetcher` mirroring the existing JWKS fetcher
     pattern (~200 lines).
   - Add manifest signing helper for hubs that publish their own
     manifest dynamically.
   - Add Tier-1 schema validators for the canonicalized categories
     (§9.2, §9.3, §9.5). These are static — Tier-1 schemas live in the
     SDK, not fetched.
   - Add envelope helpers for the correlation IDs (§9.6) so emitters
     can build linked events without manually plumbing
     `transaction_id` / `tool_invocation_id` / `request_id` strings.
   - Bump to 0.3.0; no breaking changes.

2. **`aip-activity`**:
   - Wire `HubManifestFetcher` into the ingest path.
   - Apply Tier-1 schema validation (Bucket A + B fields from §9) on
     ingest. Bucket C (`data.read`/`data.write`) gates on the
     hub's manifest declaring `data_namespaces`.
   - Add `GET /agentid/services/{namespace}/categories` for
     consumer-facing introspection (returns the cached view).
   - Keep YAML loader; add deprecation warning when used.
   - Add the new namespace ownership check (§6).
   - Add the new Tier-1 categories (`approval.*`, `delegation.*`) to
     the accepted-categories set, indexed for query.
   - Tests: manifest fetch + cache, version resolution, signature
     verification, namespace conflict, Tier-1 schema rejection (bad
     fields → 422), correlation ID joins.

3. **`agent-identity` reference IdP / `ref-idp`**:
   - Update `examples/demo-hub` to publish a
     `.well-known/agent-id-activity-manifest` so the canonical example
     shows the new pattern.
   - Update `examples/demo-hub` to emit the new Tier-1 categories
     (one of each) for documentation purposes — gives future adopters
     a copy-paste reference.

### Phase B — DojoZero adopts (parallel with Phase A finishing)

1. DojoZero gateway adds the three `.well-known/` endpoints with its
   real schemas.
2. PR DojoZero's manifest at
   `https://api.dojozero.live/.well-known/agent-id-activity-manifest` (live,
   not in `aip-activity` repo).
3. Update DojoZero's `gateway/_activity.py` emitters to:
   - Use the canonical `transfer.value` schema fields from §9.3.1.
   - Add `tool.use` emission with `linked_transfer_id` correlating to
     `transfer.value` for `place_bet` calls.
   - Add `model.call` emission inside the runner's ReActAgent loop
     with `linked_tool_invocation_id`.
   - Wire `approval.*` events when DojoZero gains approval flows
     (deferred until DojoZero actually has approval-gated actions).
4. Define `dojozero.bet_decision` and `dojozero.trial_outcome` Tier-2
   schemas with the new linkage IDs as their join keys.
5. First end-to-end Tier-2 emission lands when both Phase A and
   DojoZero's manifest are live.

### Phase C — sunset (3+ months later)

1. Old static YAML mode emits a deprecation warning each startup.
2. Once the second and third adopters land on manifest-based
   discovery, schedule YAML removal for 12 months out.
3. Spec rev folds this design back into `2026-03-25-agentid.en.md`
   §8.

## 13. Open questions

- **Manifest signing — required or optional?** TLS already protects fetch integrity. JWS adds defense against compromised CDN caches and lets `aip-activity` cache for longer. Lean: required, but the pre-rebrand `_kid` rules apply (Ed25519 + ES256 only).
- **Where do the three `.well-known/` paths actually go?** Ideally `https://<service_id>/.well-known/...` with `service_id` matching JWT `aud`. But many production hubs run their gateway on a sub-path (e.g., `https://api.example.com/dojozero/`). Spec the discovery URL as `manifest.discovery_base + "/.well-known/agent-id-activity-manifest"` to allow this, or insist on root-level `.well-known/` like JWKS does. I lean root-level — fewer footguns, matches existing AIP convention.
- **Schema language commitment.** JSON Schema for v1 is the bet. Do we promise backward compatibility if we add CUE/Protobuf later? The `schema_format` field lets hubs opt in, but does that fragment the consumer ecosystem? Probably yes. Defer; revisit when a hub asks for it.
- **Namespace alias spec.** §6 mentions aliases for cases like `dojozero` and `dojozero-prod` being the same product. Spec the field; defer the implementation. Need a real second adopter to find the right shape.
- **Tier-1 schema evolution.** Tier-1 schemas are server-defined and
  ship inside `agent-id-service-sdk` + `aip-activity`. How do they
  evolve? Same rules as Tier-2 (§7), just with the AIP team as the
  namespace owner: PATCH = doc-only, MINOR = additive, MAJOR =
  breaking with a 90-day deprecation window. The wire change is one
  more entry in `TIER1_CATEGORIES` (or a versioned variant); SDK
  bumps follow.
- **`model.call` at Tier-1 vs demote.** §9.3.3 leans keep with a
  minimal canonical schema. The honest counter is "every LLM provider
  already exposes billing." If at review you decide Tier-1 isn't the
  right home, demote to `<ns>.model_call` Tier-2 and let hubs that
  want it expose under their namespace.
- **`data.read` / `data.write` resolution.** §9.4 leans Option A
  (narrow to declared sensitive namespaces). Option B (demote
  entirely) is cleaner but loses the "show me sensitive-data access"
  cross-hub query. Pick one before Phase A starts so the SDK ships
  the right shape.

## 14. Decisions needed

Land this doc as a draft. Four decisions gate implementation; each is
called out so you can answer them explicitly rather than letting them
slip in by default. None of them is hard to revisit later, but
locking now is dramatically cheaper than locking after adopter #2.

**Decision 1 — Drop the static `DAIL_AGENT_ACTIVITY_API_KEYS`
hub-bearer-key mechanism (§5)?**
Yes is the right call for the protocol — it's the consistent design.
No is the right call if you're worried about the security trade-off
in `deferred-work.md §2` (an intercepted agent JWT becoming a
hub-write credential). The §5 design above mitigates that with the
outer hub-signed envelope. **Lean: drop, with the outer envelope.**
This affects every hub's deployment posture so it deserves an
explicit yes/no.

**Decision 2 — Approve the canonical Tier-1 schemas in §9?**
Specifically: §9.2 (universal lifecycle field lockdown), §9.3.1
(`transfer.value` shape), §9.3.2 (`tool.use` shape), §9.3.3
(`model.call` shape). Field-level pushback during review is normal;
this gate is "yes, canonicalize Tier-1 now" vs "leave as today and
let each hub diverge." **Lean: approve.** Lockdown cost is small
today, fragmentation cost grows monotonically.

**Decision 3 — `data.read` / `data.write` resolution?**
Option A (narrow to declared sensitive namespaces) or Option B
(demote to Tier-2). **Lean: A.** The compliance use case is real and
narrowing keeps the cross-hub query alive.

**Decision 4 — Add `approval.*` and `delegation.*` to Tier-1
(§9.5)?**
The spec already specifies the workflows (§7.4, §4.4) but the events
were never added to the Tier-1 list. **Lean: add.** Fills an obvious
gap; cleanly universal; needed for spend-cap policy joins.

For each, the safe default if you're unsure is to leave the existing
behavior in place and revisit. But the cost of revisit grows with
adopters, and we have one. So: explicit yes/no, then ship.
