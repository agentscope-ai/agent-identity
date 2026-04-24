# Approval Scenarios

Companion to the AIP protocol specification (§7.6 Authorization Grants & Approval Workflows). **Non-normative** — this document does not define requirements. Its job is to ground the two approval models in a realistic deployment so readers understand *why* the protocol is shaped the way it is.

One scenario — **Rita at Acme** — is documented here as the canonical illustration of IdP-delegated approval (spec §7.6.7). More scenarios may be added over time.

---

## 1. The Setting

**Rita** is a senior engineer at **Acme Corp**. Acme runs its own AIP identity provider at `idp.acme.com`, operated by Acme's identity team and integrated with the company's corporate SSO. Every Acme employee already has an account on it.

Three internal platform teams each run their own AIP hub:

| Hub | Team | What it gates |
|---|---|---|
| `deploy-hub.acme.com` | DevOps | Kubernetes deploys, rollbacks, scaling |
| `data-hub.acme.com` | Data Platform | BigQuery / Snowflake / S3 access |
| `obs-hub.acme.com` | SRE | Grafana panels, log exports, prod SSH |

All three hubs trust the IdP's signing key (via JWKS), but otherwise know nothing about Rita personally — only that she owns certain agents.

Rita has three agents registered at the IdP under her principal:

- `deploy-bot` — CI/CD deploys
- `analytics-bot` — ad-hoc analytics queries
- `incident-bot` — log / metric pulls during on-call

## 2. The Autonomous Path

Monday morning. Rita's agents quietly get work done:

- `deploy-bot` deploys `checkout-service` to **staging** — within `deploy-hub`'s autonomous policy.
- `analytics-bot` runs `SELECT COUNT(*) FROM orders WHERE region='us-west'` — `data-hub` permits non-PII reads.
- `incident-bot` pulls CPU graphs for `prod-us-east` — `obs-hub` freely allows dashboards.

No approval flow engages. Each hub evaluates its policy against the token's claims and decides locally. This is the baseline AIP path — Layer 1 claims + hub-side enforcement, no human in the loop.

## 3. The Approval Path (§7.6.7 Model 3)

**10:52 AM.** Rita's release pipeline wants to push `checkout-service v2.14` to **prod-us-west**.

`deploy-bot` makes the request. `deploy-hub` checks the agent's delegation claim: `{environments: [staging, prod-eu]}`. `prod-us-west` is outside that scope. Hub policy: "prod deploys outside the agent's scope require principal approval."

The hub has already fetched `idp.acme.com/.well-known/aip-configuration` and seen `approval_endpoint` advertised. It POSTs the request:

```http
POST https://idp.acme.com/aip/approvals
Content-Type: application/json

{
  "hub_id": "https://deploy-hub.acme.com",
  "agent_id": "aip:acme.com:agent_deploy_bot_rita",
  "resource": "/api/deploy",
  "action": "deploy.execute",
  "details": {
    "env": "prod-us-west",
    "service": "checkout-service",
    "version": "v2.14"
  },
  "reason": "Environment prod-us-west outside delegation scope"
}
```

The IdP stores a pending approval keyed to Rita's principal. Returns `approval_id=apr_abc123`. `deploy-hub` returns `202` to `deploy-bot`, which starts polling.

**10:52:03 AM.** Rita's phone buzzes. Push notification from the Acme IdP app:

> **deploy-bot** wants to deploy **checkout-service v2.14** to **prod-us-west**. Approve?

She taps. The app — already authenticated — shows the approval card with the request details. Face ID confirms. She taps **Approve**.

Behind the scenes:

1. Phone calls `POST idp.acme.com/aip/portal/approvals/apr_abc123/approve` with Rita's management token.
2. The IdP signs a JWT decision using the same key it uses to sign agent tokens:
   ```json
   {
     "iss": "https://idp.acme.com",
     "sub": "aip:acme.com:agent_deploy_bot_rita",
     "aud": "https://deploy-hub.acme.com",
     "type": "approval_decision",
     "approval_id": "apr_abc123",
     "decision": "approved",
     "constraints": {
       "env": "prod-us-west",
       "service": "checkout-service",
       "version": "v2.14"
     },
     "approved_by": "rita@acme.com",
     "exp": 1713801800
   }
   ```
3. The IdP stores the JWT on the approval row.

**10:52:07 AM.** `deploy-bot` has been polling `deploy-hub` every 2s. On this poll, `deploy-hub` polls the IdP once. Gets back `{status: "approved", decision_jwt: "..."}`. Verifies the JWT against JWKS (already cached from agent-token verification — no new network call). Checks `aud == deploy-hub` and `sub == agent_id`. Issues a local grant derived from the JWT's constraints.

**10:52:09 AM.** `deploy-bot` polls again. `deploy-hub` returns the grant. `deploy-bot` retries the deploy with `X-AIP-Grant: gnt_...`. `deploy-hub` consumes the grant (single-use), performs the deploy.

**10:53 AM.** Rita's phone shows a follow-up: "Deploy completed." She swipes it away and goes back to her coffee.

Meanwhile, if `analytics-bot` had also hit an approval threshold — say, querying a customer-PII table — the same dance would play out at `data-hub` with the same IdP. **Rita sees one queue across all three hubs, decides once per request, regardless of which hub asked.**

## 4. Why Rita Uses the IdP (and Not Something Else)

This is the question the scenario is built to answer. Of every place Rita could have approved from, why the IdP? Every alternative was considered by Acme's identity team and rejected.

### Per-hub approval portals

DevOps builds an approval UI. Data builds another. SRE builds another. Rita gets three inboxes, three auth flows, three UIs. Her manager configuring PTO coverage would need to do it in three places. At Acme's eventual scale (tens of hubs as more teams adopt AIP) this collapses under its own weight.

### Slack bot approvals

Quick to build. But: approval-by-emoji leaves no cryptographic audit trail. Messages get buried. Mobile UX is Slack's, not Acme's. Compliance can't verify "the approver was actually the principal." When Q4 audit arrives, there's no single query that produces the needed data.

### Email magic links

Links expire. Inbox becomes noise. No mobile push. No delegation support. Rejected.

### Cloud-native approval (AWS IAM Identity Center, Azure PIM, Aliyun Access Manager)

Each works well *inside one cloud*. But `deploy-bot` deploys to GCP, `analytics-bot` queries Snowflake, `incident-bot` uses Datadog. Three vendor UIs, three audit silos, no cross-cloud view. If Acme migrates a service, the approval UX changes with it. Unacceptable for a multi-cloud org.

### Dedicated approval SaaS

Extra vendor. Extra trust root. Extra contract. Every hub needs another integration. Unnecessary if the IdP can do it.

### What the IdP uniquely provides

1. **Rita is already authenticated there.** SSO + MFA + session. Zero additional auth friction when an approval arrives.
2. **It already signs things for these hubs.** Every agent token the hubs verify is signed by this IdP. Signed approval decisions reuse that trust root and key infrastructure — no new secrets, no new trust setup.
3. **It's the only place that knows principal↔agent.** Hubs see agent IDs; the IdP knows whose agent it is, the delegation scope, the backup approver.
4. **It's Acme's own infrastructure.** Compliance, audit retention, data residency follow existing corporate policy.
5. **One inbox across N hubs.** Scales as Acme adds hubs over time.
6. **Governance fits naturally.** "Every privileged action in Q4, who approved it, when" is one query, one database, with cryptographic per-row proof.
7. **Mobile, push, delegation (PTO coverage) live here.** Configured once, applies to every hub automatically.

## 5. The Architectural Line This Scenario Preserves

The reason IdP-delegated approval doesn't collapse AIP's federation story is the split it holds:

- **Hubs decide policy.** Only `deploy-hub` knew that `prod-us-west` was out of scope; only `data-hub` knows which tables are PII. The hub decides *when* approval is needed and *what* constraints attach to the resulting grant.
- **The IdP decides who decides.** It knows the principal, the device, the backup approver. It routes the decision and signs it. It does not evaluate the policy itself.

If this line blurs — if the IdP starts evaluating time-of-day rules, IP allowlists, or resource tags — then every hub on every cloud has to speak the IdP's policy language, and federation collapses. Spec §7.6.7.5 states this explicitly as a design invariant.

## 6. Takeaways

- **Model 1 (hub-local) is the baseline.** Use it when an organization doesn't have a unified identity story, or when approvers are outside the IdP's reach.
- **Model 3 (IdP-delegated) pays off when an organization already operates an IdP and has multiple hubs serving the same principal base.** Rita's story is the canonical case.
- **The split matters.** Hubs stay responsible for what they know (policy, enforcement). The IdP stays responsible for what it knows (people, signatures). Don't let the boundary drift.
- **Agents don't change.** They see the same 202 + poll + retry-with-grant protocol in both modes. Delegation is invisible to them — which is why a hub can switch modes based on what the IdP advertises, without any agent-side cooperation.
