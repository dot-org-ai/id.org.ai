# Phase 10 · Agents and claim

> **For agentic workers:** run this phase from `../autopilot.md`. Write tests first. Check `../DECISIONS.md` D9 and D11.

**Goal:**
- A person can approve a delegated agent in the browser (5a), with a trust level, spend limit and expiry.
- Trusted agents ask per action (5b, built for phones).
- A sandbox can be claimed in one click (5c). Claim-by-commit gets a live page (5d).

**Depends on:** Phases 8 and 9 (sessions, step-up).

**Read first:** `../spec/backend.md#b9` and `#b10`, `../spec/screens.md#5--agents`, `worker/routes/aap.ts`, `worker/routes/claim.ts`, `src/server/services/agents/*`, `docs/specs/2026-05-05-tenant-agent-split-design.md`.

## Tasks

### Task 1 · Approve an agent (5a)
- [ ] `POST /agent/register` for delegated agents returns `approval_url` (`/agents/approve/:agentId`). Add `'browser'` to `approval_methods` in discovery.
- [ ] `GET/POST /agents/approve/:agentId`: owner only.
  - Store `agent-policy:{agentId}` `{trust, spendLimitCents, expiresAt, workspace, approvedAt}`.
  - Activate the agent through the existing `updateAgentStatus`.
  - Reject sets `rejected`.
- [ ] Privileged requires step-up (passkey preferred) and re-confirmation every 7 days. Lapsed Privileged agents drop to Trusted until re-confirmed.
- [ ] Enforce expiry (the agent is inactive after `expiresAt`). Store and display the spend limit (D11).

### Task 2 · Per-action approvals (5b)
- [ ] `POST /agent/approvals {kind, preview, expires_in}` creates `approval:{id}`.
  - `GET /agent/approvals/:id` lets the agent poll. Optionally emit a SET event, reusing `/agent/events` patterns.
- [ ] `GET/POST /approvals/:id`: the phone-first page with a countdown.
  - Approve or Deny. "Always allow" creates `agent-rule:{agentId}:{ruleKey}`.
  - Expiry auto-denies, and an expired request shows the expired state.
- [ ] Notification: email the link (template in phase 12; until then log the link and return it to the agent).
- [ ] Policy check: Trusted agents must create an approval for `send`, `delete` and `spend` kinds; Privileged agents skip it. Matching rules skip it.

### Task 3 · Claim (5c, 5d)
- [ ] Content negotiation on `GET /claim/:token`: HTML (5c) for browsers, JSON unchanged for API callers. It requires a session.
- [ ] `POST /claim/:token {workspace}` links the tenant, the identity and the org, sets `claimed` with the same side effects as claim-by-commit, then goes to 5a for the agent if it is pending.
- [ ] Stats: counts from the entity store (contacts, deals, workflows). Hide the stats well if counts are unavailable.
- [ ] `GET /claim/:token/repo` renders 5d. It polls the existing status endpoint and maps the states. The connector shows `connecting`, then `done`.

## Acceptance
- Tests cover:
  - register returns `approval_url`;
  - approve and reject;
  - Privileged requires step-up;
  - expiry is enforced;
  - an approval request round-trips, expires as a deny, and an "always allow" rule matches;
  - claim content negotiation;
  - one-click claim links identity and org;
  - a claimed or expired token renders correctly.
- The visual diff for 5a, 5b, 5c and 5d is still 0 px.

## Commit
- `feat(agents): browser approval with trust, spend and expiry`
- `feat(agents): per-action approvals`
- `feat(claim): one-click claim and live claim-by-commit page`

Push.
