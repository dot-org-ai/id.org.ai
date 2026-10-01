# Phase 8 · Sessions, accounts and workspaces

> **For agentic workers:** run this phase from `../autopilot.md`. Write tests first.

**Goal:**
- Sessions become server-side records, so they can be revoked, and several can be signed in at once.
- `prompt`, `max_age`, `organization_id` and `login_hint` behave per OIDC.
- The account chooser (2a), workspace chooser (2b), handoff (2c) and invitations (2e) work end to end.

**Depends on:** Phases 5 and 7.

**Read first:** `../spec/backend.md#b5` and `#b6`, `../spec/screens.md#2--account-and-workspace`, `../spec/flows.md`, `worker/utils/cookies.ts`, `worker/middleware/tenant.ts` (`readSessionSignIn`).

## Tasks

Everything in Tasks 1–2 is behind `FEATURE_SESSIONS_V2` (default `0`). With it off, sessions behave exactly as today, and the who row's Switch link goes to `/login?prompt=login`.

### Task 1 · Session records
- [ ] Store `session:{sid}` and the index `sessions-by-identity:{identityId}`, as `backend.md#b5` describes.
- [ ] Add `sid` to the session JWT.
- [ ] Validate the record on every authenticated request. A short in-isolate cache is fine. A revoked sid gets 401 on the next request.
- [ ] Migration: a valid legacy JWT without `sid` gets a record created on its next request (lazy). There is no forced sign-out.

### Task 2 · Multiple accounts
- [ ] Cookie `id_accounts` holds up to 5 sids; `auth` stays the active one.
- [ ] "Use another account" (`/login?prompt=login`) adds a session rather than replacing one.
- [ ] `GET/POST /account/choose` renders 2a.
  - Choosing an account switches `auth` (re-minted from the record) and sets `remembered:{browserId}:{clientId}`.
  - "Sign out of all accounts" posts to `/signout` with scope `browser` (phase 9 completes it; wire a minimal version now).
- [ ] In `/oauth/authorize`:
  - `prompt=select_account` forces 2a, and so do 2+ sessions with nothing remembered for the client;
  - `prompt=login` forces 1a;
  - `prompt=none` never renders, and returns `login_required`, `account_selection_required` or `consent_required`;
  - `max_age` forces re-authentication;
  - `login_hint` preselects.

### Task 3 · Workspaces
- [ ] Replace the org picker: when WorkOS returns `organization_selection_required` (`/api/callback` in `worker/routes/auth.ts`, and `worker/routes/magic-link.ts`), render 2b in sign-in mode, posting to the existing `POST /api/org-select` (`pendingAuthenticationToken`, `state`, the org). Keep `org-picker.ts` until this passes; phase 13 deletes it.
- [ ] `GET/POST /workspace/choose` renders 2b, following the skip rules in `backend.md#b6`.
  - Remember the choice in `org-pref:{identityId}:{clientId}`.
  - The chosen org flows into the grant's `org_id` (shared with phase 5).
- [ ] `/workspace/new`: a derived screen (1d layout, Workspace field only) that calls the existing org creation and returns to 2b with the new org selected.
- [ ] Unify the personal org role to `owner` (migrate lazily).

### Task 4 · Handoff and invitations
- [ ] 2c: after an interactive step on id.org.ai, the final redirect to the app is a 200 page.
  - Connector in `connecting`.
  - `location.replace` in the next frame.
  - Meta refresh after 1s.
  - Foot link to the same URL.
  - Never shown for silent flows.
- [ ] `GET/POST /invite/:token` renders 2e.
  - WorkOS invitation lookup by token, accept and decline.
  - Email binding: a mismatch disables Join and emphasises Switch.
  - Expired invitations get 7b.

## Acceptance
- New tests cover:
  - two sign-ins give two sessions;
  - the chooser lists both, switches, and remembers per client;
  - each `prompt` value;
  - `max_age`;
  - a revoked sid is rejected;
  - the legacy JWT migration;
  - the chooser skip rules;
  - `org_id` from 2b in tokens;
  - invite accept, decline, mismatch and expired.
- The visual diff for 2a, 2b, 2c and 2e is still 0 px.
- A route-level flow test in the workers pool: sign in twice with two fixture users, open an OAuth request with `prompt=select_account`, pick the second, and land back with that identity.
- `organization_selection_required` at sign-in renders 2b and completes through `/api/org-select`.

## Commit
- `feat(session): server-side session records`
- `feat(session): multiple accounts and the chooser`
- `feat(oauth): prompt, max_age, login_hint`
- `feat(workspace): chooser and remembered choice`
- `feat(auth): handoff page`
- `feat(workspace): invitations`

Push.
