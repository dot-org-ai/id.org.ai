# Phase 4 · Error pages and security prerequisites

> **For agentic workers:** run this phase from `../autopilot.md`. Write tests first: a failing test, then the fix, then green.

**Goal:**
- Browsers never see raw JSON errors again; they get the 7a/7b template with a request ID.
- API callers keep byte-identical JSON.
- Close the security gaps the new pages would otherwise build on.

**Depends on:** Phase 3 (the error screens exist).

**Read first:** `../spec/backend.md#b1` and `#b13`, `../spec/security.md`, `../spec/screens.md#7--errors`.

## Tasks

### Task 1 · Error rendering (B1)
- [ ] `wantsHtml(c)` helper: true when `Accept` includes `text/html` or `Sec-Fetch-Mode: navigate`. Test the matrix: browser GET, browser form POST, fetch with JSON, curl.
- [ ] The error catalogue `worker/ui/errors.ts` maps each code to title, reason, actions and details. It uses the 7a/7b screen components.
- [ ] Route the browser-facing error paths through it:
  - `errorResponse` call sites reachable by navigation (`/login`, `/api/callback`, `/callback`, `/oauth/authorize` GET errors before redirect validation, `/device`, `/magic-link/:flow`, `/claim/:token` for HTML);
  - the JSON 404 catch-all (HTML only for navigations).
- [ ] An unregistered `redirect_uri` or an unknown client renders 7a and never redirects. Test it with an attacker URL and assert there is no `Location` header.
- [ ] Expired and used flows (magic flow, device code, invite) render 7b.
- [ ] Rate limits (budget exhausted) render the generic template with "Too many tries. Try again in N minutes."
- [ ] Every response (HTML and JSON) carries `X-Request-Id`, and the HTML details show it.

### Task 2 · Security prerequisites (B13)
- [ ] `/admin-portal`, `/fga/*` and `/pipes/*`: require authentication plus org admin, owner or platform role. Service-binding callers authenticate as on other protected routes.
  - Add the escape hatch `LEGACY_OPEN_WORKOS_ROUTES` (default `0`; `1` restores the old behaviour).
  - Add an owner step to PROGRESS: confirm which estate workers call these routes.
  - Tests: anonymous gets 401; a member of another org gets 403; the flag at `1` restores the old behaviour.
- [ ] Org member and invite routes: check membership of `:id` (reads) and admin or owner (writes). Tests for both.
- [ ] `POST /api/session/organization`: re-fetch the role for the new org. Test that roles change with the org.
- [ ] DCR client secrets:
  - Store `sha256(secret)` and compare in constant time.
  - On a successful token request with a legacy plaintext secret, rewrite it hashed.
  - Tests: new registrations are hashed; legacy secrets still work once, then come back hashed.
- [ ] New auth routes call `resolveBrowserRedirect` in enforce mode regardless of `LOGIN_CONTINUE_POLICY`. Add a helper `resolveBrowserRedirectStrict`. Leave the global flag to the owners (D10) and record that in PROGRESS.

## Acceptance
- `pnpm gate` is green, and every new test fails without its fix (check by stashing the fix once).
- The visual diff for 7a and 7b is still 0 px.
- Navigating in a browser to `/oauth/authorize?client_id=nope` shows 7a with a request ID.

## Commit
- `feat(errors): HTML error pages for browsers, JSON unchanged for APIs`
- `feat(errors): request IDs on every response`
- `fix(security): authenticate admin-portal, fga and pipes routes`
- `fix(security): org membership checks on member and invite routes`
- `fix(auth): refresh roles on org switch`
- `fix(oauth): hash DCR client secrets`

Push.
