# Phase 5 · Consent v2

> **For agentic workers:** run this phase from `../autopilot.md`. Write tests first.

**Goal:** `/oauth/authorize` renders 3a, 3b or 3c (and 7c when a workspace policy blocks the app; that check is wired in phase 11). The screen shows who is signed in, the workspace, the access level, the expandable permissions and the source row. The chosen workspace flows into every token as `org_id`. The old consent HTML is removed.

**Depends on:** Phases 3 and 4.

**Read first:** `../spec/backend.md#b2`, `../spec/screens.md#3--authorize-apps`, `../spec/security.md`, `../spec/motion.md#where-the-person-goes-next`, `../spec/logos.md`.

## Tasks

### Task 1 · Scope registry
- [ ] Create `src/sdk/oauth/scope-registry.ts` with the per-context table from `backend.md#b2`: `consent`, `consentUnverified`, `device` and `admin`, with exact copy. Expose `describeScopes(scopes, {context, resource, workspaceName, appName}) → PermissionItem[]`. It groups the OIDC scopes and puts act scopes last.
- [ ] Keep `SCOPE_DESCRIPTIONS` (`delegation.ts`) for API compatibility, derived from the registry.
- [ ] Tests:
  - every context's rows equal the mock strings (3a, 3c, 3d, 4b);
  - unknown scopes render as their raw string with a generic icon;
  - a `<script>` scope renders as text. That one is a regression guard: today's page already escapes.

### Task 2 · View model
- [ ] In `handleAuthorize`, build a `ConsentViewModel` instead of calling `renderConsentPage`:
  - client display: verified (D3) → `client_name`; unverified → host;
  - logo, `runsOnThisComputer` (a loopback redirect), redirect host and port, CIMD URL, `policy_uri` / `tos_uri` (add them to the CIMD parse, https only);
  - resource;
  - identity (name, email, avatar);
  - workspaces (via the WorkOS memberships already used by `GET /api/orgs`) and the preselected one (the `organization_id` param, otherwise the remembered one, otherwise the session's org);
  - access default;
  - variant: `basic` (only OIDC scopes), `full`, or `unverified`.
- [ ] Render through `renderPage` with the 3a/3b/3c screen. Keep the CSRF state wrapping exactly as today (`oauth.ts` `withOriginalState`). Set `form-action` to include the validated redirect origin.
- [ ] Delete the private `renderConsentPage` once the new path passes.
- [ ] Keep `generateConsentScreenHtml` (`src/sdk/oauth/consent.ts`). It is a public export of the `id.org.ai/oauth` package, so removing it would be a breaking change. Mark it `@deprecated` in its JSDoc and keep its test.

### Task 3 · POST contract
- [ ] Accept `org_id` (validated against memberships) and `access=read|act` (`read` maps to today's `approved=read`). Reject duplicates, as today.
- [ ] Store `org_id` on the authorization code and grant. Emit `org_id` in the id_token, the JWT access token (`access-token-jwt.ts`), introspection and userinfo.
- [ ] Remember consent per client per workspace (`consent:{identityId}:{clientId}:{orgId}`), with the legacy key read as "any org".
- [ ] `Accept: application/json` (fetch submit) returns `{redirect}`; a form POST keeps the 302.
- [ ] Add the step-up hook behind `FEATURE_STEP_UP` (default `0`): store a resume record, redirect to `/step-up?resume=<id>&reason=act_permissions`. Phase 9 builds `/step-up`.

### Task 4 · Client behaviour
- [ ] Use `submit.ts` with the consent form: Allow puts the connector into `connecting` and makes the button busy ("Allowing…"); then let the redirect happen (D7). Cancel posts the deny.
- [ ] The CopyButton copies the CIMD URL or `client_id`.

## Acceptance
- Existing tests stay green: `oauth-cimd-jwt-exchange`, `mcp-authorization-server*`, `oauth-delegation`, `relying-party`, consent and CSRF.
- New tests cover:
  - 3a, 3b and 3c are chosen correctly;
  - the identity and workspaces are present;
  - `org_id` round-trips into every token type;
  - the read downgrade;
  - unverified clients show the host and flipped buttons;
  - escaping;
  - JSON submit returns `{redirect}`.
- The gallery visual diff for 3a, 3b and 3c is still 0 px.
- A route-level test in the workers pool (`SELF.fetch` + `fetchMock` for WorkOS) renders `/oauth/authorize` for a fixture client. It asserts the HTML contains the same component output as the gallery fixture, built from the same props.

## Commit
- `feat(oauth): scope registry`
- `feat(oauth): consent v2 view model and screens`
- `feat(oauth): org_id on grants and tokens`
- `refactor(oauth): remove legacy consent HTML`

Push.
