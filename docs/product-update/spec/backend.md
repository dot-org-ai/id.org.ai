# Backend: what each screen needs from the server

This file was written from an audit of the live code: branch `release/main-with-security-fixes`, commit `dbadae8`, which `product-update` starts from. Each section gives:

- **Today**: what exists, with file and symbol so you can find it after lines move.
- **Build**: the requirement.
- **Contract**: routes, fields and storage.
- **Done when**: the tests that prove it.

Line numbers drift, so search for the symbol.

Storage today is key/value in Durable Objects (the `oauth` shard of `IdentityDO`), plus KV `SESSIONS`. There is no D1 database. New records follow the same pattern: typed keys, a TTL where the record expires, and `takeOnce` / `consumeBudget` (`src/server/do/Identity.ts`) for single-use and rate limits.

---

<a id="b0"></a>

## B0 · Rendering foundation (frontend plumbing)

**Today**
- Every page is a template literal with inline `<style>`, returned as `new Response(html)`:
  - `worker/views/provider-picker.ts`
  - `worker/views/org-picker.ts`
  - `renderConsentPage`, `renderDeviceVerificationPage` and `deviceApprovedHtml` in `src/sdk/oauth/provider.ts`
  - the `page()` and `codeForm` helpers in `worker/routes/magic-link.ts`
- `src/sdk/oauth/consent.ts` `generateConsentScreenHtml` is unused by the worker.
- There is no JSX, no shared layout, and no client JS bundle.
- Root `tsconfig.json` excludes `worker/`, so `pnpm typecheck` never checks the worker.
- `predeploy` runs `build:site`, which does `rm -rf worker/public` and copies `site/out` in. Anything placed directly in `worker/public/` is wiped.
- The WorkOS API base URL is hard-coded as `https://api.workos.com` in about 30 places (`src/sdk/workos/upstream.ts`, `keys.ts`, `pipes.ts`, `scim.ts`). That makes browser-level tests against a stub impossible.

**Build**
- Server components with **`hono/jsx`** (Hono is already a dependency):
  - Add `worker/tsconfig.json` with `"jsx": "react-jsx", "jsxImportSource": "hono/jsx"`, `.tsx` views and strict mode.
  - Use the wrangler-generated `worker/worker-configuration.d.ts` as the single source of runtime types. Don't add `@cloudflare/workers-types` to `types` as well, or the declarations will be duplicated.
  - Exclude `worker/ui/client/`, which gets its own `tsconfig.json` with the DOM lib.
  - Add `pnpm typecheck:worker` and make `pnpm typecheck` run both.
  - Wrangler's esbuild honours the tsconfig JSX settings. Confirm with `wrangler deploy --dry-run`.
- New UI module `worker/ui/` (see `../prompts/01-foundation.md` for the file map):
  - `tokens.css` and `ui.css`, concatenated and served at `/auth/ui.<hash>.css`.
  - Client scripts served at `/auth/<name>.<hash>.js`.
  - Fonts at `/fonts/geist/*.woff2`.
  - Anything in `worker/ui/static/` (for example first-party brand marks in `static/brand/`) is copied to the same path under `worker/public/`.
- Static asset source lives outside `worker/public`:
  - `worker/ui/static/` is copied into `worker/public/` by a new `build:ui` script.
  - `predeploy` becomes `build:site && build:ui && build:dash`, so the site build can't wipe it.
  - Client TS is bundled with esbuild (already a transitive dependency via wrangler; add it explicitly).
  - Every asset gets a content hash in its file name.
  - The ASSETS binding doesn't set long-lived caching by itself. A small worker route for `/auth/*` and `/fonts/*` calls `c.env.ASSETS.fetch(c.req.raw)` and adds `Cache-Control: public, max-age=31536000, immutable` to 200 responses.
- Fonts: `geist@1.7.2`, files `dist/fonts/geist-sans/Geist-Variable.woff2` and `dist/fonts/geist-mono/GeistMono-Variable.woff2`. These are byte-identical to `../mocks/fonts/`. Add `geist` as a devDependency and copy the two files in `build:ui`.
- A shared `renderPage()` returns the `Response` with the security headers from `security.md`.
- **Design gallery**: `GET /__design` (index) and `GET /__design/:slug?state=` render every screen with fixture data identical to the mock text.
  - Enabled only when `env.DESIGN_GALLERY === '1'`: set in `worker/.dev.vars`, never in `wrangler.jsonc`.
  - The visual-diff harness compares this against the mocks.

- **Test seam**:
  - Read the WorkOS base from `env.WORKOS_API_BASE` (default `https://api.workos.com`) in one helper, and use it everywhere.
  - Add a local stub (`test-visual/workos-stub.mjs`) for browser-level flow tests against `wrangler dev`.
  - Request-level flow tests run in the workers vitest pool with `SELF.fetch` + `fetchMock` (the existing pattern in `test/auth-callback-device-flow-regression.test.ts`).
  - **Never run `pnpm test:e2e`**: it targets production id.org.ai with real keys from `.env`.

**Done when**
- `pnpm typecheck` covers `worker/`.
- `wrangler deploy --dry-run` bundles.
- `/auth/ui.<hash>.css` (with the immutable cache header), `/fonts/geist/*` and `/__design` load in `wrangler dev`.
- `/__design` returns 404 without the flag.

---

<a id="b1"></a>

## B1 · Error pages and request IDs

**Today**
- `errorResponse` (`src/sdk/errors.ts`) returns JSON `{error, error_description}` everywhere.
- Login and callback errors are JSON (`worker/routes/auth.ts`).
- The catch-all 404 is JSON (`worker/index.ts`).
- An unregistered `redirect_uri` correctly returns 400 without redirecting (`handleAuthorize`), but as JSON.
- There are no request IDs.

**Build**
- A request-ID middleware:
  - Use `cf-ray` when present, otherwise `req_` plus 8 random base62 characters (the mock shows `req_7Hk2Qp9w`).
  - Set it as the `X-Request-Id` response header and include it in logs and audit records.
- `wantsHtml(c)`: true for GET or POST from a browser navigation (`Accept` includes `text/html`, or `Sec-Fetch-Mode: navigate`).
  - For those requests, render the error template (7a/7b/7c styles).
  - API callers keep today's JSON byte-for-byte. Existing tests must stay green.
- Error catalogue `worker/ui/errors.ts` maps codes to screen copy:
  - `invalid_request` (redirect not registered), `invalid_client`, `invalid_client_metadata` (CIMD), `expired` (flow, code, invite, approval), `already_used`, `rate_limited`, `csrf`, `blocked_by_policy`, `server_error`, `not_found`.
- Developer details show `error`, `reason`, `client`, `redirect` (when it was rejected) and `request` (the request ID), with a copy action.
- Never reflect unescaped input. Never render a rejected `redirect_uri` as a link.

**Done when**
- Each catalogue entry renders in the gallery and matches the mocks for 7a, 7b and 7c.
- `curl -H 'Accept: application/json'` still gets the old JSON.
- Browser navigation gets HTML with `X-Request-Id`.

---

<a id="b2"></a>

## B2 · Consent v2 and the scope registry

**Today**
- `renderConsentPage` (`provider.ts`) receives `client`, `params` and the CIMD display rules:
  - For CIMD it shows the host as the name, plus "Calls itself …".
  - It also shows "Returns to", "Access for" and `SCOPE_DESCRIPTIONS`.
  - It sets XFO DENY, `frame-ancestors 'none'` and `no-store`.
- It does **not** receive the signed-in identity or the organisation.
- POST contract (`worker/routes/oauth.ts`, `POST /oauth/authorize`):
  - The hidden fields are `client_id, redirect_uri, scope, state, code_challenge, code_challenge_method, nonce, resource`.
  - `approved` is `true`, `read` (which downgrades `sb:do` to `sb:read`) or anything else (deny).
  - `state` is base64url `{csrf, s}`.
  - CSRF is a double-submit: the `__csrf` cookie, plus `csrf:<token>` in the DO, single-use.
- Consent is recorded at `consent:{identityId}:{clientId}` → `{scopes, createdAt}`.
- Grants are listed and revoked at `GET /api/grants` and `POST /api/grants/revoke`, with tombstones checked at every use.
- `sb:*` scopes:
  - They require an interactive consent: no X-Issuer, no device flow, never the trusted-account client.
  - Trusted clients still see consent for them.
- CIMD: `src/sdk/oauth/cimd.ts` and `worker/utils/client-metadata.ts` (https `logo_uri` only; loopback redirects match any port and always get consent).

**Build**
- **Scope registry** `src/sdk/oauth/scope-registry.ts`. It is the single source for permission rows, with **copy per context**, because the mocks word the same scope differently by context. `describeScopes(scopes, {context, resource, workspaceName, appName})`, where `context` is `consent | consentUnverified | device | admin`.
  - Exact copy, from the mocks. `{res}` is the resource host, `{ws}` the workspace and `{app}` the app:

    | Scope | Context | Icon | Title | Detail | Act note |
    |---|---|---|---|---|---|
    | `openid profile email` (one grouped row) | consent | user | See your name, email and photo | Your profile from id.org.ai. Never your other apps or workspaces. | — |
    | | consentUnverified | user | See your name, email and photo | Your profile from id.org.ai. | — |
    | | device | user | See your name and email | Shown in the CLI as who is signed in. | — |
    | `sb:read` | consent | search | Search and read your Startups on {res} | Read-only search and fetch across Startups in {ws}. | — |
    | | consentUnverified | search | Search and read your Startups on {res} | Read-only. It can't change anything. | — |
    | | admin | search | Search and read Startups on {res} | Read-only search and fetch across Startups in {ws}. | — |
    | `sb:do` | consent | pen (accent) | Run Verbs that change your Startups | Create, update and run Verbs. Every change is logged under your name. | Changes are made in your name. |
    | | admin | pen (accent) | Run Verbs that change Startups | Create, update and run Verbs, logged under each person's name. | Changes are made in each person's name. |
    | `offline_access` | consent | clock | Stay connected while you're away | Keeps a refresh token until you revoke it in Connected apps. | — |
    | | device | clock | Stay signed in on this device | Until you sign out or revoke it in Connected apps. | — |
    | `auto.dev:api` (first-party CLI scope) | device | terminal | Use the auto.dev API as you in {ws} | Calls count against {ws}'s auto.dev plan. | — |

  - A context without a row falls back to the `consent` row.
  - Each row's "scope" line is the raw string plus ` · resource {resource}` when there is one (`openid profile email`, `sb:read · resource https://api.sb`, `offline_access`, `auto.dev:api`).
  - Unknown scopes get a generic row (icon `globe`, title = the raw scope string, escaped).
- **Keep escaping.** `renderConsentPage` already escapes every scope string (`esc(SCOPE_DESCRIPTIONS[s] ?? s)`). JSX keeps that by default. Keep the regression test that a `<script>` scope renders as text.
- Pass the identity (name, email, avatar) and the person's workspaces into the consent view.
- **Workspace select** on consent:
  - The chosen `org_id` posts with the form, is validated against the person's memberships, and is stored on the grant and the authorization code.
  - It is emitted as the `org_id` claim in the id_token, the JWT access token (`access-token-jwt.ts`), introspection and userinfo (B6).
- **Access level radio** (Read only / Read and act):
  - It maps onto the existing `approved=read` downgrade.
  - Default to `act` only when `sb:do` was requested, and show the accent marker.
- **Source row**:
  - Show the CIMD URL, or `client_id` for DCR, with copy.
  - Its details hold Runs on ("This computer" for loopback redirects, otherwise the redirect host), Returns to (redirect host:port), Identified by (the CIMD host), Verified (Yes/No), and the client's `policy_uri` / `tos_uri` when present. Add those two fields to the CIMD parse; https only.
- **Verified vs unverified** (D3):
  - Verified means a first-party seeded client (`src/sdk/oauth/clients.ts`), or a CIMD host in the `VERIFIED_CLIENT_HOSTS` env list.
  - Everything else is unverified. That includes every DCR client.
  - Unverified clients show the host as the name, the warning callout, and the flipped buttons (3c).
- **Identity-only requests** (`openid profile email`) render 3b instead of 3a.
- **Remember consent per client per workspace**: key `consent:{identityId}:{clientId}:{orgId}`. Migrate the existing key by treating it as "any org" until it is next re-consented.
- **Step-up hook**: if the grant includes `sb:do` and `now - auth_time > 600s`, store the pending consent as a resume record (single-use, 10-minute TTL), redirect to `/step-up?resume=<id>&reason=act_permissions`, then resume (B5).
- **Fetch submit**: `POST /oauth/authorize` with `Accept: application/json` returns `{redirect}` instead of a 302, so the connector can run. A form POST keeps the 302.

**Done when**
- Existing consent and CIMD tests stay green.
- New tests cover: the identity and workspaces render; `org_id` round-trips to the code, token and introspection; `access=read` downgrades; an unverified client gets the flipped buttons and the host as its name; each registry context renders its exact copy; scope strings stay escaped; a stale `auth_time` with `sb:do` redirects to step-up and resumes.

---

<a id="b3"></a>

## B3 · Device flow v2

**Today**
- `POST /oauth/device` → `handleDeviceAuthorization`:
  - The user code is 8 characters from `ABCDEFGHJKLMNPQRSTUVWXYZ23456789`, with no separator (`generateUserCode`).
  - `verification_uri` is `https://id.org.ai/device`. `verification_uri_complete` is `…/device?user_code=X`.
  - Codes last 30 minutes, with a 5-second interval.
  - `sb:*` scopes and CIMD clients are refused.
- `ALL /device` → `handleDeviceVerification`:
  - It renders a code form (`renderDeviceVerificationPage`).
  - One POST `{user_code, approved}` approves or denies.
  - There is **no CSRF token** (only an Origin check that passes when Origin is absent), no client name, no scopes and no device metadata.
- Polling handles `authorization_pending`, `access_denied` and `expired_token`. `slow_down` is not implemented.

**Build**
- Display the code as `XXXX-XXXX` and accept input with or without the hyphen or spaces (stored without them). Keep the alphabet.
- Make `verification_uri_complete` `…/device?code=XXXX-XXXX` and keep accepting `user_code=`.
- **Device metadata** captured at `POST /oauth/device`:
  - `os`: parsed from the User-Agent, or a `device_name` the CLI sends. Add this optional parameter to the CLI.
  - `city`, `region`, `country`: from `request.cf`.
  - `ip` (stored, never shown).
  - `requestedAt`.
  - Store these on the device record. Show "macOS · Miami, FL · requested 1 min ago".
- Confirm page data: client display name and icon, permissions from the scope registry, the signed-in account, workspaces.
- **Decision endpoint**: `POST /device/decision {code, org_id, decision: 'approve'|'deny', csrf}`.
  - It requires a CSRF token (double-submit, like consent) and a session.
  - It returns JSON `{ok:true, state:'approved'|'denied'}` for fetch, or a 303 to the done or cancelled page for a form post.
  - It is idempotent for the same decision, and returns `{ok:false, error:'expired'|'already_used'}` otherwise.
- Store `org_id` on the approval and carry it into tokens (B6).
- Add `slow_down` (RFC 8628 §3.5) using the existing unused `lastPollTime`.
- Add `POST /device/:id/revoke` ("Sign this device out") revoking that grant family. The dashboard UI stays out of scope.
- **CLI output** (`src/sdk/cli/`, `id.org.ai login`) matches mock 4a. Print the verification URL with the code, open the browser, add the `c`/`o` keys, show the waiting line with expiry, and print the success block.

**Done when**
- Tests cover: the hyphenated code is accepted; metadata is stored and rendered; the decision without CSRF is refused; approve then poll gives tokens with `org_id`; deny then poll gives `access_denied`; `slow_down` works; an expired code gives the 7b content.
- The visual diff passes for all six 4b states and 4c/4d.

---

<a id="b4"></a>

## B4 · Sign-in v2 (email first)

**Today**
- `GET /login` renders the provider picker, with buttons for GitHub, Google, Microsoft, Apple and Email. Microsoft, Apple and Email go to hosted AuthKit (`provider: 'authkit'`). `VALID_PROVIDERS` already accepts `MicrosoftOAuth` and `AppleOAuth`.
- `login_hint` is sanitised and forwarded.
- Login state is bound server-side: `login-csrf:` records (`LoginCsrfRecord`), the continue policy (`worker/utils/relying-parties.ts`, `resolveBrowserRedirect`), and an `_auth_code` bounce only to https origins.
- `finishWorkOSSignIn` (`worker/routes/auth.ts`) mints the session JWT with `amr`, `idp` and `auth_time`.
- **Magic link**:
  - `POST /api/magic-link` is for confidential, listed clients only. `GET/POST /magic-link/:flow` has its own inline page.
  - It uses WorkOS Magic Auth to send the 6-digit code, and verifies with the `magic-auth:code` grant (`src/sdk/workos/upstream.ts`).
  - Records are `magic-flow:{id}`, bound to the cookie `__mlf`.
  - Budgets (`worker/utils/code-guard.ts`): 5 sends per email per hour, 5 guesses per flow, 5 per email per 15 minutes, 50 per IP per hour.
- A WorkOS callback `error` returns JSON 400. An exchange failure returns 502.
- The email-code UI on `feat/upstream-microsoft-federation` (`worker/views/email-code.ts`, `/federation/email/*`) is **not** on this branch. Do not merge it; this phase replaces it.

**Build**
- `GET /login` renders 1a. `POST /login/email` takes `{email, continue, csrf}`:
  1. Normalise the email and apply the continue policy.
  2. **SSO discovery**: find the organisation by email domain (WorkOS organisation domains). If it has an active SSO connection, 303 to `/login/sso`. Cache domain lookups for 10 minutes.
  3. Otherwise create a magic flow with WorkOS Magic Auth, using a new budget path `'web'` (the same atomic budgets as `'ml'`, counted per path). Then 303 to `/login/code/:flow`.
- `GET/POST /login/code/:flow` renders 1b and verifies. It reuses the `magic-flow` records, cookie binding, `takeOnce` and the guess budget. The existing `/magic-link/:flow` renders the same 1b component.
  - Resend: `POST /login/code/:flow/resend`, under the send budget.
  - The email link (8a) points at `/login/code/:flow?code=NNNNNN`, which prefills the boxes.
- `GET /login/sso` renders 1c. Its button calls WorkOS authorize with `organization_id` (or `connection_id`) and `login_hint`.
- **Provider failure → 1f**: map WorkOS / IdP error codes to one sentence each, and keep the raw code in developer details.
- **Two-step**: when WorkOS authenticate returns an MFA challenge, go to 6d. The mechanics are in B7, but it ships in phase 7 with sign-in, because once email codes leave hosted AuthKit an MFA challenge can happen on this path.
- **Microsoft and Apple**: switch to direct providers once they are enabled in the WorkOS dashboard (an owner step). Until then they keep `provider=authkit`.
- **Passkey button with `FEATURE_PASSKEYS=0`**: hand off to hosted AuthKit (`/login?provider=authkit&continue=…`), which supports passkeys (D2).
- **Last used provider**: set the `id_last_provider` cookie (1 year, Lax, no PII) after sign-in; it shows the pill on 1a.
- **Branded sign-in (1g)**: add `brand?: { name, mark }` to first-party client definitions (`clients.ts`). Render it for a matching `client_id` only.
- **First run (1d)**: after `finishWorkOSSignIn` creates a new identity, redirect to `/welcome?continue=`.
  - `POST` updates the WorkOS user's first and last name and renames the personal organisation (`ensurePersonalOrg`).
  - "Not you?" signs out and returns to 1a.
- **Passkey sign-in** on 1a: B7, behind `FEATURE_PASSKEYS`.

**Done when**
- Tests cover: an SSO domain goes to 1c; other domains get a flow and 1b; a wrong code consumes the budget; the 6th guess is refused; the `?code=` prefill works and never auto-submits; resend is limited; a provider error renders 1f with a request ID; a first sign-in goes to 1d and then continues; branded sign-in appears only for listed first-party clients.
- All existing `login-state-binding`, `magic-link-*`, `code-send-budget` and `signin-code-bruteforce` tests stay green.

---

<a id="b5"></a>

## B5 · Sessions v2: multiple accounts, prompt, max_age, step-up

**Today**
- The session is a stateless RS256 JWT in the `auth` cookie (chunked when large; 30 days).
- Its claims include `sub, email, name, org{}, roles, amr, idp, auth_time`.
- There is no server-side session record, so a session can't be revoked before it expires.
- There is one account per browser. `/login` skips straight to `continue` when any session exists.
- There is no `prompt` or `max_age` handling. `auth_time` and `amr` are emitted but never enforced.

**Build** (behind `FEATURE_SESSIONS_V2`, default off; with it off, sessions behave exactly as today)
- **Server-side session records**:
  - `session:{sid}` → `{identityId, createdAt, lastSeenAt, authTime, amr, idp, ua, city, revokedAt?}`.
  - Index `sessions-by-identity:{identityId}` (a list of sids).
  - Add `sid` to the session JWT and check it against the record on every request (the record can be cached briefly in the isolate).
  - This makes "sign out everywhere" (B8) and per-device revoke possible.
- **Multiple accounts**:
  - Cookie `id_accounts` (HttpOnly, Secure, Lax) holds an ordered list of up to 5 `sid`s; `auth` stays the active session.
  - Choosing an account switches `auth` to that sid's JWT, re-minted from the record.
  - `remembered:{browserId}:{clientId}` → sid, for "last used here" and to skip 2a next time.
- `/oauth/authorize` honours:
  - `prompt=login`: force 1a. A new session is added, not replacing the others.
  - `prompt=select_account`: force 2a.
  - `prompt=none`: never render a page; return `login_required`, `account_selection_required` or `consent_required` to the redirect.
  - `max_age=N`: re-authenticate if `now - auth_time > N`.
  - `organization_id`: preselect, and skip 2b if the person is a member.
  - `login_hint`: prefill 1a, and pick the matching session in 2a.
- **Step-up (6a)**:
  - `GET /step-up?resume=<id>&reason=<code>` shows the factors the person has: passkey (B7) and email code (B4 flow in step-up mode, sent to the session's email). `reason` is an enum (`act_permissions`, `privileged_agent`, `max_age`, `sign_out_everywhere`) mapped to catalogue copy.
  - On success it updates `authTime` and `amr` on the session record and re-mints the JWT.
  - `resume` must be the id of a single-use server-side resume record, never a URL.
  - Triggers: consent with `sb:do` (10 minutes), approving a Privileged agent (5a), and `max_age`.
- **Handoff (2c)**: wraps the final cross-origin redirect after an interactive step (see screens).

**Done when**
- Tests cover: two sign-ins give two sessions; 2a lists both; choosing switches the active session and remembers it for the client; `prompt=select_account` / `login` / `none` behave per OIDC Core §3.1.2.1; `max_age` forces re-auth; a stale `auth_time` with `sb:do` triggers step-up, then resumes; a revoked sid is rejected on the next request.

---

<a id="b6"></a>

## B6 · Workspaces, first run, invitations

**Today**
- Org selection at sign-in happens only when WorkOS returns `organization_selection_required` (`worker/views/org-picker.ts`, `POST /api/org-select`).
- `GET /api/orgs` lists `{id, name, role, domains}`, and `POST /api/orgs` creates.
- `POST /api/session/organization` switches the session org. **Bug**: it keeps the previous org's roles.
- `ensurePersonalOrg` creates a personal org on the first sign-in, with role `admin`, while `POST /api/orgs` uses `owner`.
- There is no `org_id` in the id_token or the JWT access tokens. Userinfo returns the identity's `organizationId`, which is set only at first login.
- Invitations are sent through WorkOS (`sendOrgInvitation`). Accept and decline are hosted by WorkOS; there is no local route.
- The org member and invite routes check only authentication, not membership of `:id`.

**Build**
- **Workspace chooser (2b)**:
  - `GET/POST /workspace/choose`.
  - It also replaces `worker/views/org-picker.ts` at sign-in. When WorkOS returns `organization_selection_required` (`/api/callback` in `worker/routes/auth.ts`, and `worker/routes/magic-link.ts`), render 2b in sign-in mode, posting to the existing `POST /api/org-select`. Only then can the old org picker be deleted.
  - It is skipped when there is one workspace, an `organization_id` hint the person is a member of, or a remembered choice `org-pref:{identityId}:{clientId}`.
  - Role labels: owner, admin, member, personal ("Just you").
- **`org_id` claim** in the authorization code, id_token, JWT access token, introspection and userinfo. Use the workspace chosen for that grant (2b, 3a select, 4b select), not the session's last org.
- Fix the org-switch roles bug: re-fetch the membership role for the new org.
- Unify the personal org role to `owner`.
- **First run (1d)**: see B4.
- **New workspace** (`/workspace/new`): calls `POST /api/orgs`, then returns to the chooser with the new org selected.
- **Invitations (2e)**:
  - `GET /invite/:token` looks up the WorkOS invitation by token.
  - Join accepts it (WorkOS accept-invitation API, or authenticate with `invitation_token`) and adds the membership. Decline revokes or ignores it, per WorkOS capability.
  - Bind the invite to its email: if the session email differs, disable Join and show Switch.
  - Expired invitations show 7b.
- **Authorisation fix**: org member and invite routes must check the caller is a member, and an admin or owner for writes, of `:id`.

**Done when**
- Tests cover: chooser skip rules; `org_id` in every token type; remember per client; role refresh on switch; an invite email mismatch disables Join; a non-member gets 403 on an org route.

---

<a id="b7"></a>

## B7 · Passkeys, two-step, account linking

**Today**
- Passkeys and TOTP exist only inside hosted AuthKit. There is no linking UI.
- WorkOS: **passkeys are available only in the hosted AuthKit UI**, with no headless API. TOTP MFA has an API for custom UIs.
  - https://workos.com/docs/user-management/passkeys
  - https://workos.com/docs/authkit/mfa

**Build**
- **Two-step (6d)**:
  - When the WorkOS authenticate call returns an MFA challenge (pending authentication token plus factors), create a flow `mfa-flow:{id}` (cookie-bound, 10 minutes, 5 guesses).
  - Render 6d and authenticate with the TOTP code through the WorkOS MFA API.
  - "Use a recovery code": see D8.
- **Passkeys** (D5, default: in-house WebAuthn behind `FEATURE_PASSKEYS`):
  - Use `@simplewebauthn/server`. Recent major versions use WebCrypto and target edge runtimes; confirm with a 30-minute spike in `wrangler dev` before building on it. If it fails, use the WebAuthn verification in `@oslojs/webauthn`.
  - Store `passkey:{identityId}:{credentialId}` → `{publicKey, counter, transports, createdAt, lastUsedAt, name}`.
  - RP ID `id.org.ai`. Origins: the auth hosts in `OWN_ORIGINS`.
  - Sign-in with a passkey mints the session directly (`amr:['passkey']`, `idp:'passkey'`). WorkOS is called only to load the user and memberships.
  - 6c offers registration once after a code sign-in.
  - 6a uses a passkey as the step-up factor.
- **Account linking (1e)** (D6):
  - Detect when a completed sign-in's verified email matches an existing identity with a different identity id (for example a claim-by-commit GitHub identity).
  - Require sign-in with the existing method within 10 minutes, then link (store the new WorkOS user id or provider id on the identity).
  - Never merge silently.

**Done when**
- Tests cover: the TOTP flow with a mocked WorkOS challenge; passkey register and authenticate with SimpleWebAuthn test vectors; the linking flow requiring both proofs; the passkey flag off hides every passkey control.

---

<a id="b8"></a>

## B8 · Sign out v2

**Today**
- `GET/POST /logout` and `POST /api/logout` clear the cookies and the stored WorkOS refresh token.
- They don't log out the WorkOS session, and they don't revoke OAuth tokens.
- There is no `end_session_endpoint`.
- `GET /logout?return_url=` goes through `resolveBrowserRedirect`. **Prod runs `LOGIN_CONTINUE_POLICY=report`, so unlisted URLs are still followed** (B13).

**Build**
- `GET /signout` renders 6b; `POST /signout {scope: 'app'|'browser'|'everywhere', client_id?, return_url?}`:
  - **app**: revoke the grant families of `client_id` for this identity, and drop that client's remembered sid.
  - **browser**: revoke the active and listed sids, clear the cookies, and call WorkOS session logout.
  - **everywhere**: revoke every sid for the identity and every refresh family. An everywhere sign-out requires a fresh `auth_time` (≤10 minutes), or go to step-up first.
- Advertise `end_session_endpoint` (OIDC RP-Initiated Logout 1.0) at `/oauth/end_session`:
  - Validate `id_token_hint` and `post_logout_redirect_uri` against the client's registered URIs.
  - Show 6b when the person has other apps signed in. Otherwise sign out silently and redirect.
- Keep `GET /logout` for existing apps unchanged in behaviour (it is the legacy path).

**Done when**
- Tests cover each scope's effect on sessions and tokens; `end_session` validation; legacy `/logout` behaving as before.

---

<a id="b9"></a>

## B9 · Agents: approval, trust, spend, expiry, per-action approvals

**Today**
- AAP routes in `worker/routes/aap.ts`: register (delegated agents start `pending`), status, revoke, reactivate.
- Discovery advertises `approval_methods: ['claim_by_commit']`.
- Human approval exists only as the DO RPC `updateAgentStatus`.
- There are no trust levels per agent (L0–L3 exist on identities).
- `spendCap` is a type only. Agent lifetimes are stored but not enforced.
- There are no per-action approvals and no push.

**Build**
- `GET /agents/approve/:agentId` renders 5a for the owning identity. `POST` takes `{trust: 'sandboxed'|'trusted'|'privileged', spend_limit_cents|null, expires_at|null, workspace}`.
  - **Privileged** requires step-up (passkey preferred), and the approval must be re-confirmed every 7 days.
  - Store `agent-policy:{agentId}`; activate the agent; add `approval_methods: ['claim_by_commit','browser']` to discovery.
  - Return the approval URL from `POST /agent/register` for delegated agents.
- **Enforcement**:
  - Expiry: the agent is inactive after `expires_at`.
  - Spend limit: checked where spend happens; the hook lives in the payment module. Until spend exists, store and display it only, and note that in PROGRESS.
  - Trust:
    - **Sandboxed**: sandbox tenant only.
    - **Trusted**: acts, but send, delete and spend need an approval.
    - **Privileged**: no per-action approval.
- **Approval requests (5b)**:
  - An agent creates `POST /agent/approvals {kind, preview, expires_in}`, which gives `approval:{id}` → `{agentId, identityId, kind, preview, status, expiresAt, rule?}`.
  - The person opens `/approvals/:id` and approves or denies (with an optional "always allow" rule `agent-rule:{agentId}:{ruleKey}`).
  - The agent polls `GET /agent/approvals/:id` or receives a SET event.
  - Unanswered requests expire as `denied`.
- **Notification**: email (B12) with the link. Push is D9, default email-only.

**Done when**
- Tests cover: delegated register returns the URL; 5a approve sets the policy and status; Privileged requires step-up; an expired agent is refused; an approval request round-trips; expiry auto-denies; "always allow" skips the next matching request.

---

<a id="b10"></a>

## B10 · Claim

**Today**
- Claim-by-commit works:
  - `POST /api/provision` returns `clm_…`.
  - `GET /claim/:token` returns JSON instructions.
  - `GET /api/claim/:token/status` returns `unclaimed | pending | claimed | frozen | expired`.
  - Completion comes through the GitHub Action OIDC (`POST /api/claim`) or the webhook (`POST /webhook/github`).
- There is no browser claim, and a claim is never linked to a WorkOS user or org.

**Build**
- `GET /claim/:token` returns HTML (5c) when `Accept` includes `text/html`; JSON stays for other callers.
  - It requires a session (it goes through sign-in when there is none).
  - It shows tenant stats: contact, deal and workflow counts from the entity store.
  - `POST /claim/:token {workspace}` links the tenant, the identity and the chosen org. It sets the claim status to `claimed` (with the same side effects as claim-by-commit: level 2, `claimStatus`) and keeps the agent working with the access chosen next (redirect to 5a for the agent).
- `GET /claim/:token/repo` renders 5d.
  - It polls the status endpoint and maps `unclaimed`→waiting, `pending`→pending on a branch, `claimed`→claimed.
  - The connector goes `connecting` → `done` when the claim lands.

**Done when**
- Tests cover: HTML vs JSON negotiation; one-click claim linking identity and org; a claimed token showing the claimed state; an expired token showing 7b.

---

<a id="b11"></a>

## B11 · Workspace app policy (7c, 3d)

**Today**: there is no org-level app allow-list, request flow or admin approval.

**Build**
- `org-policy:{orgId}` → `{mode: 'open'|'approved_only', approved: {clientKey: {scope: 'everyone'|string[] userIds, scopes}}}`. The default is `open`, so nothing changes for existing orgs.
- At authorize, if the chosen workspace is `approved_only` and the client is not approved for this person, render 7c.
- `POST /admin/requests {client, org, note}` gives `access-request:{id}` and emails the org admins (B12) with a link to `/admin/requests/:id` (3d).
- 3d approves for everyone or the requester only, then notifies the requester (email) so they can retry.
- Policy mode is edited by API only for now (the dashboard is out of scope): `PUT /api/orgs/:id/policy` (owner/admin).

**Done when**
- Tests cover: `open` orgs are unaffected; `approved_only` blocks, then a request, then approval, then the retry succeeds; non-admins can't approve.

---

<a id="b12"></a>

## B12 · Emails

**Today**: WorkOS sends every email (Magic Auth codes, invitations). There are no templates in the repo and no sign-in alerts.

**Build** (D4, default: our own templates, sent through WorkOS's "send your own emails" mode)
- With WorkOS sending disabled for Magic Auth and invitations, the API responses carry what we need:
  - the Magic Auth `code`;
  - the invitation `accept_invitation_url` / token.
  - Reference: https://workos.com/docs/authkit/custom-emails
- Templates: `worker/ui/emails/`. They are light, table-based, inline CSS, and come with a plain-text part. They must match 8a, 8b and 8c inside the inbox preview frame.
- Sender: `EMAIL_PROVIDER` abstraction with one implementation chosen in D4. Until it is decided, keep WorkOS sending and ship the templates behind `FEATURE_OWN_EMAILS`.
- **Sign-in alert (8c)**: sent on a new device or location sign-in. Its "This wasn't me" link is a signed, single-use link that revokes that session (B5) and asks the person to secure the account.
- Also add the access-request email (B11) and the approval email (B9), in the same template family.

**Done when**
- Snapshot tests of rendered templates (HTML and text); the visual diff of the gallery email previews against 8a, 8b and 8c; the alert link revokes exactly one session.

---

<a id="b13"></a>

## B13 · Security prerequisites (land first)

Found during the audit. These must be fixed before or with the redesign, because new pages build on them:

1. **Continue policy is in report mode in prod** (`LOGIN_CONTINUE_POLICY=report` in `worker/wrangler.jsonc`), so `/login?continue=` and `/logout?return_url=` still follow unlisted URLs.
   - Default here: switch to `enforce` once the report logs show no legitimate misses.
   - The new screens must use `resolveBrowserRedirect` in enforce mode regardless.
2. **Unauthenticated routes**: `/admin-portal`, `/fga/*` and `/pipes/*` (`worker/routes/workos.ts`) sit outside `authenticateRequest`.
   - Add auth plus org authorisation. Service-binding callers (the `AUTH_HTTP` / `OAUTH` bindings from estate workers) authenticate as they do on other protected routes.
   - Add an escape hatch, `LEGACY_OPEN_WORKOS_ROUTES=1`, which restores the old behaviour if an unknown caller breaks. It defaults to `0` (secure).
   - Owner step: confirm which estate workers call these routes.
3. **Org member and invite routes** don't check membership of `:id` (`authenticateOrgRequest`). See B6.
4. **Org switch keeps the old org's roles** (`POST /api/session/organization`). See B6.
5. **DCR client secrets are stored in plaintext** and compared with `!==`. Hash them with SHA-256, compare in constant time, and migrate on next use.
6. **Device decision has no CSRF token** (`handleDeviceVerification`). See B3.

These are owner-visible changes. Each gets its own commit with a test.
