# Phase 7 · Sign-in v2 (email first)

> **For agentic workers:** run this phase from `../autopilot.md`. Write tests first. Every existing auth test must stay green: this is the most security-sensitive phase.

**Goal:**
- `/login` becomes the email-first 1a: providers, an optional passkey, the "Last used" pill.
- Email routes to SSO (1c) or an emailed code (1b), using our own screen on top of the existing magic-flow machinery.
- Provider failures land on 1f.
- First sign-in gets 1d.
- First-party apps can get branded sign-in (1g).
- Workspaces that require two-step get 6d.
- Hosted AuthKit is no longer the path for email.

**Depends on:** Phases 3 and 4.

**Read first:**
- `../spec/backend.md#b4`
- `../spec/screens.md#1--sign-in`
- `../spec/security.md#codes-and-budgets`
- `worker/routes/auth.ts` (`/login`, `finishWorkOSSignIn`, `LoginCsrfRecord`)
- `worker/routes/magic-link.ts`
- `worker/utils/code-guard.ts`
- `worker/utils/relying-parties.ts`

## Tasks

### Task 1 · 1a on `/login`
- [ ] Replace `renderProviderPicker` with the 1a screen.
  - Keep every existing query contract: `continue`, `redirect_uri`, `provider`, `login_hint`.
  - Keep the session skip, unless `prompt=login` arrives (phase 8 adds prompt; accept the param now).
  - Keep the synthetic probe (`worker/index.ts` cron) working; update its assertion to the new page.
- [ ] Provider buttons keep today's `/login?provider=…` flow, including `login_hint`.
- [ ] Set the `id_last_provider` cookie after success. Render the "Last used" pill from it.
- [ ] Passkey button: with `FEATURE_PASSKEYS=1`, WebAuthn (phase 9). With it off, the same button hands off to hosted AuthKit (`/login?provider=authkit&continue=…&login_hint=…`), so existing AuthKit passkey users keep working (D2).
- [ ] Microsoft and Apple: send them to direct WorkOS providers (`MicrosoftOAuth`, `AppleOAuth`) when `DIRECT_MICROSOFT_APPLE=1`; otherwise keep `provider=authkit`. That flag defaults to `0` until the owners enable those providers in the WorkOS dashboard (owner step in PROGRESS).
- [ ] Remove `worker/views/provider-picker.ts` once nothing imports it.

### Task 2 · Email → SSO or code
- [ ] `POST /login/email`:
  - CSRF, then normalise the email.
  - SSO discovery: look up the WorkOS organisation by domain, cached 10 minutes.
  - Then either a 303 to `/login/sso`, or create a magic flow on a new `'web'` budget path and 303 to `/login/code/:flow`.
  - Same budgets as `'ml'`. Don't reveal whether the account exists.
- [ ] `GET/POST /login/code/:flow` renders 1b.
  - Cookie-bound, single-use, under the guess budget. Verify with the existing magic-auth grant, then `finishWorkOSSignIn` (`requestedProvider: 'magic_link'`, or `email_otp` per `describeWorkOSSignIn`).
  - `?code=` prefills the boxes and never auto-submits.
  - Resend: `POST /login/code/:flow/resend`.
- [ ] Re-render `/magic-link/:flow` with the same 1b component. Its behaviour and budgets are unchanged; the existing `magic-link-*` tests must pass unchanged.
- [ ] `GET /login/sso` renders 1c. Its button calls WorkOS authorize with `organization_id` / `connection_id` and `login_hint`. Show the lock note only when the org enforces SSO.

### Task 3 · Failures, first run, branding
- [ ] WorkOS callback `error` → 1f with a mapped one-sentence reason (raw code in the developer details). An exchange failure → the generic error template.
- [ ] First run: when `finishWorkOSSignIn` provisions a new identity, continue to `/welcome?continue=`.
  - `POST` updates the WorkOS user's name and renames the personal org (`ensurePersonalOrg`).
  - "Not you?" signs out and returns to 1a.
- [ ] Branded sign-in: add `brand` to the first-party client definitions in `src/sdk/oauth/clients.ts` (headless.ly first). `/login` with that `client_id` (or a matching `continue` host) renders 1g. Third-party clients never get it.

### Task 4 · Two-step (6d)

Two-step ships here, not in phase 9: once email codes leave hosted AuthKit, a WorkOS MFA challenge can happen on this path.

- [ ] When a WorkOS authenticate call (provider callback, magic-auth code) returns an MFA challenge, create an `mfa-flow:{id}` record (cookie-bound, 10 minutes, 5 guesses under the code budgets) and render 6d at `/login/two-step/:flow`.
- [ ] Verify the TOTP through the WorkOS MFA API (https://workos.com/docs/authkit/mfa and the AuthKit MFA API reference), then `finishWorkOSSignIn`.
- [ ] "Use a recovery code" stays hidden per D8. "Use a passkey instead" appears only with `FEATURE_PASSKEYS=1` and a registered passkey.
- [ ] Tests: the challenge goes to 6d; a correct code continues; the guess budget applies; a stub of the WorkOS MFA error shape is used.

### Task 5 · Clean up the federation leftovers
- [ ] Confirm nothing references `/federation/email/*` on this branch.
- [ ] Note in PROGRESS that `feat/upstream-microsoft-federation`'s `email-code.ts` is superseded. The Entra federation path (`/federation/microsoft/*`) is **not** part of this update; leave it to its branch.

## Acceptance
- Every existing test passes unchanged: `login-state-binding`, `continue-policy`, `host-trust`, `relying-party`, `magic-link-attempts`, `magic-link-callers`, `code-send-budget`, `signin-code-bruteforce`, `cookie-auth`.
- New tests cover:
  - an SSO domain goes to 1c;
  - any other domain goes to 1b with a flow;
  - the guess and send budgets on the `'web'` path;
  - prefill without auto-submit;
  - a provider error goes to 1f with a request ID;
  - a first sign-in goes to 1d and then continues;
  - branding only for listed first-party clients;
  - the "Last used" pill.
- The visual diff for 1a, 1b, 1c, 1d, 1f, 1g and 6d is still 0 px.
- A route-level flow test in the workers pool (`SELF.fetch` + `fetchMock` for WorkOS) completes email → code → continue.
- One browser-level check against `wrangler dev` with `WORKOS_API_BASE` pointing at `test-visual/workos-stub.mjs` does the same through the real page. Never use `pnpm test:e2e`.

## Commit
- `feat(auth): email-first sign-in page`
- `feat(auth): own email-code screen on the magic-flow path`
- `feat(auth): SSO discovery`
- `feat(auth): provider failure fallback`
- `feat(auth): first run`
- `feat(auth): branded first-party sign-in`
- `feat(auth): two-step`

Push.
