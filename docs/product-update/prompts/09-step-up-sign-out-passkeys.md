# Phase 9 · Step-up, sign out, passkeys, account linking

> **For agentic workers:** run this phase from `../autopilot.md`. Write tests first. Check `../DECISIONS.md` D5, D6 and D8 before starting.

**Goal:**
- Sensitive grants ask for a fresh check (6a).
- Sign out has three clear scopes and an OIDC `end_session` (6b).
- Passkeys can be added (6c) and used to sign in and step up, behind a flag.
- Account conflicts are linked only after proving both (1e).

**Depends on:** Phase 8.

**Read first:** `../spec/backend.md#b5` (step-up), `#b7` and `#b8`, `../spec/screens.md#6--security-and-sign-out`, `../spec/screens.md#1e`.

## Tasks

### Task 1 · Step-up (6a)
- [ ] `GET/POST /step-up?resume=<id>&reason=<code>`.
  - `resume` is a single-use resume record id, never a URL.
  - `reason` is an enum (`act_permissions`, `privileged_agent`, `max_age`, `sign_out_everywhere`) mapped to catalogue copy. Never render query text.
  - Factors: an email code (the B4 flow in step-up mode, sent to the session email) and a passkey (when enabled and registered).
  - Success updates `authTime` and `amr` on the session record and re-mints.
- [ ] Turn on `FEATURE_STEP_UP` triggers: consent with `sb:do` when `auth_time` is older than 600s (phase 5 hook), `max_age`, Privileged agent approval (phase 10), and sign out everywhere.

### Task 2 · Sign out (6b)
- [ ] `GET/POST /signout` with scope `app`, `browser` or `everywhere`, with the effects in `backend.md#b8`. `everywhere` needs a fresh `auth_time`.
- [ ] `end_session_endpoint` at `/oauth/end_session`.
  - Validate `id_token_hint` and `post_logout_redirect_uri`.
  - Show 6b when other apps are signed in; otherwise sign out silently.
  - Advertise it in both discovery documents.
- [ ] Legacy `GET/POST /logout` and `POST /api/logout` stay behaviour-identical (they have tests).

### Task 3 · Passkeys (6c, 1a, 6a) behind `FEATURE_PASSKEYS`
- [ ] Spike first (30 minutes): `@simplewebauthn/server` registration and authentication verification in `wrangler dev`. Record the result in PROGRESS. If it fails, use `@oslojs/webauthn`.
- [ ] Store `passkey:{identityId}:{credentialId}` records. RP ID `id.org.ai`; the allowed origins are the auth hosts.
- [ ] Offer 6c once, after a code sign-in. "Not now" is remembered for 30 days.
- [ ] Passkey sign-in on 1a mints the session directly (`amr: ['passkey']`); WorkOS loads the user and memberships.
- [ ] Passkeys are a step-up factor on 6a.

### Task 4 · Account linking (1e) per D6
- [ ] Detect when a completed sign-in's verified email matches a different existing identity.
- [ ] Store a pending link (10 minutes). Render 1e. On success with the existing method, link and continue. Never merge without both proofs.

## Acceptance
- Tests cover:
  - a stale `auth_time` with `sb:do` goes through step-up and resumes;
  - resume records are single-use;
  - each sign-out scope's effect;
  - `end_session` validation;
  - the legacy logout is unchanged;
  - passkey register and authenticate with library test vectors;
  - with the flag off, the 1a passkey button hands off to hosted AuthKit, and 6a and 6c never offer passkeys;
  - linking requires both proofs.
- The visual diff for 6a, 6b, 6c and 1e is still 0 px.

## Commit
- `feat(auth): step-up`
- `feat(auth): sign out scopes and end_session`
- `feat(auth): passkeys (flagged)`
- `feat(auth): account linking`

Push.
