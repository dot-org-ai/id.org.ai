# Phase 12 · Emails

> **For agentic workers:** run this phase from `../autopilot.md`. Check `../DECISIONS.md` D4 first. If no provider is chosen, build everything behind `FEATURE_OWN_EMAILS=0` and stop short of switching WorkOS sending off.

**Goal:** Our own templates (8a sign-in code, 8b invitation, 8c new sign-in alert) plus the access-request and approval emails, sent through one provider abstraction. The sign-in alert's "This wasn't me" revokes exactly that session.

**Depends on:** Phases 3 (the templates exist), 8, 10 and 11.

**Read first:** `../spec/backend.md#b12`, `../spec/screens.md#8--emails`, https://workos.com/docs/authkit/custom-emails

## Tasks
- [ ] `worker/email/provider.ts`: an `EmailProvider` interface `{ send({to, subject, html, text, tags}) }`, with a `LogProvider` for dev and tests. Add the real provider once D4 is decided, with its API key in a secret.
- [ ] Templates (already built in phase 3): add plain-text parts and subject lines exactly as `../spec/screens.md#8--emails`. The code subject is "Your id.org.ai code: 482913". The HTML code is grouped "482 913".
- [ ] Magic Auth: when `FEATURE_OWN_EMAILS=1`, take the `code` from WorkOS's create-magic-auth response, which is discarded today (`src/sdk/workos/upstream.ts`). Send 8a with our link, `/login/code/:flow?code=`. WorkOS email sending for Magic Auth must be switched off in the WorkOS dashboard; record that as an owner step in PROGRESS.
- [ ] Invitations: send 8b with our `/invite/:token` link (from the invitation's token).
- [ ] Sign-in alert (8c):
  - Trigger: the first sign-in from a new device (`sid` with an unseen UA family + city pair) for the identity.
  - "This wasn't me" is a signed, single-use, 7-day link that revokes that sid and shows a confirmation page with "Secure your account" next steps (error template layout).
- [ ] Access-request (phase 11) and approval (phase 10) emails, in the same template family. Copy is written to match the screens' tone.

## Acceptance
- Snapshot tests for each template (HTML and text).
- The visual diff for 8a, 8b and 8c is still 0 px.
- Tests: the alert link revokes only its sid and is single-use; with the flag off, WorkOS paths are unchanged.

## Commit
`feat(email): templates and provider` and `feat(email): sign-in alerts` → push.
