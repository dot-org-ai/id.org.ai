# Decisions

These are choices the design depends on, each with the default the autopilot uses unless an owner changes it here.

To change one, edit **Decision** and set **Status** to `decided`. The autopilot reads this file at the start of every phase. It never waits on an `open` item: it builds the default behind a flag and records that in `PROGRESS.md`.

| ID | Question | Default (what gets built) | Status | Affects |
|---|---|---|---|---|
| D1 | Which branch is the base? | `product-update`, cut from `release/main-with-security-fixes` (the live code, 22 commits ahead of `main`). Merge it back through a PR to that release branch. Don't deploy from here. | default | All |
| D2 | Own sign-in screens, or hosted AuthKit? | Own screens (1a–1g, 6d), built on WorkOS APIs: OAuth providers, Magic Auth, SSO by organisation, MFA. While `FEATURE_PASSKEYS=0`, 1a's "Sign in with a passkey" button hands off to hosted AuthKit, which supports passkeys, so existing passkey users keep working. Microsoft and Apple stay on hosted AuthKit until the owners enable them as direct providers in WorkOS (`DIRECT_MICROSOFT_APPLE`). | default | B4, B7 |
| D3 | What makes a client "verified"? | First-party seeded clients (`src/sdk/oauth/clients.ts`), plus CIMD hosts listed in env `VERIFIED_CLIENT_HOSTS` (start with `chatgpt.com,claude.ai`). DCR clients are always unverified. | open | B2, 3c |
| D4 | Who sends emails, and with which provider? | Our templates (8a–8c), with WorkOS sending switched off for Magic Auth and invitations. Provider: undecided. Until it is decided, WorkOS keeps sending and our templates ship behind `FEATURE_OWN_EMAILS=0`. | open | B12 |
| D5 | Passkeys: in-house WebAuthn, or hand off to hosted AuthKit? | In-house WebAuthn (`@simplewebauthn/server`), behind `FEATURE_PASSKEYS=0` until reviewed. Reason: WorkOS passkeys work only in hosted AuthKit, with no headless API. | open | B7, 1a, 6a, 6c |
| D6 | Account linking (1e): when does it show? | Only when a completed sign-in's verified email matches a *different* existing identity (for example a claim-by-commit GitHub identity). Same-email logins that WorkOS already links stay silent. | default | B7, 1e |
| D7 | Should the verdict play before a redirect to the app? | No. Play the verdict where the person stays on id.org.ai (device, agent, claim, invite, admin, sign out). Where the browser leaves (consent, choosers, sign-in), go `connecting` and redirect without waiting. | default | motion.md |
| D8 | Two-step recovery codes | Recovery codes are not part of the WorkOS MFA API this design relies on (verify in phase 7). Default: "Use a recovery code" is hidden until a recovery design exists; "Use a passkey instead" shows only when the person has a passkey. | open | 6d |
| D9 | How do per-action approvals reach the person? | Email link (B12) plus the CLI or agent printing the link. Push notifications later. | default | B9, 5b |
| D10 | Continue policy in prod | Switch `LOGIN_CONTINUE_POLICY` from `report` to `enforce` once a week of report logs shows no legitimate misses. New screens enforce regardless. | open | B13 |
| D11 | Spend limits on agents | Store and show the limit now (as designed, with no extra label). Enforce it at the payment hook once agent spend exists, and track that as a follow-up issue. | default | B9, 5a |
| D12 | Where do the docs and the work live? | Repo `dot-org-ai/id.org.ai`. The landing site and the dashboard (`/dash`, Connected apps, Security, Approvals inbox) are out of scope for this update. | decided | All |
