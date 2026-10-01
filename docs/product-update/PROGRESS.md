# Progress

The autopilot updates this file at the start and end of every phase (see `autopilot.md`). Owners can read it to see exactly where the work is.

**Base:** `release/main-with-security-fixes` @ `dbadae8` (2026-09-28)
**Started:** —
**Toolchain:** node — · pnpm — · wrangler —
**Baseline:** typecheck — · tests — passed / — failed (pre-existing failures listed below) · dry-run —

## Phases

| # | Phase | Prompt | Status | Gate (tests · visual) | Notes |
|---|---|---|---|---|---|
| 0 | Preflight | `prompts/00-preflight.md` | todo | | |
| 1 | Foundation | `prompts/01-foundation.md` | todo | | |
| 2 | Design system | `prompts/02-design-system.md` | todo | | |
| 3 | Screens (UI) | `prompts/03-screens.md` | todo | | |
| 4 | Errors and security prerequisites | `prompts/04-errors-and-security.md` | todo | | |
| 5 | Consent v2 | `prompts/05-consent.md` | todo | | |
| 6 | Device flow v2 and CLI | `prompts/06-device.md` | todo | | |
| 7 | Sign-in v2 | `prompts/07-sign-in.md` | todo | | |
| 8 | Sessions, accounts, workspaces | `prompts/08-accounts-and-workspaces.md` | todo | | |
| 9 | Step-up, sign out, two-step, passkeys | `prompts/09-step-up-sign-out-passkeys.md` | todo | | |
| 10 | Agents and claim | `prompts/10-agents-and-claim.md` | todo | | |
| 11 | Workspace app policy | `prompts/11-app-policy.md` | todo | | |
| 12 | Emails | `prompts/12-emails.md` | todo | | |
| 13 | QA and launch readiness | `prompts/13-qa-and-launch.md` | todo | | |

Statuses: `todo` · `in progress` · `done` · `blocked (see below)`.

## Pre-existing test failures (baseline)
—

## In-flight branches (from phase 0)
—

## Assumptions made (defaults used from DECISIONS.md, or judgement calls)
—

## Owner steps (things only a person can do)
- WorkOS dashboard: switch off WorkOS email sending for Magic Auth and invitations, when D4 is decided (phase 12).
- Provide the official provider marks and the first-party brand marks (`spec/logos.md`).
- Decide D3, D4, D5, D8 and D10 (`DECISIONS.md`).
- WorkOS dashboard: enable Microsoft and Apple as direct OAuth providers, then set `DIRECT_MICROSOFT_APPLE=1` (phase 7).
- Confirm which estate workers call `/admin-portal`, `/fga/*` and `/pipes/*` before relying on `LEGACY_OPEN_WORKOS_ROUTES=0` in prod (phase 4).
- Never run `pnpm test:e2e` for this work. It targets production.

## Design questions (spec or mock gaps found while building)
—

## Blocked
—

## Follow-ups
- auto.dev and headless.ly CLIs: adopt `spec/cli-output.md` (other repos).
