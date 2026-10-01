# Progress

The autopilot updates this file at the start and end of every phase (see `autopilot.md`). Owners can read it to see exactly where the work is.

**Base:** `release/main-with-security-fixes` @ `dbadae8` (2026-09-28)
**Started:** 2026-10-01
**Toolchain:** node v22.14.0 · pnpm 10.14.0 · wrangler 4.88.0 · typescript 5.9.3 · vitest 2.1.9
**Baseline:** typecheck clean (root only; worker not yet typechecked) · tests: workers pool 94 files / 2394 passed / 0 failed, node config 27 files / 520 passed / 0 failed · dry-run OK (799.61 KiB / gzip 174.14 KiB)
**Tracking:** beads epic `id-6zy`, one child per phase (`id-6zy.1` = phase 0 … `id-6zy.14` = phase 13)

## Where we are (resume point)
- **Phase:** 1 (Foundation), not started.
- **Next step:** read `prompts/01-foundation.md`, then Task 1 (worker tsconfig + typecheck).
- **Pushes:** blocked, see **Blocked**. All commits are on the local `product-update` branch only.

## Phases

| # | Phase | Prompt | Status | Gate (tests · visual) | Notes |
|---|---|---|---|---|---|
| 0 | Preflight | `prompts/00-preflight.md` | done (2026-10-01) | 2914 passed / 0 failed · visual n/a | Baseline recorded; push blocked (see Blocked) |
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
None. Workers pool: 94 files, 2394 tests, all passed. Node config (`vitest.node.config.ts`): 27 files, 520 tests, all passed. (`vitest.node.config.ts` lists `test/oauth-dev.test.ts` and `test/oauth-server.test.ts`, which don't exist; vitest skips them silently.)

## In-flight branches (from phase 0)
Compared by subject (`git log HEAD..origin/<b>`), since most were cherry-picked into the release branch under new hashes. Not merged, per phase 0.

| Branch | Commits whose subject is not on `product-update` | Expected overlap |
|---|---|---|
| `feat/upstream-microsoft-federation` | `1817ecd` feat(federation): upstream Microsoft Entra OIDC + email-code fallback; `9020161` fix(federation): email-code fallback uses magic-auth:code; `81fc441` chore(beads): export id-msf; `f2291e2` site: add /trust | `worker/views/email-code.ts` and `/federation/email/*` are superseded by phase 7 (own 1b screen). `/federation/microsoft/*` is out of scope. Conflicts expected in `worker/routes/auth.ts` and `worker/index.ts` if it is ever merged. |
| `feat/mcp-authorization-server-2` | Same four as above (it is built on the federation branch); everything else is already here | Same as above |
| `hotfix/login-state-binding` | `1817ecd`, `81fc441`, `f2291e2` (shared ancestry only) | None beyond the federation commit |
| `fix/relying-party-live` | `1817ecd`, `9020161`, `81fc441`, `f2291e2` | Same as above |
| `cli/refresh-issuing-client` | `b3638ed` fix(cli): refresh under the issuing client_id; `77b801e` feat(oauth): first-party CLI family may refresh each other's tokens; `dbc2849` feat(oauth): register rpc_do_cli; `d8f19a5` feat(oauth): userinfo + introspection carry the session-JWT authorization claims; plus the shared three | Phase 5 (`org_id` in userinfo/introspection) and phase 6 (`src/sdk/cli/`) touch the same files. Expect conflicts in `src/sdk/oauth/provider.ts` and `src/sdk/cli/*` when it lands. |

## Assumptions made (defaults used from DECISIONS.md, or judgement calls)
- A1 (phase 0): every `open` decision (D3, D4, D5, D8, D10) is built with its DECISIONS.md default, behind its flag. No owner input is awaited.
- A2 (phase 0): the new local `product-update` branch had git's auto-tracking pointed at `origin/release/main-with-security-fixes` (it was cut from it). Upstream was unset immediately so no bare `git push` can ever target `release/*`.
- A3 (phase 0): the README's "Where this runs" note was left in place: the session's permission classifier refused that edit. It is harmless (it describes the copy in `dot-do/id.org.ai`). An owner can delete those three lines by hand.

## Owner steps (things only a person can do)
- WorkOS dashboard: switch off WorkOS email sending for Magic Auth and invitations, when D4 is decided (phase 12).
- Provide the official provider marks and the first-party brand marks (`spec/logos.md`).
- Decide D3, D4, D5, D8 and D10 (`DECISIONS.md`).
- WorkOS dashboard: enable Microsoft and Apple as direct OAuth providers, then set `DIRECT_MICROSOFT_APPLE=1` (phase 7).
- Confirm which estate workers call `/admin-portal`, `/fga/*` and `/pipes/*` before relying on `LEGACY_OPEN_WORKOS_ROUTES=0` in prod (phase 4).
- Never run `pnpm test:e2e` for this work. It targets production.
- Push the local `product-update` branch to origin from an account with write access (see **Blocked**).

## Design questions (spec or mock gaps found while building)
—

## Blocked
- **Push to origin (all phases).** `git push -u origin product-update` returns 403: the GitHub account on this machine (`bryant22`) has pull-only access to `dot-org-ai/id.org.ai` (`gh api repos/dot-org-ai/id.org.ai` → `push: false`). Every phase commit is on the local `product-update` branch only. **Owner step:** push it from an account with write access (`git push -u origin product-update`), or grant `bryant22` write access. The phase 13 draft PR depends on this push.

## Follow-ups
- auto.dev and headless.ly CLIs: adopt `spec/cli-output.md` (other repos).
