# Progress

The autopilot updates this file at the start and end of every phase (see `autopilot.md`). Owners can read it to see exactly where the work is.

**Base:** `release/main-with-security-fixes` @ `dbadae8` (2026-09-28)
**Started:** 2026-10-01
**Toolchain:** node v22.14.0 · pnpm 10.14.0 · wrangler 4.88.0 · typescript 5.9.3 · vitest 2.1.9
**Baseline:** typecheck clean (root only; worker not yet typechecked) · tests: workers pool 94 files / 2394 passed / 0 failed, node config 27 files / 520 passed / 0 failed · dry-run OK (799.61 KiB / gzip 174.14 KiB)
**Tracking:** beads epic `id-6zy`, one child per phase (`id-6zy.1` = phase 0 … `id-6zy.14` = phase 13)

## Where we are (resume point)
- **Phase:** 2 (Design system), in progress.
- **Done so far in phase 2 (uncommitted at the time of writing; see git status):** every component in `spec/components.md` as `worker/ui/components/*.tsx` with its CSS in `worker/ui/ui.css`; the 4b screen and fixture (`worker/ui/screens/DeviceConfirm.tsx`, `worker/ui/gallery/fixtures/devices.ts`) pass 7/7 at 0 px; client scripts written in `worker/ui/client/` (copy, code-input, submit, device-confirm, countdown, claim-status, logo, plus `lib/connector.ts`, `lib/submit.ts`).
- **Next step:** client-script tests (vitest.ui.config.ts), component markup tests, the `/__design/components` sheet, split gallery CSS out of the production stylesheet, then the phase 2 gate and review.
- **Local dev on this machine:** ports 8787 and 8788 are held by other projects' long-running `workerd`, so this session runs `PORT=8797 pnpm dev:worker` and `STUB_PORT=8798 pnpm dev:stub`, with `WORKOS_API_BASE=http://127.0.0.1:8798` in `worker/.dev.vars`, and `pnpm test:visual --base http://127.0.0.1:8797`.

## Phases

| # | Phase | Prompt | Status | Gate (tests · visual) | Notes |
|---|---|---|---|---|---|
| 0 | Preflight | `prompts/00-preflight.md` | done (2026-10-01) | 2914 passed / 0 failed · visual n/a | Baseline recorded; push blocked (see Blocked) |
| 1 | Foundation | `prompts/01-foundation.md` | done (2026-10-01) | 2938 passed / 0 failed (workers 2412, node 520, ui 6) · visual self-test 72/72 · dry-run OK | Reviewed: 1 blocking finding fixed (`form-action` dropped `[::1]`), 12 non-blocking, the important ones fixed (`79e0ffe`) |
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
- A4 (phase 1): WorkOS helpers take an API key, not `env`, and are public SDK exports, so the seam is module-level: the worker, cron, RPC entrypoints and `IdentityDO` call `configureWorkOSBase(env)`, and every helper builds URLs with `workosUrl()`. Only loopback overrides are honoured, so production always uses `https://api.workos.com`.
- A5 (phase 1): `wrangler dev` presents the first route's host (`oauth.do`) unless run with `--local-upstream`; `pnpm dev:worker` does that. With the stub configured, `/login` uses its own loopback `/api/callback` (`isLocalStubOrigin`); production always sends WorkOS `https://id.org.ai/api/callback`.
- A6 (phase 1): the workers test pool reuses `worker/wrangler.jsonc`, so it would also load a developer's `worker/.dev.vars`. `vitest.config.ts` blanks every binding wrangler adds beyond `wrangler.jsonc`'s vars, so the suite behaves the same with or without local dev setup.
- A7 (phase 1): Privacy, Terms and Status don't exist on id.org.ai yet. The footer links are placeholders in `worker/ui/links.ts` (`/privacy`, `/terms`, `/status`); see owner steps.
- A8 (phase 1): `predeploy` now runs `build:site && build:ui && build:dash`. `build:dash` points at a sibling repo (`../../.studio/ui`) and was not run here.
- A3 (phase 0): the README's "Where this runs" note was left in place: the session's permission classifier refused that edit. It is harmless (it describes the copy in `dot-do/id.org.ai`). An owner can delete those three lines by hand.

## Owner steps (things only a person can do)
- WorkOS dashboard: switch off WorkOS email sending for Magic Auth and invitations, when D4 is decided (phase 12).
- Provide the official provider marks and the first-party brand marks (`spec/logos.md`).
- Decide D3, D4, D5, D8 and D10 (`DECISIONS.md`).
- WorkOS dashboard: enable Microsoft and Apple as direct OAuth providers, then set `DIRECT_MICROSOFT_APPLE=1` (phase 7).
- Confirm which estate workers call `/admin-portal`, `/fga/*` and `/pipes/*` before relying on `LEGACY_OPEN_WORKOS_ROUTES=0` in prod (phase 4).
- Never run `pnpm test:e2e` for this work. It targets production.
- Replace the placeholder Privacy, Terms and Status URLs in `worker/ui/links.ts` with the real pages (phase 1).

## Design questions (spec or mock gaps found while building)
—

## Blocked
—

Resolved: pushing to origin was blocked in phase 0 (`bryant22` had pull-only access). Owner access was granted on 2026-10-01; `product-update` is on origin and tracks `origin/product-update`.

## Incidents
- Phase 1, 2026-10-01: while proving the WorkOS stub by hand, one GET with a fake stub code reached production `https://id.org.ai/api/callback`. At that point the worker still sent WorkOS the production callback URL, and the hand-run curl followed the stub's redirect. Production refused it (403: the login state wasn't bound), and nothing changed. Since then the stub refuses non-loopback `redirect_uri`s, `pnpm dev:worker` keeps the local origin, and `test-visual/stub-smoke.mjs` refuses any non-loopback hop.

## Follow-ups
- auto.dev and headless.ly CLIs: adopt `spec/cli-output.md` (other repos).
- `worker/routes/mcp.ts` `nullStub` lacks 17 newer `IdentityStub` methods (L0 never calls them). It carries a `@ts-expect-error` so the worker typechecks; give it the full interface (phase 1).
- Only `test/ui-*.test.ts` are typechecked (`test/tsconfig.ui.json`); the rest of `test/` predates typechecking (phase 1).
- `test-visual/stub-smoke.mjs` (`pnpm test:stub-smoke`) needs a running `wrangler dev` and stub, so it isn't in `pnpm gate` (phase 1).
