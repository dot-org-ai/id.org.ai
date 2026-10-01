# Progress

The autopilot updates this file at the start and end of every phase (see `autopilot.md`). Owners can read it to see exactly where the work is.

**Base:** `release/main-with-security-fixes` @ `dbadae8` (2026-09-28)
**Started:** 2026-10-01
**Toolchain:** node v22.14.0 · pnpm 10.14.0 · wrangler 4.88.0 · typescript 5.9.3 · vitest 2.1.9
**Baseline:** typecheck clean (root only; worker not yet typechecked) · tests: workers pool 94 files / 2394 passed / 0 failed, node config 27 files / 520 passed / 0 failed · dry-run OK (799.61 KiB / gzip 174.14 KiB)
**Tracking:** beads epic `id-6zy`, one child per phase (`id-6zy.1` = phase 0 … `id-6zy.14` = phase 13)

## Where we are (resume point)
- **Session stopped 2026-10-01 at the usage limit.** All background subagents were stopped before they finished; nothing they did is on `product-update`.
- **Phase 3 (Screens):** all six groups merged; **72/72 manifest cases at 0 px** on the integrated build (`9ac8e45`); `1cf60da` (one link-button rule, FootLinks CSS) re-checked 1b and 6d at 0 px. The phase 3 review found 3 blocking issues (screens that stay on id.org.ai built as forms that leave; missing result states for 5b/5c/6b and 4b's error templates; consent's unverified handling left to the caller). Shared fixes are in (`15c4ac7`, `1eda623`). The three fix subagents (branches `phase3fix-agents` = 5a–5c, `phase3fix-accounts-security` = 2e/6b/4b/errors, `phase3fix-authorize` = 3a–3d) were **stopped with no commits**; their worktrees under `.claude/worktrees/agent-*` may hold uncommitted partial edits. **Next:** redo (or finish from those worktrees) the three fix groups, merge, remove the `.id-footlinks` duplicate from `css/security.css` if a group re-adds it, rebuild assets, re-run all 72 visual cases and `pnpm gate`, land phase 3 (`bd close id-6zy.4`).
- **Phase 4 (Errors and security):** implemented ahead (`31f8499` B13.2/3, `bd18c83` B13.4, `8e3c200` B13.5, `2fa1453` strict redirects, `aaeec6e` B1 HTML errors). Its reviewer was **stopped before reporting**. **Next:** run a fresh reviewer, fix blocking findings, land phase 4 (`bd close id-6zy.5`).
- **Phase 5 (Consent v2):** Task 1 (scope registry, `d60e8ff`) done. Task 3 (consent POST + `org_id`) subagent was stopped before writing anything. **Next:** Task 2 (`ConsentViewModel` in `handleAuthorize`, render Consent via `renderPage` with `formActionOrigins`, keep CSRF state, delete `renderConsentPage`, deprecate `generateConsentScreenHtml`), Task 3, Task 4 (`submit.js` on consent, copy CIMD URL); `relying-party.test.ts` `consentFields` regex may need updating for JSX inputs.
- **Local dev on this machine:** ports 8787 and 8788 are held by other projects' long-running `workerd`, so this session runs `PORT=8797 pnpm dev:worker` and `STUB_PORT=8798 pnpm dev:stub`, with `WORKOS_API_BASE=http://127.0.0.1:8798` in `worker/.dev.vars`, and `pnpm test:visual --base http://127.0.0.1:8797`. Subagents use ports 8811–8823.

## Phases

| # | Phase | Prompt | Status | Gate (tests · visual) | Notes |
|---|---|---|---|---|---|
| 0 | Preflight | `prompts/00-preflight.md` | done (2026-10-01) | 2914 passed / 0 failed · visual n/a | Baseline recorded; push blocked (see Blocked) |
| 1 | Foundation | `prompts/01-foundation.md` | done (2026-10-01) | 2938 passed / 0 failed (workers 2412, node 520, ui 6) · visual self-test 72/72 · dry-run OK | Reviewed: 1 blocking finding fixed (`form-action` dropped `[::1]`), 12 non-blocking, the important ones fixed (`79e0ffe`) |
| 2 | Design system | `prompts/02-design-system.md` | done (2026-10-01) | 3023 passed / 0 failed (workers 2431, node 520, ui 72) · 4b 7/7 at 0 px · reduced motion 0 animated | Reviewed: 2 blocking (shared fetch path for forms that stay; component-sheet variants) fixed in `28cac3e`, with most non-blocking items |
| 3 | Screens (UI) | `prompts/03-screens.md` | in progress | 72/72 at 0 px · ui 223 tests | Built by six parallel groups, integrated; review fixes in progress |
| 4 | Errors and security prerequisites | `prompts/04-errors-and-security.md` | in progress | workers 2448 passed | B1, B13.2–B13.5 and strict redirects done; review running |
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
- A9 (phase 2): every `CodeInput` box is named `code`, so without JS the form posts the characters in order and the server joins them, instead of a hidden mirror input.
- A10 (phase 2): client scripts split by what the form does: `submit.js` for forms that leave id.org.ai (connecting + busy, then the normal post) and `fetch-form.js` for forms that stay (fetch, verdict, then a server-rendered template swaps in). 4b's state machine is `fetch-form.js`; there is no separate `device-confirm.js`. `connector.ts` is a library, not an entry. Each script is under 2 KB minified (`build:ui` enforces it).
- A11 (phase 2): countdowns run from server-rendered seconds left (`data-seconds-left`), not an absolute expiry, so client clock skew can't expire a page early.
- A12 (phase 2): radii the mocks use that `tokens.css` doesn't name (4, 5, 6, 7, 9, 17px) are named in a derived block at the top of `ui.css`, because `tokens.css` must stay identical to the spec copy.
- A3 (phase 0): the README's "Where this runs" note was left in place: the session's permission classifier refused that edit. It is harmless (it describes the copy in `dot-do/id.org.ai`). An owner can delete those three lines by hand.

## Owner steps (things only a person can do)
- WorkOS dashboard: switch off WorkOS email sending for Magic Auth and invitations, when D4 is decided (phase 12).
- Provider marks: the GitHub, Google, Microsoft and Apple marks from `worker/views/provider-picker.ts` now render in the provider buttons (`ProviderMark`). Check each against the provider's current brand guidelines, and provide the first-party brand marks (`spec/logos.md`).
- Decide D3, D4, D5, D8 and D10 (`DECISIONS.md`).
- WorkOS dashboard: enable Microsoft and Apple as direct OAuth providers, then set `DIRECT_MICROSOFT_APPLE=1` (phase 7).
- Confirm which estate workers call `/admin-portal`, `/fga/*` and `/pipes/*` before relying on `LEGACY_OPEN_WORKOS_ROUTES=0` in prod (phase 4).
- Never run `pnpm test:e2e` for this work. It targets production.
- Replace the placeholder Privacy, Terms and Status URLs in `worker/ui/links.ts` with the real pages (phase 1).

## Design questions (spec or mock gaps found while building)
- **Owner design change, 2026-10-01 (1a/1g sign-in):** Bryant asked for a narrower card, providers stacked one per row, and real provider marks. Built: sign-in uses a 440px column (`Page narrow`), `.id-providers` is one column, and `ProviderMark` replaces the dashed slot on 1a, 1g and 1e. The mocks were not edited, so 6 cases now differ from them by design: 1a, 1e and 1g at desktop and phone. The other 66 are at 0 px. **Open:** whether to update those mocks to the new design, or record the 6 cases as approved deviations. The gate stays at 66/72 until that's decided.
- **Owner design change, 2026-10-01 (dropdowns):** Bryant asked for our own dropdowns instead of the native one. Built without script: where a select can be styled (`appearance: base-select`, Chrome 135+), its open list now matches the card (panel, rounded rows, hover, checkmark, a short fade that reduced motion turns off). It stays a real `<select>`, so keyboard, screen readers, autofill and form posts are unchanged. Safari and Firefox keep their native list. The closed box is unchanged (0 px on every select screen: 3a, 4b, 5a, 5c). Used on 3a, 4b, 5a and 5d.

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
