# Progress

The autopilot updates this file at the start and end of every phase (see `autopilot.md`). Owners can read it to see exactly where the work is.

**Base:** `release/main-with-security-fixes` @ `dbadae8` (2026-09-28)
**Started:** 2026-10-01
**Toolchain:** node v22.14.0 · pnpm 10.14.0 · wrangler 4.88.0 · typescript 5.9.3 · vitest 2.1.9
**Baseline:** typecheck clean (root only; worker not yet typechecked) · tests: workers pool 94 files / 2394 passed / 0 failed, node config 27 files / 520 passed / 0 failed · dry-run OK (799.61 KiB / gzip 174.14 KiB)
**Tracking:** beads epic `id-6zy`, one child per phase (`id-6zy.1` = phase 0 … `id-6zy.14` = phase 13)

## Where we are (resume point)
- **Draft PR:** https://github.com/dot-org-ai/id.org.ai/pull/35 (`product-update` → `release/main-with-security-fixes`), opened 2026-10-01 ahead of phase 13 so Nathan can review. Phase 13 updates this PR rather than opening a new one. Keep it a draft; never merge.
- **Phases 3 and 4 landed (2026-10-01).** Phase 3's three blocking findings were fixed in fix round 2 (`12c2355` agents, `9f14b55` authorize, `d428ef7` accounts/security, merged at `5e8cb3e`) and confirmed FIXED by a fresh reviewer; its should-fix items on the 5b countdown race and 3d trust are fixed (`ca26e64`), the rest are follow-ups. Phase 4's review found two blocking authorization holes, both fixed with tests (`44f5ee2`); its should-fix items are owner steps and follow-ups below.
- **Phase 5 (Consent v2): built, in review (2026-10-01).** `/oauth/authorize` renders 3a/3b/3c from a provider view model (`edd17b1`); `org_id` flows into every token (`dd45da9`, merged `bbc2c00`); the POST contract (access, per-workspace consent, fetch submit, step-up behind `FEATURE_STEP_UP`) is `6de3e6e`. A manual browser run on `wrangler dev` found and fixed two bugs the tests missed: native form posts from the new pages got 403 (`Origin: null` under `Referrer-Policy: no-referrer`, `b1a90c3`) and local sign-in never kept its cookie (`Domain=.0.1`, `7bfa313`). Gate green (3418 tests); visual identical to the baseline (53 at 0 px + 19 intentional). **Next:** act on the phase 5 reviewer's findings, then land phase 5 (`bd close id-6zy.6`).
- **Phase 5 (Consent v2):** Task 1 (scope registry, `d60e8ff`) done. Task 3 (consent POST + `org_id`) subagent was stopped before writing anything. **Next:** Task 2 (`ConsentViewModel` in `handleAuthorize`, render Consent via `renderPage` with `formActionOrigins`, keep CSRF state, delete `renderConsentPage`, deprecate `generateConsentScreenHtml`), Task 3, Task 4 (`submit.js` on consent, copy CIMD URL); `relying-party.test.ts` `consentFields` regex may need updating for JSX inputs.
- **Local dev on this machine:** ports 8787 and 8788 are held by other projects' long-running `workerd`, so this session runs `PORT=8797 pnpm dev:worker` and `STUB_PORT=8798 pnpm dev:stub`, with `WORKOS_API_BASE=http://127.0.0.1:8798` in `worker/.dev.vars`, and `pnpm test:visual --base http://127.0.0.1:8797`. Subagents use ports 8811–8823.

## Phases

| # | Phase | Prompt | Status | Gate (tests · visual) | Notes |
|---|---|---|---|---|---|
| 0 | Preflight | `prompts/00-preflight.md` | done (2026-10-01) | 2914 passed / 0 failed · visual n/a | Baseline recorded; push blocked (see Blocked) |
| 1 | Foundation | `prompts/01-foundation.md` | done (2026-10-01) | 2938 passed / 0 failed (workers 2412, node 520, ui 6) · visual self-test 72/72 · dry-run OK | Reviewed: 1 blocking finding fixed (`form-action` dropped `[::1]`), 12 non-blocking, the important ones fixed (`79e0ffe`) |
| 2 | Design system | `prompts/02-design-system.md` | done (2026-10-01) | 3023 passed / 0 failed (workers 2431, node 520, ui 72) · 4b 7/7 at 0 px · reduced motion 0 animated | Reviewed: 2 blocking (shared fetch path for forms that stay; component-sheet variants) fixed in `28cac3e`, with most non-blocking items |
| 3 | Screens (UI) | `prompts/03-screens.md` | done (2026-10-01) | 3385 passed / 0 failed (workers 2466, node 520, ui 399) · dry-run OK · visual 53/72 at 0 px, the other 19 intentional (owner design changes) and unchanged | Six parallel groups, then fix round 2 for the review's 3 blocking findings (confirmed fixed by a second review); 2 should-fix fixed (`ca26e64`), the rest in Follow-ups |
| 4 | Errors and security prerequisites | `prompts/04-errors-and-security.md` | done (2026-10-01) | 3385 passed / 0 failed (workers 2466, node 520, ui 399) · dry-run OK · 7a/7b at 0 px · `/oauth/authorize?client_id=nope` → 7a with request ID | Review: 2 blocking holes (cross-org member writes; platform caller from an unvalidated header) fixed with tests in `44f5ee2`; every new test fails without its fix (checked by revert); should-fix items in Owner steps and Follow-ups |
| 5 | Consent v2 | `prompts/05-consent.md` | in progress | 3418 passed / 0 failed (workers 2497, node 520, ui 401) · visual unchanged | Built; review running |
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
- Before deploying phase 4: confirm the WorkOS org scope of SaaS.Studio's `IDORGAI_ORG_TOKEN`. A key scoped to an org other than `PLATFORM_ORG_ID` now gets 403 on other orgs' member routes (B13.3), and `LEGACY_OPEN_WORKOS_ROUTES` doesn't cover those routes (phase 4 review should-fix 4).
- Decide what makes a platform caller: today any unscoped WorkOS `sk_` key is one, and `/api/keys` creates unscoped keys when it can't resolve an org. Safer: only keys scoped to `PLATFORM_ORG_ID`, or a key-id allowlist (phase 4 review should-fix 5).
- Decide, with D10, whether `resolveBrowserRedirectStrict` should accept only origins bound to the flow's client. Today it accepts any registered client's origin, and `/oauth/register` is open (phase 4 review should-fix 1). The helper has no callers yet; the new screens will be the first.

## Design questions (spec or mock gaps found while building)
- **Owner design change, 2026-10-01 (1a/1g sign-in):** Bryant asked for a narrower card, providers stacked one per row, and real provider marks. Built: sign-in uses a 440px column (`Page narrow`), `.id-providers` is one column, and `ProviderMark` replaces the dashed slot on 1a, 1g and 1e. The mocks were not edited, so 6 cases now differ from them by design: 1a, 1e and 1g at desktop and phone. The other 66 are at 0 px. **Open:** whether to update those mocks to the new design, or record the 6 cases as approved deviations. The gate stays at 66/72 until that's decided.
- **Owner design change, 2026-10-01 (dropdowns):** Bryant asked for our own dropdowns instead of the native one. Built without script: where a select can be styled (`appearance: base-select`, Chrome 135+), its open list now matches the card (panel, rounded rows, hover, checkmark, a short fade that reduced motion turns off). It stays a real `<select>`, so keyboard, screen readers, autofill and form posts are unchanged. Safari and Firefox keep their native list. The closed box is unchanged (0 px on every select screen: 3a, 4b, 5a, 5c). Used on 3a, 4b, 5a and 5d.
- **Owner design change, 2026-10-01 (3a on phones):** the Access radio cards (the only side-by-side radio group, `layout="row"`) stack full-width at ≤480px, in DOM order. `3a-consent.phone` now differs from its mock by design (61px taller); desktop 3a is unchanged. Gate: 65/72, the 7 differing cases all owner-directed (1a, 1e, 1g desktop+phone; 3a phone).
- **Owner design change, 2026-10-01 (narrow column on 13 more screens):** after measuring every screen at 440px (nothing clips; at most one extra description line), the narrow column now covers the whole sign-in journey and the account screens: 1b, 1c, 1d, 1e, 1f, 2a, 2b, 2c, 2e, 6a, 6b, 6c, 6d (with 1a and 1g). Consent and approvals (3a–3d, 5a–5d), the device flow (4b–4d) and errors (7a–7c) keep 560px for their permission lists and details. `worker/ui/screens/column-width.test.tsx` checks every fixture state. Phones are unchanged (the card is full-width there). **Gate: 53/72; all 19 differing cases are owner-directed:** 1a–1g, 2a, 2b, 2c, 2e and 6a–6d desktop; 1a, 1e, 1g and 3a phone. The open question above (update the mocks, or record approved deviations) now covers all 19.
- **Results that can't name the choice (phase 3).** Result templates are rendered before the person picks, and `fetch-form` reads the template name from the button, so after a JS swap 6b says "signed out of headless.ly" whatever scope was chosen, and 5a/5c/3d/4b omit the chosen policy, workspace or scope (the no-JS pages name them). Naming the choice needs a small `fetch-form.ts` change (pick the template from the checked `[data-done]` radio), but `fetch-form.js` is 2045 of 2048 B. Raise the budget, trim elsewhere, or accept.
- **2e on an email mismatch** disables Decline as well as Join (the server refuses either from the wrong account). screens.md#2e says only Join; update the spec if agreed.

## Blocked
—

Resolved: pushing to origin was blocked in phase 0 (`bryant22` had pull-only access). Owner access was granted on 2026-10-01; `product-update` is on origin and tracks `origin/product-update`.

## Incidents
- Phase 1, 2026-10-01: while proving the WorkOS stub by hand, one GET with a fake stub code reached production `https://id.org.ai/api/callback`. At that point the worker still sent WorkOS the production callback URL, and the hand-run curl followed the stub's redirect. Production refused it (403: the login state wasn't bound), and nothing changed. Since then the stub refuses non-loopback `redirect_uri`s, `pnpm dev:worker` keeps the local origin, and `test-visual/stub-smoke.mjs` refuses any non-loopback hop.

- Phase 5, 2026-10-01: during a manual browser check of `/oauth/authorize` on `wrangler dev`, an unauthenticated request was redirected to the production sign-in page (`https://id.org.ai/login?continue=…`): the OAuth provider's issuer was hard-coded to production. One GET of the public sign-in page; nothing was submitted. Since `edd17b1`'s follow-up, the provider's issuer is the local server whenever the WorkOS stub is configured and the request is loopback (`createOAuthProvider`, tested in `test/oauth-local-issuer.test.ts`), so local redirects stay local.

## Follow-ups
- auto.dev and headless.ly CLIs: adopt `spec/cli-output.md` (other repos).
- `worker/routes/mcp.ts` `nullStub` lacks 17 newer `IdentityStub` methods (L0 never calls them). It carries a `@ts-expect-error` so the worker typechecks; give it the full interface (phase 1).
- Only `test/ui-*.test.ts` are typechecked (`test/tsconfig.ui.json`); the rest of `test/` predates typechecking (phase 1).
- `test-visual/stub-smoke.mjs` (`pnpm test:stub-smoke`) needs a running `wrangler dev` and stub, so it isn't in `pnpm gate` (phase 1).
- **Before wiring each stay-on screen to its route (phases 5–10):** give 5a, 5b, 5c, 2e, 3d and 6b a generic `error` template for both regions (plus `error-expired` / `error-already_used` where they apply), as 4b has. Without one, a failed post leaves only the screen-reader status, a broken connector and a primary still labelled "Approving…" with `aria-busy` (phase 3 re-review should-fix 2). Also split `ErrorCard` into body and foot parts so those templates can reuse the catalogue copy.
- Phase 3 re-review nits: the Verified filter in Consent's source row is case-sensitive; export the trust-derived document title from `Consent.tsx` for the `/oauth/authorize` route; an already-used approval still offers "Start again" to `/login`; `fetch-form.test.tsx` injects templates that shadow 4b's real ones; the status region keeps the busy text after a swap; swapped-in templates aren't re-enhanced (logo fallback); 5c's "Claim from a repo" and 6b's Cancel stay clickable during a post; result states load unused scripts; 5b's "Nothing left headless.ly." could read "Nothing was sent from headless.ly."; 4b's `error-cancel` minutes go stale.
- Phase 4 review should-fix 2: inactive or pending WorkOS memberships count as members in `resolveCaller` and on org switch. Keep only `status === 'active'` (or pass `statuses=active`).
- Phase 4 review should-fix 3: admins can assign the owner role and change owners' memberships. Restrict both to owners.
- Phase 4 review should-fix 6 (B1 gaps): no `app.onError` (a thrown error on a browser route is `text/plain`); the magic-link guess budget renders the old form at 429, not "Too many tries…"; expired or used device codes render the old device page, not 7b; the `already_used` kind is never produced by the middleware; the request ID isn't written to logs or audit records.
- Phase 4 review nits: the catch-all 404 under `/api/*` is HTML for navigations; `wantsHtml` ignores q-values; `test/org-switch-roles.test.ts` never calls `assertNoPendingInterceptors`; DCR legacy-rehash tests cover only `client_credentials`; org switch mints `platformRole: superadmin` for any platform-org member; `listUserOrgMemberships` doesn't paginate past 100 or encode `user_id`; native key scopes are ignored on member routes; `POST /api/orgs` accepts `owner_sub` from any authenticated caller; B13.2 and B13.3 share one commit.
