# Autopilot: id.org.ai auth redesign

You are Claude Code, implementing the id.org.ai auth redesign in this repo, on branch `product-update`. This file is the controller. It tells you how to run the whole update, phase by phase, without stopping, and how to know you are done.

**Start command** (what the owner types):

```
Read docs/product-update/autopilot.md and run it.
```

**Resume:** the same command. `PROGRESS.md` says where you are.

---

## 1 · Before anything else

1. Read in full:
   - `README.md` and `DECISIONS.md`;
   - every file in `spec/`;
   - the next phase's prompt in `prompts/`.
2. Open `mocks/screens/4b-device-confirm.html` and `mocks/screens/3a-consent.html` in a browser (Playwright is fine). Click through them, so you know what "done" looks and feels like.
3. Read `PROGRESS.md`. Continue from the first phase that isn't `done`.

## 2 · Ground rules (non-negotiable)

1. **Source of truth, in this order:**
   1. the mock HTML in `mocks/screens/` (exact values and copy);
   2. `spec/`;
   3. the phase prompt.

   When they disagree, follow the mock and fix the spec text in the same commit. **Never edit `mocks/`**, and never loosen the visual-diff bar to make something pass.
2. **Branch and deploy:**
   - Work only on `product-update`. Push it after every phase.
   - Never push to `main` or `release/*`.
   - Never run `pnpm deploy` / `wrangler deploy` (except `--dry-run`).
   - Never change a production value in `worker/wrangler.jsonc`, other than adding new flags that default off.
3. **Feature flags:**
   - Every new user-facing flow ships behind a flag that defaults off in `wrangler.jsonc` and on in `worker/.dev.vars.example`: `FEATURE_SESSIONS_V2`, `FEATURE_STEP_UP`, `FEATURE_PASSKEYS`, `FEATURE_OWN_EMAILS`, `DIRECT_MICROSOFT_APPLE`, and any you add, all listed in `README.md#flags`.
   - Security fixes are on by default. Where one could break an unknown caller, it gets an escape hatch that defaults to the secure value (`LEGACY_OPEN_WORKOS_ROUTES=0`).
   - The new visuals for existing routes (1a, 3a, 4b and so on) need no flag. They replace the old HTML once their phase's tests pass.
4. **Compatibility:**
   - API callers keep byte-identical JSON.
   - Existing routes keep working: `/login`, `/logout`, `/device`, `/magic-link/:flow`, `/claim/:token` (JSON), `/api/*`.
   - The existing test suite must stay green. Any failure that wasn't in the phase 0 baseline blocks the phase.
5. **Security:** `spec/security.md` applies to every page you touch. No inline scripts or styles (emails excepted). CSRF on every POST. Strict redirect resolution. Escape all request data.
   - **Never run `pnpm test:e2e`**: it targets production id.org.ai with real keys.
   - Flow tests run in the workers pool (`SELF.fetch` + `fetchMock`). Browser checks run against `wrangler dev` with `WORKOS_API_BASE` pointing at `test-visual/workos-stub.mjs`.
6. **No human waits:**
   - Decisions use the defaults in `DECISIONS.md`.
   - If something is genuinely blocked (for example it needs a dashboard change at WorkOS, or a secret you don't have), build everything up to that point, add an entry under **Owner steps** or **Blocked** in `PROGRESS.md` with exactly what's needed, and move to the next task that doesn't depend on it.
7. **Quality bar:**
   - Tests first for backend behaviour.
   - Pixel diff at **0 px** for UI. Documented engine-rounding exceptions only, ≤4 px, in `test-visual/allowances.json`, with the reviewer's sign-off.
   - Typed props and no `any`.
   - Components composed, not copied: if two screens need the same thing, it's a component.
8. **Repo conventions** (`CLAUDE.md`, `AGENTS.md`):
   - No semicolons, single quotes, 2-space indent.
   - Conventional commits with a body explaining why, ending with the repo's usual `Co-authored-by` trailer.
   - Use `bd` if installed.
   - "Landing the plane": `git pull --rebase`, then `bd sync` if available, then `git push`, and confirm `git status` is up to date.
9. **Scope:** auth flows only. The dashboard (`/dash`, Connected apps, Security, Approvals inbox) and the landing site are out of scope (D12). Don't touch them, except to keep their routes working.

## 3 · The loop

For each phase in `PROGRESS.md` whose status isn't `done`:

1. **Prepare**
   - Read the phase prompt and every spec section it lists.
   - Re-read `DECISIONS.md`; owners may have changed a default.
   - Set the phase to `in progress` in PROGRESS, with the start time.
2. **Plan**
   - Turn the prompt's tasks into your task list.
   - Where tasks are independent and touch different files, plan subagents (section 4).
3. **Build**
   - Implement task by task. Backend: write a failing test, make it pass, refactor. UI: make the gallery fixture match the mock, then run `pnpm test:visual --only <ids>` until it's 0 px.
   - Commit after each task.
4. **Gate:** all four must pass.
   - `pnpm gate`: `build:ui`, typecheck (root, worker and client), tests (workers pool plus `vitest.ui.config.ts`), `wrangler deploy --dry-run`. The tree must be clean afterwards.
   - With `cd worker && npx wrangler dev` running (`worker/.dev.vars` from the example, `DESIGN_GALLERY=1`): `pnpm test:visual`. From phase 3 on, that means **all** cases, not just this phase's.
   - The phase's own acceptance list.
   - No new failures against the baseline.
5. **Review**
   - Spawn a fresh reviewer subagent that has not seen your work. Give it:
     - the phase prompt;
     - the relevant spec files;
     - `git diff <phase start>..HEAD`;
     - this instruction: *"Check every acceptance item and every spec requirement this phase touches. List anything missing, untested, insecure, inconsistent with the mocks, duplicated (controls or links), or using hard-coded colours or inline styles or scripts. Mark each finding blocking or not."*
   - Fix every blocking finding, then re-run the gate.
6. **Land**
   - Update PROGRESS: status `done`, end time, gate results (test counts, visual X/72), assumptions made, owner steps, follow-ups.
   - Commit `docs(product-update): phase N done`, and push (landing the plane).
7. Continue to the next phase.

Stop only when phase 13 is `done` and its draft PR exists, or when every remaining task is blocked on owner steps. In that case write a clear summary at the top of PROGRESS.

**Before you stop for any reason** (finished, blocked, or running low on context), update `PROGRESS.md` with exactly where you are (phase, task, next step), commit, and push. The next session resumes from it.

## 4 · Subagents

Use them for independent, file-disjoint work, and give each one a complete brief. They don't share your context.

- **Phase 3:** one subagent per screen group (the table in `prompts/03-screens.md`). Each owns `worker/ui/screens/<its screens>.tsx` and `worker/ui/gallery/fixtures/<group>.ts`.
  - If one needs a new or changed component, it reports back; you make the component change centrally, then re-run all visual diffs.
- **Backend phases:** split by route file where tasks don't overlap. For example, in phase 9, sign out vs two-step vs passkeys.
- **Every phase:** one reviewer subagent at step 5 (above). In phase 13, a second, fully independent reviewer for the final pass.

A subagent brief contains:
- the goal;
- the files it owns;
- the files it must not touch;
- the spec sections and mocks it needs;
- the exact commands that must pass;
- an instruction to report what it changed and any spec questions.

## 5 · When things don't match

| Situation | Do this |
|---|---|
| Spec text vs mock | Follow the mock. Fix the spec in the same commit. |
| Mock vs a security rule | Follow the security rule, and keep the visual identical (for example move an inline style into CSS). If the visual must change, record it in PROGRESS under **Design questions**. Never silently change the design. |
| A screen needs a state the mock doesn't show | Build it from the same components following `spec/layout.md`. Add it to the gallery as a derived state. List it in PROGRESS so a designer can review it. |
| Backend capability is impossible as specified (for example a WorkOS API limitation) | Implement the closest safe behaviour behind its flag. Document it under **Design questions**. Continue. |
| A test from the baseline starts failing | Stop and fix before continuing. Never skip, delete or loosen an existing test, unless the behaviour it pins is intentionally replaced; in that case replace it with a test for the new behaviour, and say so in the commit body. |
| Merge conflict with an in-flight branch | Keep this branch's behaviour. Note the conflict in PROGRESS for the owners. |

## 6 · Definition of done (whole update)

- Phases 0–13 are `done` in PROGRESS.
- `pnpm gate` is green, and `pnpm test:visual` is 72/72 at 0 px (or documented ≤4 px exceptions).
- Every screen in `spec/screens.md` is reachable through its real route, wired to real data (WorkOS mocked in tests), with flow coverage (workers-pool route tests plus browser checks against `wrangler dev` with the WorkOS stub) of the flows in `prompts/13-qa-and-launch.md`.
- axe has zero violations; reduced motion is respected; the phone rules are verified.
- The security prerequisites (B13) are fixed with tests, apart from the owner decision D10.
- The legacy views are removed and `CLAUDE.md` is updated.
- A **draft PR** from `product-update` to `release/main-with-security-fixes` describes:
  - what shipped;
  - flags and their defaults;
  - owner steps;
  - decisions still open;
  - test and visual results;
  - follow-ups.
- Nothing is merged and nothing is deployed.
