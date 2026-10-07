# Phase 13 · QA and launch readiness

> **For agentic workers:** run this phase from `../autopilot.md`. Use a fresh reviewer subagent for Task 4, one that did not write the code.

**Goal:** Prove the whole update against the design, the flows, accessibility and security. Remove dead code. Leave a PR the owners can merge with confidence.

**Depends on:** Phases 1–12.

## Tasks

### Task 1 · Full visual regression
- [ ] `pnpm test:visual`: 72/72 at 0 px, or only the documented exceptions.
- [ ] Render every derived state in the gallery and review it against `spec/layout.md` (dividers, actions, phone rules).
- [ ] Live pages: for each route that renders a screen, run `wrangler dev` against `test-visual/workos-stub.mjs` (`WORKOS_API_BASE`) with fixture users. Screenshot the live page and diff it against the gallery render of the same fixture. This proves the route wires the same component and props.

### Task 2 · Flows end to end

Run these as route-level tests in the workers pool (`SELF.fetch` + `fetchMock`), plus a browser pass against `wrangler dev` with the WorkOS stub. **Never `pnpm test:e2e`**: it targets production.
- [ ] OAuth with a fresh browser: 1a → 1b → 1d → 2b → 3a → app.
- [ ] Returning person on a trusted app: no screens at all.
- [ ] `prompt=select_account` with two sessions: 2a → back.
- [ ] `sb:do` with a stale sign-in: 3a → 6a → back.
- [ ] Device: 4a CLI → 4b Confirm → CLI prints success. Cancel → CLI prints cancelled.
- [ ] Agent: register → 5a approve → 5b approval → agent proceeds.
- [ ] Claim: 5c one click; 5d by commit (simulated webhook).
- [ ] Blocked app: 7c → request → 3d approve → retry passes.
- [ ] Sign out: each scope.
- [ ] Errors: a bad `redirect_uri` gives 7a with no redirect. Expired flows give 7b.

### Task 3 · Accessibility and motion
- [ ] axe-core on every gallery screen and state, with zero violations.
- [ ] A keyboard pass on 1a, 1b, 3a, 4b, 5a and 6b (documented in PROGRESS).
- [ ] `prefers-reduced-motion: reduce`: assert `animation-name: none` on every connector node, and that states still swap on time.
- [ ] Phone (390×844): primary on top, 48px buttons, an edge-to-edge card, and no horizontal scroll at 320px.

### Task 4 · Independent review
- [ ] A reviewer subagent gets:
  - `spec/` and `mocks/`;
  - the full diff against the base commit;
  - this checklist.

  It reports any spec requirement without a test, any security rule broken, any duplicated control or link, any inline style or script (outside emails), and any hard-coded colour.
- [ ] Fix every blocking finding.

### Task 5 · Clean up and document
- [ ] Remove the legacy views once nothing references them: `worker/views/provider-picker.ts`, `worker/views/org-picker.ts` (only after phase 8 rewired `organization_selection_required` to 2b), `renderDeviceVerificationPage`, `deviceApprovedHtml`, and the magic-link inline `page()`/`codeForm`.
- [ ] Keep `generateConsentScreenHtml`: it is a public SDK export, deprecated in phase 5.
- [ ] Update `CLAUDE.md` (the stale `src/do`, `src/db` paths, plus a short "Auth UI" section pointing to `worker/ui/` and the gallery).
- [ ] Document every flag and env var in `docs/product-update/README.md#flags` with its prod default.
  - All new flows default **off** in `wrangler.jsonc`, except where a phase made them safe and on by design.
  - `DESIGN_GALLERY` is never set in `wrangler.jsonc`.
- [ ] Open a **draft PR** from `product-update` into `release/main-with-security-fixes` (D1). The body includes:
  - what shipped, phase by phase;
  - flags and their defaults;
  - owner steps (WorkOS dashboard email setting, D3/D4/D5/D10 decisions, provider marks, first-party brand files);
  - the test and visual-diff summary;
  - known follow-ups.
- [ ] Do not merge and do not deploy.

## Acceptance
- Every task is ticked in PROGRESS and the draft PR exists.
