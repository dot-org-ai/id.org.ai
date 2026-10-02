# Phase 3 · Screens (UI only)

> **For agentic workers:** run this phase from `../autopilot.md`. You can run it in parallel with subagents: one per group below. Each owns only its own screen files and fixtures.

**Goal:** Every screen in `spec/screens.md` exists as a presentational component with typed props. It renders in the design gallery with fixtures that reproduce the mock text exactly, and it passes the pixel diff at 0 px on desktop and phone, in every state. No routes change in this phase. Wiring happens in phases 4–12.

**Depends on:** Phase 2.

**Read first:**
- `../spec/screens.md` (your group)
- `../spec/layout.md`
- `../spec/components.md`
- `../mocks/manifest.json`
- The mock HTML for each screen you build.

**Architecture:**
- **Screen files**: `worker/ui/screens/<Name>.tsx`, for example `SignIn.tsx`, `EmailCode.tsx` and `DeviceConfirm.tsx`.
  - Each exports `<Name>Props` and the component.
  - A screen composes components only. If you need new CSS, it belongs in a component. Add or extend one and add it to the component sheet.
- **Fixtures**: `worker/ui/gallery/fixtures/<group>.ts`, keyed by manifest slug, in the shape defined in `01-foundation.md` (`default`, `states`, `derived`).
  - Copy every string verbatim from the mock: names, emails, codes, times, counts.
  - Use the same monogram tiles as the mocks, not real logos.
- **States**: the manifest's state names (`copied`, `connecting`, `verdict`, `signed`, `cancelling`, `cancelled`) go in `states`, selected by `/__design/<slug>?state=<name>`.
  - Visual state comes from props (`copied`, `focusIndex`, connector `state`, `busy`), never from clicking.
- **Frozen**: gallery pages render with `data-frozen`, so nothing moves or navigates (see `01-foundation.md#gallery-contract`).
- **Emails** (8a–8c): build the real email templates in `worker/ui/emails/` following `../spec/emails.md`: tables, inline CSS, the hex palette, Geist via `@font-face`. Emails are the one place inline styles are required. The gallery renders the preview frame plus the template, which must match the mock.

## Groups (one subagent each)

| Group | Screens (slugs) |
|---|---|
| Sign in | 1a, 1b, 1c, 1d, 1e, 1f, 1g |
| Accounts | 2a, 2b, 2c, 2e |
| Authorize | 3a (+copied), 3b (+copied), 3c (+copied), 3d (+copied) |
| Devices | 4b (done in phase 2), 4c, 4d |
| Agents | 5a (+copied), 5b (phone only), 5c, 5d (+copied) |
| Security | 6a, 6b, 6c, 6d |
| Errors | 7a (+copied), 7b, 7c |
| Emails | 8a, 8b, 8c |

The flow map (0), connect motion (2d) and terminal (4a) are references, not pages. Don't build them.

## Tasks (per group)
- [ ] Read the screen's mock in a browser. List every component it needs and confirm each exists.
- [ ] Write the screen component and its props type. Add the derived states listed in `spec/screens.md` (errors, expired, mismatch, busy) as `derived` fixtures. They have no mock, so they are reviewed by eye against the rules, not diffed.
- [ ] Write the fixtures.
- [ ] `pnpm test:visual --only <slugs>` must pass at 0 px on every viewport in the manifest.
- [ ] Add a unit test per screen for its accessibility contract: one `h1`, labelled controls, forms posting to the route named in `spec/screens.md` with a CSRF field placeholder, and a `role=status` region where states change.

## Rules
- **The mock is the truth.** If the spec text and the mock disagree, match the mock and note the spec fix in PROGRESS.
- **Never edit `docs/product-update/mocks/`.** Never raise `--max-pixels`.
- If a diff won't go to 0 because of a genuine rendering-engine difference (for example a sub-pixel rounding in a nested flex, or a hex conversion in an email), document it in PROGRESS with the diff image path and the reason. Add an entry to `test-visual/allowances.json` keyed by case name (for example `"8a-email-sign-in-code.desktop": 3`). At most 4 px. That needs the reviewer's sign-off. Never edit the harness.

## Acceptance
- All 72 manifest cases pass: `pnpm test:visual` reports 72/72 at 0 px, or documented ≤4 px exceptions.
- Every derived state renders in the gallery.
- `pnpm gate` is green.

## Commit
One commit per group: `feat(ui): sign-in screens`, `feat(ui): account and workspace screens`, and so on. Push after the whole phase.
