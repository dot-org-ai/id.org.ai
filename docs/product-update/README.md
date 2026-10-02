# Product update: auth UI redesign

**Status:** ready to build · **Date:** 2026-10-01 · **Owners:** Bryant Skarda, Nathan Clevenger · **Branch:** `product-update` (from `release/main-with-security-fixes`)

> **Where this runs:** this copy is kept in `dot-do/id.org.ai` (the landing site) for reference. The auth screens are served by the worker in **`dot-org-ai/id.org.ai`**, and every code path in these docs (`worker/…`, `src/…`) refers to that repo.
>
> To build, put this folder at `docs/product-update/` on a `product-update` branch of `dot-org-ai/id.org.ai`, cut from `release/main-with-security-fixes`. Then run the autopilot from there. The `product-update.bundle` from the design session already contains that branch.

This folder holds everything needed to rebuild every browser-facing id.org.ai auth screen and flow: sign-in, account and workspace switching, consent, CLI and device confirmation, agent approvals, claim, step-up, sign out, errors and emails. The bar is Linear, Resend and WorkOS quality. It is written so Claude Code can implement it end to end with `autopilot.md`, and so a person can review any part of it.

**Out of scope:** the dashboard (`/dash`, Connected apps, Security, Approvals inbox) and the landing site. Those come in a later update.

## How to run it

In Claude Code, from the repo root, on branch `product-update`:

```
Read docs/product-update/autopilot.md and run it.
```

The autopilot works through `prompts/00` to `13` in order. It records progress, assumptions and owner steps in `PROGRESS.md` and pushes after each phase. It never deploys and never merges. It finishes with a draft PR into `release/main-with-security-fixes`.

To run one phase by hand instead: `Read docs/product-update/autopilot.md, then run only prompts/05-consent.md.`

## What's here

| Path | What it is |
|---|---|
| `autopilot.md` | The controller prompt: ground rules, the phase loop, gates, reviews, subagents, definition of done |
| `PROGRESS.md` | Live status per phase, assumptions, owner steps, blockers |
| `DECISIONS.md` | Open product and engineering choices, with the default that gets built |
| `prompts/` | One plan per phase (00 preflight to 13 QA), each with tasks, acceptance gates and commits |
| `spec/layout.md` | Page shell, card anatomy, actions, phone rules, divider rules, copy rules |
| `spec/components.md` | Every component with exact CSS values, props, states and accessibility |
| `spec/tokens.css` | Design tokens (colours, shadows, radii, type, motion), ready to drop in |
| `spec/motion.md` | The connector: geometry, timings, keyframes, the state machine, reduced motion |
| `spec/screens.md` | Every screen: route, when it shows, data, actions, states, backend dependency |
| `spec/flows.md` | The sign-in pipeline and the sequences for OAuth, devices, agents and claim |
| `spec/backend.md` | Per capability: what exists in the live code (file and symbol), what to build, contracts, tests |
| `spec/security.md` | Headers, CSP, CSRF, redirects, budgets: the gates for every page |
| `spec/accessibility.md` | WCAG 2.2 AA requirements and checks |
| `spec/logos.md` | How app and provider logos work (`logo_uri`, monogram fallback, official marks) |
| `spec/cli-output.md` | CLI login output (id.org.ai here; the spec for the auto.dev and headless.ly CLIs) |
| `spec/icons.md` | Every icon the screens use: name, Lucide name, where it's used, exact SVG |
| `spec/emails.md` | Email palette (hex), type, layout and the gallery preview frame |
| `mocks/screens/*.html` | **The reference design.** One standalone HTML per screen, plus one per state |
| `mocks/png/*.png` | 1x screenshots of every screen and state, desktop (720) and phone (390) |
| `mocks/fonts/` | Geist and Geist Mono variable fonts (`geist@1.7.2`, SIL OFL) used by the mocks |
| `mocks/manifest.json` | Every screen and state, its file and its comparison viewports |
| `tools/visual-diff.mjs` | Pixel diff of the implementation's design gallery against the mocks |

## Mock HTML or screenshots?

**The mock HTML is the source of truth; the screenshots are for looking.** Every number in the specs (spacing, sizes, colours, shadows, timings) comes from the HTML, so open it in a browser and read the computed styles.

Don't copy the HTML's markup. It uses inline styles, and the production pages must not (CSP: `spec/security.md`). Build components with classes and tokens that reproduce it exactly, then prove it with the pixel diff. The same Chromium, the same font files and the same CSS values produce identical pixels, so the bar is **0 differing pixels** per screen. That is measured with pixelmatch at a colour threshold of 0.05, counting anti-aliased pixels, so a 1px padding or 2px radius change fails. Documented engine-rounding exceptions are allowed up to 4 px, in `test-visual/allowances.json`.

The live mocks behave like the canvas:
- `4b-device-confirm.html`: click Confirm or Cancel to run the real state machine.
- Copy icons copy to the clipboard and show the check.
- `2d-connect-motion.html`: the motion spec on a loop.

To view them, open any file directly in a browser, or serve the folder:

```
npx serve docs/product-update/mocks
```

## Running the checks

```bash
pnpm install
pnpm gate                       # typecheck (root + worker), tests, build:ui, wrangler dry-run

cp worker/.dev.vars.example worker/.dev.vars   # once; wrangler reads .dev.vars next to wrangler.jsonc
cd worker && npx wrangler dev   # serves the app on :8787 with /__design
pnpm test:visual                # in another shell, from the repo root; 72 cases at 0 px
pnpm test:visual --only 3a,4b   # a subset

node docs/product-update/tools/visual-diff.mjs --self-test   # mocks against mocks: proves the harness
```

Phase 1 creates `pnpm gate`, `pnpm test:visual`, `worker/.dev.vars.example`, the WorkOS stub and the gallery. Before that, only `--self-test` works (it needs the `playwright`, `pixelmatch` and `pngjs` devDependencies). Diff images land in `test-visual/output/`.

**Never run `pnpm test:e2e` for this work.** It targets production id.org.ai with real keys from `.env`. Flow tests run in the workers pool, and browser checks run against `wrangler dev` with `WORKOS_API_BASE` pointing at the local stub.

## Flags

Every new flow ships behind a flag that defaults off in `worker/wrangler.jsonc` and on in `worker/.dev.vars.example`. The autopilot keeps this table current.

| Flag | Default (prod) | Turns on |
|---|---|---|
| `DESIGN_GALLERY` | unset, never set in `wrangler.jsonc` | `/__design` gallery (local only) |
| `FEATURE_SESSIONS_V2` | `0` | Server-side session records, multiple accounts, the account chooser (phase 8) |
| `FEATURE_STEP_UP` | `0` | Step-up before act permissions and on `max_age` (phase 9) |
| `FEATURE_PASSKEYS` | `0` | In-house passkey sign-in, step-up and the add-passkey offer (phase 9, D5). Off: the passkey button hands off to hosted AuthKit. |
| `FEATURE_OWN_EMAILS` | `0` | Our email templates and sender instead of WorkOS's (phase 12, D4) |
| `DIRECT_MICROSOFT_APPLE` | `0` | Microsoft and Apple as direct WorkOS providers instead of hosted AuthKit (owner enables them in WorkOS first) |
| `LEGACY_OPEN_WORKOS_ROUTES` | `0` (secure) | Escape hatch: `1` restores unauthenticated `/admin-portal`, `/fga/*`, `/pipes/*` if an unknown caller breaks (phase 4) |

**Config** (not on/off flags):

| Variable | Prod value | Meaning |
|---|---|---|
| `VERIFIED_CLIENT_HOSTS` | `chatgpt.com,claude.ai` (D3) | CIMD hosts whose `client_name` is trusted and which get the verified consent screen |
| `WORKOS_API_BASE` | unset (`https://api.workos.com`) | Test seam: the local WorkOS stub in dev and tests |

## Design source

The screens were designed on the id.org.ai Auth design canvas (a private Claude artifact; ask Bryant for access). `mocks/` is an export of that canvas. If the design changes, re-export it rather than editing the mocks by hand.

## What the audit found (read before building)

`spec/backend.md` lists what the live code already does. Highlights:
- Consent, CIMD, the device flow, magic-link codes, login-state binding and grant revocation exist.
- Multiple accounts, `prompt` / `max_age`, step-up, workspace choice per app, HTML errors, request IDs, device metadata, browser agent approval, one-click claim and sign-out scopes do not.

It also lists security gaps to fix first (B13):
- unauthenticated `/admin-portal`, `/fga/*` and `/pipes/*`;
- org routes without membership checks;
- the continue policy in `report` mode in prod;
- DCR secrets stored in plaintext;
- device decisions without a CSRF token.
