# Phase 1 · Foundation

> **For agentic workers:** run this phase from `../autopilot.md`.

**Goal:** Make it possible to build the new screens properly:
- typed server components (`hono/jsx`) in a typechecked `worker/`;
- one stylesheet and small client scripts served as hashed static assets that survive the site build;
- the Geist font files;
- a shared page renderer with the security headers;
- a test seam for WorkOS;
- a dev-only design gallery with a frozen mode;
- the pixel-diff harness wired to it.

**Depends on:** Phase 0.

**Read first:** `../spec/backend.md#b0`, `../spec/security.md`, `../spec/layout.md`, `../spec/emails.md#gallery-preview`, `../tools/visual-diff.mjs`, `../mocks/manifest.json`.

**Architecture:**
- Views are `.tsx` files using `hono/jsx`, rendered on the server to a string. They are presentational only: typed props, no I/O.
- Routes fetch data and pass props.
- CSS is plain CSS with `id-` prefixed class names, built from `tokens.css` and `ui.css`.
- Client behaviour is progressive enhancement: small TS modules bundled with esbuild and loaded with `type="module"`.

## File map

| Path | Purpose |
|---|---|
| `worker/tsconfig.json` | Strict TS for the worker: `"jsx": "react-jsx"`, `"jsxImportSource": "hono/jsx"`. Runtime types come from the existing wrangler-generated `worker/worker-configuration.d.ts` only (no `@cloudflare/workers-types` in `types`, to avoid duplicate declarations). Includes `worker/**/*` and the `src/**` it imports. Excludes `worker/ui/client/**`. |
| `worker/ui/client/tsconfig.json` | `lib: ["ES2022", "DOM"]`, strict, no emit. Client scripts only. |
| `package.json` | Scripts: `typecheck` (`tsc --noEmit && tsc --noEmit -p worker && tsc --noEmit -p worker/ui/client`), `build:ui`, `test` (add `&& vitest run --config vitest.ui.config.ts`), `test:visual`, `gate`. devDependencies: `geist@1.7.2`, `pixelmatch@^7`, `pngjs@^7`, `esbuild`, `happy-dom`. |
| `vitest.ui.config.ts` | Node runner with `environment: 'happy-dom'` for `worker/ui/**/*.test.ts` (client scripts, the tokens-equality test, the component markup tests). The workers pool can't read host files or provide a DOM. |
| `scripts/build-ui.mjs` | Deletes `worker/public/auth/` and `worker/public/fonts/geist/`, then: bundles `worker/ui/client/*.ts` into `worker/public/auth/<name>.<hash>.js` (esm, minified); concatenates `worker/ui/tokens.css` + `worker/ui/ui.css` into `worker/public/auth/ui.<hash>.css`; copies the two Geist woff2 files from `node_modules/geist/dist/fonts/...` to `worker/public/fonts/geist/`; copies `worker/ui/static/**` to the same paths under `worker/public/`; writes `worker/ui/assets.json` (logical name → hashed path). |
| `worker/ui/tokens.css` | Copy of `docs/product-update/spec/tokens.css`. A test asserts the two are identical. |
| `worker/ui/ui.css` | Component CSS (phase 2 fills it). |
| `worker/ui/assets.ts` | Imports `assets.json` and exports `assetUrl('ui.css')` and similar. |
| `worker/routes/static-ui.ts` | `GET /auth/*` and `GET /fonts/*` call `c.env.ASSETS.fetch(c.req.raw)` and add `Cache-Control: public, max-age=31536000, immutable` to 200s. Mount before the catch-all. |
| `worker/ui/render.tsx` | `renderPage(c, element, opts)` returns a `Response`. It writes the doctype and `<html lang="en">`, a `<head>` (title, viewport meta, font preloads, the stylesheet, module scripts) and the headers and CSP from `spec/security.md`. `opts.formActionOrigin` extends `form-action`. `opts.frozen` adds `data-frozen` to `<html>` (gallery only). |
| `worker/ui/icons.tsx` | `<Icon name size />` from the table in `spec/icons.md` (stroke 1.75, `aria-hidden`). |
| `worker/ui/components/` | Only `Page.tsx`, `Header.tsx`, `Footer.tsx` and `Card.tsx` in this phase, which the smoke fixture needs. |
| `worker/ui/screens/` | Empty in this phase. |
| `worker/ui/gallery/fixtures/index.ts` | Merges `fixtures/<group>.ts` files (one per screen group, added in phase 3). The shape is `Record<slug, { default: Props; states?: Record<stateName, Props>; derived?: Record<stateName, Props> }>`. `states` keys match the manifest's state names exactly (`copied`, `connecting`, `verdict`, `signed`, `cancelling`, `cancelled`). `derived` holds the extra states that have no mock. |
| `worker/ui/gallery/routes.tsx` | `GET /__design` (index: every manifest slug and state plus every derived state, marking which have fixtures) and `GET /__design/:slug?state=<name>` (looked up in `states`, then `derived`). Mounted only when `c.env.DESIGN_GALLERY === '1'`, otherwise 404. Email slugs (8a–8c) render through the email preview (`../spec/emails.md#gallery-preview`), with no `style-src` restriction. |
| `worker/middleware/request-id.ts` | Uses `cf-ray`, or else `req_` plus 8 random base62 characters. Puts it on the context and sets the `X-Request-Id` response header. Mount it first. |
| `src/sdk/workos/base.ts` | `workosBase(env)` returns `env.WORKOS_API_BASE ?? 'https://api.workos.com'`. Replace every hard-coded `https://api.workos.com` (about 30, in `upstream.ts`, `keys.ts`, `pipes.ts`, `scim.ts`). No behaviour change in prod. |
| `test-visual/workos-stub.mjs` | A tiny local HTTP stub of the WorkOS endpoints the auth flows use (authorize redirect, authenticate, magic_auth, organizations, users, invitations), with fixture users. Point `wrangler dev` at it with `WORKOS_API_BASE=http://127.0.0.1:8788` for browser-level flow tests. |
| `worker/.dev.vars.example` | `DESIGN_GALLERY=1`, `WORKOS_API_BASE=http://127.0.0.1:8788`, and placeholder secrets that let `wrangler dev` boot. Wrangler reads `.dev.vars` next to `wrangler.jsonc`, which is in `worker/`. Add `worker/.dev.vars` and `test-visual/output/` to `.gitignore`. |
| `test/ui-foundation.test.ts` | Workers pool: the headers, CSP, gallery gate, request IDs and the static-ui cache header. |

## Gallery contract

The gallery must render each fixture **exactly as the mock shows it, and stay still**.

- `renderPage(..., { frozen: true })` sets `<html data-frozen>`. Every client script checks it:
  - **No timers, no polling, no redirects, no autofocus.** Countdowns don't tick, the claim status doesn't poll, and 2c doesn't redirect or emit its meta refresh.
  - Static enhancements still run (for example un-hiding the copy buttons), so the frozen render equals the mock.
- Props control visual state, never interaction:
  - `focusIndex` on CodeInput;
  - `copied` on CopyButton (the script must not reset a server-rendered copied state);
  - the connector `state`;
  - the button `busy` / `disabled`.
- Fixture strings are copied verbatim from the mock HTML.

## Tasks

### Task 1 · Typecheck the worker
- [ ] Add both tsconfigs. Make `pnpm typecheck` run all three projects.
- [ ] Fix existing worker type errors **only if they are trivial**. Otherwise add `// @ts-expect-error <reason>` with a follow-up in PROGRESS. Do not refactor unrelated code.
- [ ] Confirm wrangler bundles `.tsx` with the hono JSX runtime: `cd worker && npx wrangler deploy --dry-run --outdir /tmp/idorg-dry`.

### Task 2 · Static assets that survive the site build
- [ ] `scripts/build-ui.mjs` as above. It must be idempotent and leave no stale files.
- [ ] Set `predeploy` to `pnpm build:site && pnpm build:ui && pnpm build:dash`. `build:site` wipes `worker/public`, so `build:ui` must run after it.
- [ ] Commit the built output and `assets.json`, as the repo already does for `worker/public`.
- [ ] Add `worker/routes/static-ui.ts` with the immutable cache header. Test it.

### Task 3 · renderPage, security headers, request IDs
- [ ] Implement them as above. The CSP is exactly as `spec/security.md`.
- [ ] Test: a smoke page through `renderPage` has every header and no inline `<script>` or `style=` attribute.

### Task 4 · WorkOS test seam
- [ ] Add `workosBase(env)` and replace the hard-coded bases.
- [ ] The existing tests must pass unchanged. They use `fetchMock` on `api.workos.com`, which is still the default.
- [ ] Write `test-visual/workos-stub.mjs` with one smoke test: `wrangler dev` plus the stub serves `/login`.
- [ ] Add to PROGRESS: **never run `pnpm test:e2e`** (it hits production).

### Task 5 · Design gallery
- [ ] Gallery routes, gated by `DESIGN_GALLERY`, with the frozen contract.
- [ ] The index lists every slug and state from `docs/product-update/mocks/manifest.json` (import it as JSON).
- [ ] Add a temporary smoke fixture: the page shell plus an empty card. It proves fonts, CSS and headers end to end. Delete it in phase 3.
- [ ] Test: `/__design` is 404 without the flag and 200 with it.

### Task 6 · Visual-diff harness
- [ ] With the devDependencies installed, `node docs/product-update/tools/visual-diff.mjs --self-test` must report 72/72 passing at 0 px. If Playwright's browser is missing, run `npx playwright install chromium` or set `CHROMIUM_PATH`.
- [ ] `pnpm test:visual` runs `node docs/product-update/tools/visual-diff.mjs --base http://localhost:8787`. Extra arguments pass through (`pnpm test:visual --only 4b`).
- [ ] The harness's per-case allowances live in `test-visual/allowances.json`, keyed by case name, for example `4b-device-confirm--signed.desktop`. At most 4 px each, with a reason in PROGRESS. Don't edit the harness to change the bar.

### Task 7 · One gate command
- [ ] `pnpm gate` runs, in order: `pnpm build:ui` (first, so `assets.json` is fresh for typecheck and tests), `pnpm typecheck`, `pnpm test`, then `cd worker && npx wrangler deploy --dry-run --outdir /tmp/idorg-dry`.
- [ ] It must leave the working tree clean when nothing changed (`build:ui` is deterministic).
- [ ] The visual diff is separate because it needs `wrangler dev` running. The autopilot runs both.

## Acceptance
- `pnpm gate` is green, with no new test failures versus the phase 0 baseline, and `git status` is clean afterwards.
- `cd worker && npx wrangler dev` (with `worker/.dev.vars`) serves:
  - `/__design` and `/__design/<smoke>`;
  - Geist from `/fonts/geist/` (check `document.fonts`);
  - `/auth/ui.<hash>.css` with the immutable cache header.
- The visual-diff self-test is 72/72.
- `/__design` returns 404 when `DESIGN_GALLERY` is unset.

## Commit
Commit per task, for example `build(ui): hono/jsx views and a typechecked worker`, `build(ui): static assets pipeline`, `feat(ui): renderPage with security headers and request IDs`, `test: WorkOS base URL seam and local stub`, `test(ui): design gallery and visual-diff harness`. Then push.
