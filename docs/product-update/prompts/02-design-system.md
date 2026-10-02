# Phase 2 · Design system

> **For agentic workers:** run this phase from `../autopilot.md`. Read `../spec/components.md` in full before writing any CSS.

**Goal:** Build every component in `spec/components.md` once: typed, accessible, and pixel-exact against the mocks. Add the client scripts that bring them to life (copy, code inputs, connector states, busy submit, countdown, live status). Screens in phase 3 should then be pure composition.

**Depends on:** Phase 1.

**Read first:**
- `../spec/components.md`
- `../spec/layout.md`
- `../spec/motion.md`
- `../spec/accessibility.md`
- `../spec/tokens.css`
- Then open the mock HTML for 1a, 3a, 4b and 5d in a browser with devtools. The computed styles are the truth.

**Architecture:**
- **Class names**: `id-` prefix, one block per component, modifiers with `--`. For example `.id-btn`, `.id-btn--primary`, `.id-btn--sm`, `.id-card`, `.id-card__body`, `.id-card__foot`, `.id-actions`.
- **CSS**:
  - Everything reads from the variables in `tokens.css`.
  - No `!important`, except inside the `prefers-reduced-motion` and ≤480px phone blocks, where the mocks use it.
  - Production CSS uses `min-height` for controls; the mocks use `height` plus `min-height`. The rendered size is identical.
- **Components**:
  - One `.tsx` per component in `worker/ui/components/`, exported from `worker/ui/components/index.ts`.
  - Props are typed with no `any`.
  - Rich text props (descriptions with highlighted names) take JSX children, never HTML strings.
- **Client scripts**:
  - `worker/ui/client/<name>.ts`, each self-initialising on `[data-js="<name>"]` elements, under 2 KB minified each.
  - No framework and no global state.
  - Every one degrades to a working no-JS form.
  - Every one honours the gallery's frozen mode (`<html data-frozen>`): no timers, polling, redirects or autofocus. See `01-foundation.md#gallery-contract`.

## Components to build (in this order)

1. **Foundations**: `Icon`, `Page`, `Header`, `Footer`, `Card`, `CardHead`, `CardFoot`, `Actions`, `FootNote`, `FootText`, `Dotted`.
2. **Controls**: `Button` (primary, secondary, ghost × sm, md; `href` renders an `<a>`; `busy`, `disabled`; on phones the action band sets 48px height through CSS, so there's no lg variant), `ProviderButton`, `Field`, `Select`, `Textarea`, `CodeInput`, `RadioCard` + `RadioGroup`, `Checkbox`, `CopyButton`, `Link`, `Pill`.
3. **Identity**: `Avatar`, `Who`, `AccountRow`, `AnotherAccountRow`, `AppTile` (bezel: logo / monogram / icon, plus the logo error fallback), `IconTile`.
4. **Content**: `Well` (and its variants), `KeyValue`, `PermissionList`, `SourceRow`, `Disclosure`, `CodeBlock`, `WarningCallout`, `Note`, `Steps`, `StatusList`, `Stats`, `Countdown`, `NameSub`.
5. **Connector**: `Connector({ left, right, state })`, with `idle | connecting | done | broken | ok | fail` exactly as `spec/motion.md`. It uses the same dot sizes, gaps, delays and keyframes, with `data-state` on the root so client code can switch states.

## Client scripts

| Script | Behaviour | Test |
|---|---|---|
| `copy.ts` | `[data-js=copy][data-value]`: clipboard write, check icon swap, `role=status` "Copied", revert after 1500ms, restart on a second click. It unhides itself (the button is `hidden` without JS), and it also unhides in frozen mode. It never resets a server-rendered copied state. | Fake timers and a clipboard stub. |
| `code-input.ts` | Auto-advance, Backspace back, arrow keys, paste to fill, uppercase for device codes, hyphen and space tolerance. It mirrors into one hidden `name="code"` input. | Typing, paste and backspace sequences. |
| `connector.ts` | `setConnector(el, state)`: re-renders the dots for a state by swapping `data-state` and restarting animations. It exports the timing constants from `spec/motion.md`. | The state attribute and the classes applied. |
| `submit.ts` | `[data-js=submit]` forms: on submit, set the connector to `connecting`; set the primary to busy (label from `data-busy-label`, `aria-busy`); disable the secondary. Forms marked `data-fetch` post with `fetch` (CSRF in a header), then call `onDone`/`onFail` hooks: verdict, a wait, then a swap or redirect, per `motion.md#where-the-person-goes-next`. | Fake timers: busy, done, the 2150ms swap; error, broken. |
| `device-confirm.ts` | The 4b state machine from `motion.md#device-confirm-4b-the-reference-state-machine`, built on `submit.ts`. | Exact timings: Confirm → signed after resolve + 2150ms; Cancel → cancelled after 1820ms. |
| `countdown.ts` | `[data-js=countdown][data-expires-at]`: **m:ss** every second (4:32, 0:42); `data-urgent` turns the text accent at ≤60s (5b only; the 1b resend timer stays fg-3); announces at 60s and 0, then calls the expiry swap (5b) or shows the "Resend code" link (1b). | Fake timers. |
| `claim-status.ts` | Polls a status URL every 5s, updates the StatusList and the connector (`connecting` → `done` → `ok`). | Mocked fetch. |

Client-script and component-markup tests run under `vitest.ui.config.ts` (happy-dom, set up in phase 1), not the workers pool.

## Tasks

### Task 1 · Port tokens and base styles
- [ ] `worker/ui/tokens.css` identical to the spec copy, with the font URLs pointing at `/fonts/geist/`.
- [ ] Base styles from `spec/layout.md`: body, focus-visible, placeholders, links, hover and pressed, `details[data-x]` marker hiding, chevron rotation, reduced motion, and the phone block (≤480px) for the card and actions.

### Task 2 · Components (in the order above)
- [ ] Each component with its CSS. Add each component to a component sheet at `/__design/components` that shows every variant.
- [ ] Unit tests for the rendered markup contract: roles, labels, `aria-*`, `type="submit"` / `type="button"`, and no inline `style=`.

### Task 3 · Client scripts
- [ ] As in the table, each with tests, bundled by `build:ui`.

### Task 4 · Pixel check on a composition
- [ ] Build fixtures and a screen for **4b-device-confirm** only, all six states, as the proof that the system reproduces the hardest mock.
- [ ] `pnpm test:visual --only 4b` must pass at 0 px for desktop and phone and every state.
- [ ] If it doesn't, fix the component. Never the mock.

## Acceptance
- `pnpm gate` is green.
- The component sheet renders every variant.
- The 4b visual diff passes: 0 px, desktop and phone, six states.
- Client script tests pass, including the exact timings.
- No component file contains a hex or oklch literal: everything comes from tokens. Check with `grep -R "oklch(" worker/ui/components` (should be empty).

## Commit
One commit per group: `feat(ui): foundations`, `feat(ui): controls`, `feat(ui): identity components`, `feat(ui): content components`, `feat(ui): connector and motion`, `feat(ui): client scripts`, `test(ui): 4b pixel parity`. Push.
