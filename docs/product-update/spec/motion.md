# Motion: the connector

The connector is the one moving element in the auth UI: two app tiles joined by five dots that grow toward the destination. Pulsing means connecting. The middle dot becomes the verdict: a green check or the accent X, the same size. Nothing else on the page animates, except content fading in when a screen changes state in place.

The reference for every state, at real speed:

- `../mocks/screens/2d-connect-motion.html`: both stories on an 8s loop, plus the three resting cells.
- `../mocks/screens/4b-device-confirm.html`: live. Click **Confirm** or **Cancel**.
- `../mocks/screens/4b-device-confirm--{connecting,verdict,signed,cancelling,cancelled}.html`: each state on its own.

## Rules

1. **It starts on the person's click**: Allow, Confirm, Continue, Approve, Join, Claim. It never starts on page load.
2. **Pages reached afterwards show the result still** (`ok` / `fail`). There is no animation on load.
3. **Error pages** show the `fail` state still.
4. **Reduced motion** (`prefers-reduced-motion: reduce`): every animation is off. Each state renders in its resting form, and the page still swaps state on time.
5. **No spinner** anywhere. The connector, plus the busy button label, is the progress indicator.

## Geometry (card scale)

| Part | Value |
|---|---|
| Tiles | 56px app tiles (see `components.md#app-tile-bezel`) |
| Row | `display: flex; align-items: center; gap: 10px` |
| Dots wrapper | `padding: 0 8px` |
| Dots row | `gap: 9px` |
| Dot diameters, left to right | 3.8, 4.7, 5.6, 6.6, 7.5px (base 3, 3.75, 4.5, 5.25, 6 × 1.25) |
| Dot colour | `var(--id-fg)` |
| Opacity at rest | 0.3 (muted). Dots past a failure: 0.12 (dim). Connecting base: 0.45. |
| Verdict glyph box | 18 × 18px, centred on the middle dot (absolutely positioned, `left: 50%; top: 50%; margin: -9px 0 0 -9px`) |
| Check | `<path d="M5 12.5 9.5 17 19 7" pathLength="1" stroke-dasharray="1">`, stroke `var(--id-green)`, width 2.25, round caps and joins, viewBox 24 |
| X | Lucide `x` at 18px, stroke width 2.25, colour `var(--id-accent)` |
| Destination ring | Overlay on the destination tile: `position: absolute; inset: -1px; border-radius: 17px; border: 1.5px solid var(--id-ring-line); pointer-events: none; opacity: 0` |

## Timing constants

| Name | Value | Meaning |
|---|---|---|
| WAVE | 2.0s | Pulse period |
| ST | 0.155s | Stagger per dot |
| RISE | 0.28s | Time for a dot to reach its peak (14% of WAVE) |
| CROSS | 0.9s | RISE + 4 × ST: the pulse leaves the first dot and lands on the last |
| T0 | 0.2s | One-shot states start after a beat |
| S_AT | 0.95s | CROSS + 0.05: the success verdict lands just after the pulse |
| F_AT | 0.62s | RISE + 2 × ST + 0.03: the failure verdict lands just after the pulse peaks on the middle dot |

Easings: `--id-ease-out` `cubic-bezier(0.22, 1, 0.36, 1)`, `--id-ease-in` `cubic-bezier(0.5, 0, 0.75, 0)`, `--id-ease-inout` `cubic-bezier(0.65, 0, 0.35, 1)`.

## Keyframes (copy verbatim)

```css
@keyframes idwave {
  0%      { opacity: .3;  transform: scale(1);   animation-timing-function: cubic-bezier(.33, 0, .15, 1) }
  14%     { opacity: .85; transform: scale(1.2); animation-timing-function: cubic-bezier(.45, 0, .25, 1) }
  45%, 100% { opacity: .3; transform: scale(1) }
}
@keyframes idring   { 0% { transform: scale(1); opacity: .45 } 50%, 100% { transform: scale(1.25); opacity: 0 } }
@keyframes idmorph  { from { transform: scale(1); opacity: 1 } to { transform: scale(0); opacity: 0 } }
@keyframes idbreak  { from { transform: scale(.4); opacity: 0 } to { transform: scale(1); opacity: 1 } }
@keyframes idcheck  { from { stroke-dashoffset: 1 } to { stroke-dashoffset: 0 } }
@keyframes idfadein { from { opacity: 0; transform: translateY(4px) } to { opacity: 1; transform: none } }

@media (prefers-reduced-motion: reduce) {
  .id-connector *, .id-fade, .id-status-dot { animation: none !important }
}
```

The mocks mark animated nodes with `data-m` and switch them off with `[data-m] { animation: none !important }`. Any selector works, as long as it covers every animated node.

## States

Dot index `i` runs 0–4, left to right; the middle dot is `i = 2`.

### `idle`
- All dots static at opacity 0.3. No ring, no glyph.

### `connecting` (loops until the server answers)
- Every dot: `opacity: .45; animation: idwave 2s linear ${i × 0.155}s infinite; will-change: transform, opacity`. This gives delays of 0, .155, .31, .465 and .62s.
- Destination ring: `animation: idring 2s var(--id-ease-out) 0.9s infinite`. The app tile answers each pulse as it lands.

### `done` (plays once, then rests as `ok`)
- Every dot: `opacity: .3; animation: idwave 2s linear ${0.2 + i × 0.155}s 1`. One last pulse crosses all five dots at delays .2, .355, .51, .665 and .82s.
- Middle dot: wrapped in an element with `opacity: 0; transform: scale(0); animation: idmorph .2s var(--id-ease-in) 1.15s backwards`. It shows the dot until 1.15s, then shrinks away.
- Glyph (check): `animation: idbreak .3s var(--id-ease-out) 1.25s both`. It pops in from scale .4.
- Check path: `stroke-dashoffset: 0; animation: idcheck .3s var(--id-ease-inout) 1.27s backwards`. The tick draws itself.
- At about 1.57s the verdict is complete.

### `broken` (plays once, then rests as `fail`)
- Dots 0–2: `opacity: .3; animation: idwave 2s linear ${0.2 + i × 0.155}s 1`. The pulse leaves and dies on the middle dot.
- Dots 3–4: static at opacity **0.12**. They never light.
- Middle dot: `idmorph .2s var(--id-ease-in) 0.82s backwards`.
- Glyph (X): `idbreak .3s var(--id-ease-out) 0.92s both`.

### `ok` / `fail` (resting; pages reached afterwards)
- `ok`: dots at 0.3, the middle dot hidden (`opacity: 0; transform: scale(0)`), the check drawn.
- `fail`: dots 0–1 at 0.3, dots 3–4 at 0.12, the middle dot hidden, the X shown.

## Which screens use which state

| Screen | On load | On action |
|---|---|---|
| 1a, 1b, 1c, 1e, 1g, 2a, 2b, 2e, 3a–3d, 4b, 4c, 5a–5c, 6a–6d | `idle` | `connecting` on submit. See "Where the person goes next". |
| 1d | single id.org.ai tile, no connector | — |
| 2c Handing off | `connecting` (this page *is* the in-between moment) | — |
| 4d Device connected | `ok` | — |
| 5d Claim from a repository | `connecting` while waiting for the push | `done` when the claim lands, then `ok` |
| 1f, 7a, 7b, 7c (failures) | `fail` | — |

### Where the person goes next

- **They stay on id.org.ai** (4b device confirm, 5a approve agent, 5b approve action, 5c claim, 2e join, 3d admin approve, 6b sign out):
  1. Submit with `fetch`. The connector goes to `connecting` and the primary button goes busy.
  2. On success, switch to `done`, then wait for the verdict plus a 0.6s hold (2.15s after the switch: T0 + S_AT + 0.4 + 0.6) before swapping in the done content.
  3. On failure or refusal, switch to `broken` and show the error.
  4. Without JS the form posts normally and the server renders the done page with `ok`.
- **The browser leaves for the app** (consent Allow, account and workspace choice, sign-in, step-up):
  1. Go to `connecting` on submit, with the buttons busy.
  2. Let the form post and the redirect happen. Do not hold the redirect back to play a verdict.
  3. If the response is an error page, it renders `fail`.

## Device confirm (4b): the reference state machine

```
idle ──Confirm──▶ connecting ──server OK──▶ verdict(done) ──2150ms──▶ signed
  │                    │                                           (head: ok · body: account/workspace/device well · foot: "Wasn't you? Sign this device out")
  │                    └──server error──▶ broken ──▶ error message in place (foot: the error, primary "Try again")
  └──Cancel──▶ cancelling(broken; both buttons disabled) ──1820ms──▶ cancelled
                                                        (head: fail · "Sign-in cancelled" · foot: "Started it by mistake? Run auto.dev login again.")
```

- While `connecting` and during the verdict: Cancel is disabled (`opacity .45`), and Confirm is busy ("Confirming…", `opacity .7`, `aria-busy="true"`).
- While `cancelling`: both buttons are disabled.
- The swapped-in content uses `animation: idfadein .35s var(--id-ease-out) both`, on both the body block and the foot.
- The card is pinned to the top of the viewport (`layout.md#page-shell`), so its top edge and the connector never move when the body height changes.
- The mock waits 1300ms to stand in for the server. In production, `connecting` lasts exactly as long as the request.
- **Confirm**:
  - On click: `connecting` and busy at once, and `POST /device/decision` starts.
  - On `{ok:true}`: `done` at once, then swap in the signed content 2150ms later (T0 + S_AT + 0.4 + 0.6).
  - On an error: `broken` at once, then swap in the error content (the 7b copy for `expired` / `already_used`, the generic error otherwise) 1820ms later.
- **Cancel**:
  - On click: `broken` at once, both buttons disabled, and `POST /device/decision` (deny) starts. The timer starts at the **click**, as in the mock.
  - Swap to the cancelled content when **both** 1820ms (T0 + F_AT + 0.4 + 0.6) have passed **and** the deny succeeded.
  - If the deny fails, swap to the error content instead (the request may still be pending, so say "We couldn't cancel this request. Close this tab; the code expires in N minutes.").
- **Where the swapped content comes from**: the server renders all three bodies and feet into the page. The form is visible; the signed, cancelled and error variants sit in `<template data-state="…">` elements. The script clones the right template into the card body and foot. That matches the mock, which also has every state in the markup.
- **No-JS**: the form posts to `/device/decision` and gets a 303 to:
  - `/device/done?code=XXXX-XXXX` (4d), when the code is approved by this identity;
  - `/device/cancelled?code=XXXX-XXXX` (the cancelled card on its own).

  Reloading either page re-reads the code's state: approved shows 4d, denied shows cancelled, and anything else (expired, never decided) shows 7b.
- The mock's logic class (inside `4b-device-confirm.html`) is the reference implementation of these timers.

## Status-list pulse (5d)

The current step's 8px dot uses `animation: idwave 2s linear infinite`, the same curve as the connector, so the page has one rhythm.

## Testing motion

- Visual snapshots are taken with animations disabled (Playwright `animations: 'disabled'`). Infinite animations sit at their first frame and one-shot animations at their end state. This is what the mocks' PNGs show.
- Add a unit test for the state machine timings: fake timers; Confirm → busy at once → `done` on resolve → `signed` 2150ms later. Cancel → `cancelled` after 1820ms.
- Add one browser check (Playwright against the gallery, with `reducedMotion: 'reduce'`) that every connector node has `animation-name: none`.
