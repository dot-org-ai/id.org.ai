# Components

These are the building blocks of every auth screen. Each entry gives exact CSS values (they match the mocks), the props the component takes, its states and its accessibility contract. Colours, shadows and radii refer to the variables in `tokens.css`.

Build each one once, as a typed server component (see `../prompts/02-design-system.md`), and compose screens from them. A screen should not need its own CSS beyond layout glue.

Icons are Lucide geometry (ISC licence) drawn at **stroke-width 1.75**, not Lucide's default of 2. Sizes are given per use. The name → path table is `icons.md` (copied from the mocks).

---

## Page, Header, Footer

See `layout.md#page-shell`.

- Props: `title` (document title), `brand?: { name, mark }` for a branded app (1g), `secured?: boolean` (1g footer), `headerRight?: node` (5b countdown), `pinTop?: boolean` (4b).
- Document `<title>`: "Sign in · id.org.ai", "Authorize Codex · id.org.ai" and so on.
- Response headers on every auth page: `Cache-Control: no-store`, `X-Frame-Options: DENY`, `Content-Security-Policy: frame-ancestors 'none'` plus the CSP in `security.md`, and `Referrer-Policy: no-referrer`.

## Card, CardHead, CardFoot

See `layout.md#card-anatomy`. Props:

- `Card`: `children` (the body), `foot` (node).
- `CardHead`: `connector` (node), `title` (string), `description` (rich text, with highlighted names).
- `CardFoot`: `children`.
- `data-card` / `data-card-body` hooks (or classes) carry the phone rules.

## App tile (bezel)

The 56px tile the connector joins.

- `width/height: 56px; box-sizing: border-box; border-radius: 16px; background: var(--id-bezel-bg); border: 1px solid var(--id-bezel-border); box-shadow: var(--id-bezel-shadow); display: flex; align-items: center; justify-content: center; flex-shrink: 0; color: var(--id-fg); font-weight: 600; letter-spacing: -0.01em`.
- Content options:
  - **id.org.ai**: the org.ai mark at 28px.
  - **App logo**: the app's `logo_uri` image, `object-fit: contain`, about 32px. See `logos.md`.
  - **Monogram fallback**: 1–2 letters. Font size 22px for one letter, 19px for two (20px for `.d`).
  - **Icon**: for a CLI, agent, device, key, shield or clock, an icon at 24px (bot at 26px).
- Props: `logoUrl?`, `monogram?`, `icon?`, `label` (accessible name; the tile itself is decorative inside the connector).

## Connector

The signature element: two app tiles joined by five dots. Full spec, timings and keyframes are in `motion.md`.

- Props: `left`, `right` (tiles), and `state`: `idle | connecting | done | broken | ok | fail`.
- Layout at card scale (k = 1.25):
  - Row `display: flex; align-items: center; gap: 10px`.
  - Dots wrapper `padding: 0 8px`; dots row `gap: 9px`.
  - Dot diameters `3.8, 4.7, 5.6, 6.6, 7.5px`, `background: var(--id-fg)`, opacity 0.3 at rest.
  - Verdict glyph box 18px.
- Direction: **id.org.ai on the left, the app on the right**. Where the app is the requester (agent action 5b, claim 5c/5d), the requester is on the left and id.org.ai on the right. Admin approval (3d) goes app → workspace.
- `aria-hidden="true"`: the title says what is happening. Announce state changes through the page text, not the dots.

## Button

| Size | Height | Padding | Radius | Font | Use |
|---|---|---|---|---|---|
| `md` (default) | 44px | 0 16px | 10px | 14px / 500 | Everything in the auth column |
| `sm` | 32px | 0 12px | 8px | 13px / 500 | Secondary inline actions (for example "Sign out of all accounts") |

On phones (≤480px), buttons in the action band change **height only**, to 48px. Radius stays 10px and the font stays 14px; this is the `[data-actions] > *` rule in `layout.md#phones-viewport--480px`. There is no `lg` variant.

- Base: `box-sizing: border-box; min-height: <height>; flex-shrink: 0; display: flex; align-items: center; justify-content: center; gap: 8px; font-family: inherit; white-space: nowrap; cursor: pointer; text-decoration: none`.
- Icon: 16px, before the label.
- Variants:
  - **Primary**: `background: var(--id-fg); color: var(--id-bg); border: 1px solid var(--id-fg); box-shadow: var(--id-sh-primary)`. Hover `filter: brightness(0.93)`.
  - **Secondary**: `background: var(--id-panel); color: var(--id-fg); border: 1px solid var(--id-line-2); box-shadow: var(--id-sh-ctrl)`. Hover `filter: brightness(1.14)`.
  - **Ghost**: `background: transparent; color: var(--id-fg-2); border: 1px solid transparent`. Hover `background: var(--id-hover-ghost)`.
- In the action band, buttons are `width: 100%`.
- States:
  - Pressed: `transform: scale(0.985)`.
  - Disabled: `opacity: 0.45; cursor: default`.
  - Busy (primary): `disabled`, `opacity: 0.7; aria-busy="true"`, and the label changes to the progressive form ("Confirming…", "Allowing…", "Signing in…").
- Render as `<a>` for navigation and `<button type="submit">` inside forms. Never use a `<div>`.

## Provider button

Same box as a secondary `md` button with `justify-content: flex-start; padding: 0 14px`.

- Contents: the provider mark (18px), the name (`flex-grow: 1; text-align: left`), and an optional "Last used" pill: `font-size: 11px; line-height: 16px; padding: 1px 6px; border-radius: 99px; background: var(--id-raised); color: var(--id-fg-2); font-weight: 500`.
- Providers: GitHub, Google, Microsoft, Apple.
- Layout: `display: grid; grid-template-columns: repeat(auto-fit, minmax(min(200px, 100%), 1fr)); gap: 10px`, which gives 2×2 on desktop and one column on phones.
- Marks: the official mark of each provider, at 18px. The mocks show a dashed 18px placeholder where the mark goes. See `logos.md`.

## Field (label + input)

- Wrapper: column, `gap: 6px`.
- Label row: `display: flex; justify-content: space-between; align-items: baseline`.
  - `label`: 13px/500, `var(--id-fg-2)`.
  - Optional right hint: 12px, fg-3 (for example "From GitHub").
- Input: `box-sizing: border-box; width: 100%; height: 44px; padding: 0 14px; border-radius: 10px; background: var(--id-panel); border: 1px solid var(--id-line-2); box-shadow: var(--id-sh-input); color: var(--id-fg); font: 14px var(--id-font); outline: none`.
  - Placeholder in fg-3.
  - Focus: `border-color: var(--id-select)`.
- Optional hint below: 12px/18px, fg-3.
- Errors: replace the hint with the error text in `var(--id-accent)`, set `aria-invalid="true"`, and link it with `aria-describedby`.

## Select

- Same box as the input, plus `appearance: none; padding-right: 36px; cursor: pointer`.
- A chevrons-up-down icon (14px, fg-3) sits absolutely at `right: 12px`, with pointer-events off.
- Label as in Field.

## Textarea

- Same box as the input, with `height: auto; padding: 12px 14px; line-height: 20px; resize: none`, and 3 rows.

## Code input

The one-character boxes for email codes, authenticator codes and device codes.

- Row: `display: flex; gap: 8px; justify-content: center`.
- Each box: `box-sizing: border-box; flex: 1 1 0; min-width: 0; border-radius: 10px; border: 1px solid var(--id-line-2); background: var(--id-panel); box-shadow: var(--id-sh-input); color: var(--id-fg); text-align: center; font-family: var(--id-mono); font-weight: 500; outline: none`.
  - The boxes stretch to share the row equally (`flex: 1 1 0; min-width: 0`). The mock also sets `width: 46px` / `42px`, but flex overrides it, so the computed width is about 77px per box (6 boxes) or 53.4px (8 boxes) in the 560px card.
  - 6-digit codes: `height: 54px`, 22px type.
  - 8-character device codes: `height: 52px`, 20px type, and a "–" separator (18px, fg-3, `align-self: center`) after the fourth box.
- Focused box: `border-color: var(--id-select); box-shadow: var(--id-sh-input), var(--id-ring)`.
  - The mocks show this style statically on one box (1b: the 5th; 4c: the 1st; 6d: the 3rd) without real focus. Give the component a `focusIndex` prop that renders the same style through a class (`.is-focused`), so the gallery matches.
  - In production, the script focuses the first empty box on load. The gallery's frozen mode skips that (`../prompts/01-foundation.md#gallery-contract`).
- Behaviour (progressive enhancement over a single text input):
  - Typing advances to the next box; Backspace on an empty box goes back.
  - Pasting a full code fills every box. Accept "WDJB-MJHT", "wdjbmjht" and "WDJB MJHT"; uppercase device codes.
  - `inputmode="numeric"` for digit codes. Set `autocomplete="one-time-code"` on the first box (or on a hidden single field that is the real form value).
  - Completing every box does not auto-submit; the person presses Verify / Continue.
  - Accessible name per box: "Character N of 6". The mock says "Character N", which isn't visible, so it doesn't affect the diff. The mock also uses `inputmode="text"` everywhere; production uses `numeric` for digit codes.

## Radio card

- `<label>` wrapping a visually hidden radio input:
  - `box-sizing: border-box; display: flex; gap: 12px; padding: 14px; border-radius: 12px; border: 1px solid var(--id-line-2); background: var(--id-panel); box-shadow: var(--id-sh-ctrl); cursor: pointer; flex: 1 1 0; min-width: 0; transition: border-color .15s, background .15s`.
  - Checked: `border-color: var(--id-select); background: var(--id-raised); box-shadow: var(--id-sh-ctrl), var(--id-ring)`.
- Ring: 16px circle, `border: 1.5px solid` (fg-3, or fg when checked), `margin-top: 2px`. When checked it holds an 8px fg dot.
- Text column, gap 3px:
  - Title: 14px/500, fg.
  - Optional accent marker after the title: a 6px dot in `var(--id-accent)` for elevated choices (Read and act, Privileged, Sign out everywhere).
  - Description: 13px/19px, fg-3.
- Groups:
  - Vertical stack with gap 8px under a 13px/500 fg-2 group label.
  - Consent's two access levels sit side by side: `display: flex; gap: 10px; flex-wrap: wrap`.

## Checkbox

- Label row: `display: flex; align-items: center; gap: 10px; min-height: 24px; font-size: 13px; color: var(--id-fg-2)`.
- Box: 16px, radius 5px, `border: 1.5px solid` (fg-3; fg when checked).
- Checked: fill fg with a 12px check in `var(--id-bg)`.
- The real `<input type="checkbox">` is visually hidden, not `display: none`, so it stays focusable.

## Who row (signed-in account)

- `display: flex; align-items: center; gap: 12px; padding: 0 2px`.
- Contents:
  - Avatar, 32px.
  - Name: 14px/500.
  - Email: 13px, fg-3.
  - On the right: "Switch" (Link). With `FEATURE_SESSIONS_V2` on, it goes to `/account/choose?continue=<current request>`. With it off (phases 5–7), it goes to `/login?prompt=login&continue=<current request>`, which replaces the session.
- Variants:
  - The right slot can be empty (sign out, link account, admin approve).
  - The right slot can hold a meta text instead (step-up: "Confirmed 3 hours ago", 13px fg-3, nowrap).
  - Admin approval shows the admin ("Nathan Clevenger", "nathan@do.industries · Drivly admin").

## Avatar

- Circle: `background: var(--id-raised); border: 1px solid var(--id-line-2); box-sizing: border-box`.
- Initials in 600 weight at `max(10px, floor(size × 0.36))`, which gives **11px** at 32 and **12px** at 34.
- Sizes: 32 (who row) and 34 (account row).
- When the identity has a profile photo, show it cropped to the circle with the same border.

## Account row (account chooser)

- A link row:
  - `box-sizing: border-box; width: 100%; display: flex; align-items: center; gap: 12px; padding: 12px 14px; min-height: 60px; border-radius: 12px; border: 1px solid var(--id-line-2); background: var(--id-panel); box-shadow: var(--id-sh-ctrl); color: var(--id-fg); text-decoration: none`.
  - Hover `filter: brightness(1.14)`.
- Contents:
  - Avatar, 34px.
  - Name (14px/500) with an optional badge ("Last used here"): `font-size: 11px; padding: 1px 6px; border-radius: 99px; background: var(--id-raised); color: var(--id-fg-2); font-weight: 500`. It has no explicit line-height (normal).
  - Email (13px, fg-3).
  - Chevron-right (16px, fg-3) on the right.
- "Use another account" row: the same size, padding and radius, but `background: transparent`, **no shadow**, `border: 1px dashed var(--id-line-2); color: var(--id-fg-2); font-size: 14px`, and a plus icon (18px) in a 34px slot.
- Stack gap: 10px.

## Well

A sunk box for read-only facts.

- `box-sizing: border-box; border-radius: 14px; background: var(--id-sunk); border: 1px solid var(--id-line); box-shadow: var(--id-sh-input); padding: 16px; display: flex; flex-direction: column; gap: 8px`.
- Variants:
  - **Device code** (4b): padding 22px 16px, gap 10px, centred.
    - Code: mono 32px/40px, weight 500, `letter-spacing: 0.14em`.
    - Meta line underneath: laptop icon (14px) plus "macOS · Miami, FL · requested 1 min ago" (13px fg-3, gap 8px).
  - **Key/values** (2e, 4d, 5b): a KeyValue list.
  - **Stats** (5c): see Stats.
  - **Quote** (3d): padding 14px 16px. Send icon (14px, fg-3, padding-top 3px) plus the quoted note (14px/21px, fg-2), gap 12px.
  - **Email preview** (5b): KeyValues (gap 6px), then a block with `border-top: 1px solid var(--id-line); margin-top: 4px; padding-top: 10px` (13px/20px, fg-2), then a "View full email" Link.

## KeyValue

- Row: `display: flex; justify-content: space-between; gap: 16px; font-size: 13px; line-height: 20px`.
- Key: fg-3, no shrink.
- Value: fg, right-aligned, `overflow-wrap: anywhere`. Mono values (codes, IDs, URLs) use 12px mono.

## Dotted rule

See `layout.md#dividers`. The dot colour is `var(--id-dot)`.

- Props: `label?` (the "or" variant).
- `aria-hidden="true"`. The labelled variant is plain text ("or") for screen readers, or hidden if it is redundant.

## Permission list (expandable)

- Heading: 13px/500, fg-2. Then the list (gap 4px between heading and list).
- Each row is a `<details>`:
  - Rows are separated by `border-top: 1px solid var(--id-line)`, except the first row.
  - `summary`: `display: flex; align-items: center; gap: 12px; padding: 12px 0; cursor: pointer; list-style: none` (also hide the WebKit marker).
    - Icon: 16px, fg-2, or accent for act permissions.
    - Title: 14px/20px fg. Act permissions are weight 500 with a sub-line under them (13px/19px, accent; for example "Changes are made in your name."). Title and sub-line are a column with gap 2px.
    - Chevron-right: 14px, fg-3, rotating 90° when open (`transition: transform .2s`).
  - Panel: `padding: 0 0 12px 28px; display: flex; flex-direction: column; gap: 6px`.
    - Detail sentence: 13px/19px, fg-2.
    - Raw scope string: mono 12px, fg-3. For example `sb:do · resource https://api.sb`.
- Props: `heading`, and `items[] { icon, title, detail, scope, act?: boolean, actNote? }`.
- Data comes from the scope registry (`backend.md#b2`).

## Source row (who is asking)

The app's identity, with a copy action.

- Row: `display: flex; align-items: flex-start; gap: 10px`.
- Left: a `<details>`:
  - `summary`: `display: flex; align-items: center; gap: 10px; min-height: 32px`.
    - Icon (16px fg-3): globe for an app, key for an agent key.
    - Text: 14px fg, or 13px mono for keys and fingerprints. `text-decoration: underline dotted var(--id-fg-3); text-underline-offset: 4px`, with ellipsis on overflow.
    - Chevron-down: 14px fg-3, rotating 180° when open.
  - Panel: `padding: 8px 0 2px 26px; gap: 4px`.
    - KeyValues: "Runs on", "Returns to", "Identified by". Add "Verified: No" only for unverified clients (3c).
    - Then the app's own privacy policy and terms links (13px, gap 16px, padding-top 4px).
- Right: CopyButton (icon-only). It copies the full value: the CIMD URL, `client_id` or fingerprint.

## Copy button

- Icon-only:
  - `width/height: 32px; border-radius: 8px; border: 0; background: transparent; color: var(--id-fg-3); display: flex; align-items: center; justify-content: center; cursor: pointer`, with the copy icon at 14px.
  - Hover: `color: var(--id-fg); background: var(--id-hover-icon)`, transition `color .15s, background-color .15s`.
- Labelled variant (error details): `height: 32px; padding: 0 8px; margin-left: -8px; gap: 6px; font-size: 12px; align-self: flex-start`, showing the icon plus "Copy details".
- On click:
  - Write the value to the clipboard with `navigator.clipboard.writeText`.
  - Swap the icon for a check: 14px, `stroke: var(--id-green)`, stroke-width 2.25.
  - The labelled variant also changes its text to "Copied" (fg-2).
  - The icon-only variant puts a visually hidden "Copied" in a `role="status"` element.
  - After **1.5s** it reverts. A second click restarts the timer.
- No-JS: the value stays visible and selectable, and the button is hidden (`hidden` until the script runs).

## Note (inline)

- `display: flex; gap: 8px; font-size: 13px; line-height: 20px; color: var(--id-fg-3)`. Optional 14px icon with `margin-top: 2px`.
- Uses:
  - lock: "Your admin controls this account…", "We only link accounts after…"
  - terminal: after cancel.

## FootNote and FootText

See `layout.md#actions`.

## Warning callout

For unverified apps (3c).

- `box-sizing: border-box; display: flex; gap: 12px; padding: 14px 16px; border-radius: 14px; background: var(--id-accent-bg); border: 1px solid var(--id-accent-line)`.
- Icon: triangle-alert, 16px, accent, padding-top 2px.
- Title: 14px/500, fg. Body: 13px/19px, fg-2. Title and body are a column with gap 4px.

## Link

- 13px, fg-2, `text-decoration: underline; text-decoration-color: var(--id-line-2); text-underline-offset: 3px`. Hover: fg.

## Pill

- The pills on the auth screens are the two above (provider "Last used", account row "Last used here"). Both use `padding: 1px 6px`; check the line-height difference.
- Generic pill, for future use: `font-size: 11px; line-height: 16px; padding: 1px 6px; border-radius: 99px; background: var(--id-raised); color: var(--id-fg-2); font-weight: 500; white-space: nowrap`.
- Accent variant: `background: var(--id-accent-bg); color: var(--id-accent)`.

## Disclosure (developer details)

- `<details>`. The `summary` is `display: flex; align-items: center; gap: 8px; min-height: 28px; font-size: 13px; color: var(--id-fg-2)`, with a chevron-right (14px, fg-3) that rotates 90° when open.
- Panel: `padding: 10px 0 0 22px; gap: 6px`.
- Used open by default on 7a, with KeyValues and a labelled CopyButton. On 5d it holds a `<pre>` code block (12px/19px mono, fg-2, padding 12px 14px, radius 10px, sunk, line border).

## Code block

- `display: flex; align-items: center; gap: 10px; padding: 8px 8px 8px 14px; border-radius: 10px; background: var(--id-sunk); border: 1px solid var(--id-line); box-shadow: var(--id-sh-input)`.
- Code: mono 13px, fg, `white-space: pre`, with ellipsis on overflow.
- Then an icon-only CopyButton.

## Steps (5d)

- Each step: `display: flex; gap: 14px`.
  - Number box: 22px square, radius 6px, `border: 1px solid var(--id-line-2)`, 12px/600 fg-2, `margin-top: 1px`.
  - Column (gap 10px): label (14px/500), then the step content.

## Status list (5d)

- Rows: `display: flex; align-items: center; gap: 12px; padding: 10px 0`, with hairlines between rows only.
- Dot, 8px:
  - Current step: filled fg, pulsing with `idwave 2s linear infinite`.
  - Upcoming step: a 1.5px fg-3 ring.
- Title: 14px; fg for the current step, fg-3 for upcoming. Sub-line: 12px, fg-3.
- Steps: "Waiting for a push", "Pending on a branch", "Claimed".
- Wrap the list in `aria-live="polite"`.

## Stats (5c)

- Inside a Well with gap 14px.
- Grid: `repeat(3, minmax(0, 1fr)); gap: 12px`.
  - Number: 22px/600, `letter-spacing: -0.02em; font-variant-numeric: tabular-nums`.
  - Label: 13px, fg-3.
- Then a footer row: `border-top: 1px solid var(--id-line); padding-top: 12px`, with a clock icon (14px) and "Sandbox ends in 18 hours" (13px, fg-2), gap 8px.

## Icon tile (36px, inside wells)

- `width/height: 36px; border-radius: 9px; background: var(--id-panel); border: 1px solid var(--id-line-2); box-shadow: var(--id-sh-ctrl)`.
- Icon at 16px, fg. Used for the SSO organisation (building icon).

## Name + sub (two-line text)

- Column: name 14px/500 fg; sub-line 13px fg-3.

## Countdown (5b header right)

- Clock icon (14px) plus "4:32 left" in 13px fg-2, gap 6px. The format is **m:ss** (no leading zero on minutes). The mock does not use tabular figures, so neither does production.
- It counts down every second. At ≤ 60s the text turns accent (5b only, via a prop). At 0 the page swaps to the expired state (see `screens.md#5b`).
- The 1b resend timer ("Resend in 0:42") uses the same script in m:ss, always in fg-3, and becomes a "Resend code" link at 0.
- In the gallery's frozen mode the countdown doesn't tick.
