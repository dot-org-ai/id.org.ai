# Layout and design rules

These are the rules behind every auth screen. Where this file gives a number, it matches the reference mocks in `../mocks/screens/`. If this file and a mock ever disagree, the mock wins and this file gets fixed.

## Page shell

Every auth screen uses the same shell, top to bottom:

| Part | Spec |
|---|---|
| `body` | `margin: 0; background: var(--id-bg); color: var(--id-fg); font-family: var(--id-font); -webkit-font-smoothing: antialiased; -moz-osx-font-smoothing: grayscale; text-rendering: optimizeLegibility` |
| Page | `min-height: 100vh; display: flex; flex-direction: column` |
| Header | `display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 18px 24px; min-height: 72px; box-sizing: border-box`. Left: the brand. Right: usually empty (the phone action-approval screen puts the countdown here). |
| Brand | Link with `display: flex; align-items: center; gap: 8px; font-size: 14px; font-weight: 500; letter-spacing: -0.01em; color: var(--id-fg); text-decoration: none`: the org.ai mark at 18px, then `id.org.ai`. |
| Main | `flex-grow: 1; display: flex; justify-content: center; align-items: center; padding: 24px 20px 40px`. One exception: the live device-confirm screen (4b) pins content to the top with `align-items: flex-start; padding: 72px 20px 40px`, so the card's top edge stays still while its body changes height between states. |
| Column | `width: 100%; max-width: 560px; display: flex; flex-direction: column` (gap 0: the card is the only child). |
| Footer | `display: flex; justify-content: center; gap: 20px; padding: 24px 20px; font-size: 12px`. Links: Privacy, Terms, Status, in `var(--id-fg-3)`, no underline. Branded sign-in (1g) swaps this for `Secured by [org.ai mark 14px] id.org.ai` (12px; "Secured by" in fg-3, the mark and name in fg-2, gap 8px; mark and name gap 6px). |
| Branded brand (1g) | Replaces the id.org.ai brand: `display: flex; align-items: center; gap: 10px; font-size: 14px; font-weight: 600; color: var(--id-fg)`. A 28px app tile (radius 7px, `var(--id-panel)` background, `1px solid var(--id-line-2)` border, `var(--id-sh-ctrl)` shadow, monogram 13px/600) or the app's mark at 28px, then the app name. |

There is **no account chip in the header**. The signed-in account is shown inside the card (the "who" row with Switch), where the decision is being made.

## Card anatomy

```
┌─────────────────────────── card (max 560px, radius 20) ───────────────────────────┐
│  body  padding 32px 28px 26px · flex column · gap 22px                             │
│    head   connector (two 56px app tiles + five dots), then title + description     │
│    blocks …                                                                         │
├──────────────────── 1px var(--id-line) ────────────────────────────────────────────┤
│  foot  background var(--id-card-foot) · padding 16px 20px · flex column · gap 14px │
│    actions (one full-width button, or two buttons splitting the width)             │
│    optional line underneath, centred (safety note, alternate links)                │
└────────────────────────────────────────────────────────────────────────────────────┘
```

- Card: `width: 100%; max-width: 560px; box-sizing: border-box; border-radius: 20px; background: var(--id-card); border: 1px solid var(--id-line-2); box-shadow: var(--id-sh-card); overflow: hidden; align-self: center`.
- Head: `display: flex; flex-direction: column; align-items: center; gap: 20px; text-align: center`. The text block below the connector is a column with `gap: 8px`:
  - `h1`: `margin: 0; font-size: 22px; line-height: 28px; font-weight: 600; letter-spacing: -0.02em; text-wrap: balance`.
  - Description `p`: `margin: 0; font-size: 15px; line-height: 23px; color: var(--id-fg-2); text-wrap: balance`. Names inside it (app, email, workspace, person) are highlighted with `color: var(--id-fg); font-weight: 500`.
- Foot: `display: flex; flex-direction: column; gap: 14px; padding: 16px 20px; background: var(--id-card-foot); border-top: 1px solid var(--id-line)`.
- The 560px column is deliberate: headlines and descriptions stay on one or two lines. Do not narrow it.

## Actions

- **Two actions split the width evenly**: `display: grid; grid-template-columns: 1fr 1fr; gap: 10px`. The secondary (outlined) action is on the left and the primary (white) is on the right.
- **One action fills the width.**
- The **safety line** sits centred under the buttons, when a screen has one: icon 14px plus text, 12px/17px, `var(--id-fg-3)`, gap 8px, `justify-content: center; text-align: center`. Examples:
  - 4b: shield icon, "Never confirm a code someone sent you."
  - 1b: mail icon, "Or open the link in the email on this device."
  - 7c: send icon, "Admins get an email and can approve in one click."
  - 1d: no icon, "Signed in with GitHub as **bryant22**. Not you?"
- **Text-only feet** (no buttons) use 13px/20px `var(--id-fg-3)`, centred, `text-wrap: balance`. Examples: "New here? Any option above creates your account.", "Not redirected? Continue to headless.ly", "Wasn't you? Sign this device out".
- **Unverified apps flip the emphasis**: Allow becomes the outlined button on the left and Cancel the primary on the right (3c).
- Nothing else goes in the action band: no help links, no "learn more", and no second copy of links that already exist in the card.

## Phones (viewport ≤ 480px)

- The card goes edge to edge: `align-self: stretch; width: auto; max-width: none; margin: 0 -20px; border-radius: 0; border-left: 0; border-right: 0; box-shadow: none`.
- Card body padding becomes `28px 20px 24px`.
- Two actions **stack full width, primary on top**: `grid-template-columns: 1fr`, and the primary gets `order: -1`. Keep the DOM order secondary, then primary, and reorder only visually.
- Action buttons are **48px** tall on phones (`[data-actions] > * { height: 48px; min-height: 48px }`). Only the height changes: radius and font size stay as on desktop.
- Reference: `5b-action-approval` (390px). Every other screen has a `.phone.png` at 390×844 in `../mocks/png/`.

## Dividers

- A **dotted rule** separates *open* sections: a row of 1px dots, 2px tall, 7px apart, at 22% white. Use `background-image: radial-gradient(circle at 1px 1px, var(--id-dot) 1px, transparent 1.3px); background-size: 7px 2px; background-repeat: repeat-x; height: 2px`.
  - A dotted rule never sits next to a border or a hairline: not above the card foot, not under a boxed well, not against a list's hairline.
  - The labelled form ("or" on sign-in) puts the label (12px, fg-3) between two dotted lines with gap 12px.
- **Lists get hairlines between rows only**: `1px solid var(--id-line)`, with none above the first row and none below the last. This applies to permission lists and the claim status list.
- **Boxed elements get space, not a rule.** Wells, radio cards, account rows, warning callouts and inputs are separated by the body gap (22px), or by their own stack gap (8–12px) inside a group.
- Typical use: head, then a dotted rule, then the who row, when the content after the head is open (consent, workspace chooser, sign out, step-up, admin approve, link account, errors with developer details). When the next thing is boxed (the code well on 4b, wells on 2e/4d/5c), skip the rule.

## Copy rules

- Sentence case everywhere: buttons, labels, titles.
- Name the app, the account and the workspace in the description, highlighted.
- Never show the same link twice on a screen. Privacy and Terms belong to the page footer; the app's own privacy and terms live inside its source row.
- Errors lead with what happened in plain words. Developer detail sits in a disclosure underneath, with a copy action.
- Times: "requested 1 min ago", "Confirmed 3 hours ago", "in 6 days", "4:32 left" (tabular figures).

## Interaction rules

- **Motion starts on the person's click**, never on page load: Allow, Confirm, Continue, Approve, Join and so on. Pages reached afterwards show the result still. See `motion.md`.
- **Copy is a bare icon**: no border and no background at rest; on hover a faint fill and brighter icon; after copying, a green check for 1.5s. See `components.md#copy-button`.
- **Selected and focused** controls get a `var(--id-select)` border plus the `var(--id-ring)` halo.
- **Hover**: primary buttons `filter: brightness(0.93)`; secondary buttons, provider buttons and account rows `filter: brightness(1.14)`; ghost buttons get the `var(--id-hover-ghost)` fill. Transitions: `filter .15s, background-color .15s, border-color .15s, transform .1s`. Pressed: `transform: scale(0.985)`.
- **Focus-visible**: `outline: 2px solid var(--id-select); outline-offset: 2px` on every interactive element.
- **Reduced motion**: with `prefers-reduced-motion: reduce`, every animation is off and each state renders in its resting form.
