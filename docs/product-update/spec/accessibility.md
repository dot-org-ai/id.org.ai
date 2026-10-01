# Accessibility

The target is WCAG 2.2 AA on every auth screen. These checks run in the QA phase (`../prompts/13-qa-and-launch.md`).

## Structure
- One `h1` per page: the card title. Landmarks: `header`, `main`, `footer`.
- The card body is a `form` when it submits. Group radio cards in a `fieldset` with a visually hidden `legend`, matching the visible group label.
- Each permission row is a native `<details>`/`<summary>`, so keyboard and screen readers work without script.
- The connector is `aria-hidden="true"`. State changes are announced through text in a `role="status"` region: "Confirming…", "Signed in", "Cancelled".

## Keyboard
- Tab order follows the visual order on desktop.
  - On phones the primary button is visually first but second in the DOM. That's acceptable because the buttons are adjacent and labelled.
- Every control has a visible `:focus-visible` outline (2px `--id-select`, offset 2px).
- Code inputs:
  - Arrow keys move between boxes.
  - Backspace on an empty box moves back.
  - Paste fills every box.
  - The whole group is labelled ("Enter the 6-digit code").
- Radio cards: arrow keys move the selection (native radios underneath).
- The account chooser rows are links, reachable with Tab and activated with Enter.

## Contrast
- fg-2 and fg-3 on the card and page backgrounds pass AA for their sizes. Keep text no lighter than fg-3, and don't put fg-3 on `--id-raised` for body text.
- Accent text (act permission notes, errors) on the card background passes AA at 13px. Re-check it if the accent changes.
- Disabled buttons (opacity .45) are exempt, but must have `disabled` or `aria-disabled`.

## Motion
- `prefers-reduced-motion: reduce` turns off every animation; states still change on time (`motion.md`).
- No content flashes more than 3 times a second. The pulse is 0.5Hz.

## Forms and errors
- Each input has a visible label. Placeholders are examples, not labels.
- Errors are linked with `aria-describedby`, the input gets `aria-invalid="true"`, and focus moves to the first invalid field on submit.
- Timeouts:
  - The 5b countdown and code expiry are announced once at 60 seconds and at expiry, through the status region.
  - No session timeout happens without warning.

## Language and zoom
- `<html lang="en">`.
- The layout works at 200% zoom and at a 320px width, with no horizontal scroll.
- Text spacing overrides (WCAG 1.4.12) must not clip text in buttons. Buttons use `min-height`, not a fixed `height`, in production CSS.

## Checks
- Run axe-core on every gallery screen and state (no violations).
- Do a manual keyboard pass on 1a, 1b, 3a, 4b, 5a and 6b.
- Do a VoiceOver smoke pass on 3a and 4b.
