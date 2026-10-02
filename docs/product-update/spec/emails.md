# Emails

Mocks: `../mocks/screens/8a-email-sign-in-code.html`, `8b-email-invitation.html` and `8c-email-sign-in-alert.html`. Copy and subjects: `screens.md#8--emails`.

Each mock shows an **inbox preview frame** (a light page, plus "From" and "Subject" lines), the email card, and a footer line. The **template** is the white card plus the footer line. The preview frame exists only in the design gallery, so the template can be pixel-compared against the mock.

## Palette

Emails are light. Mail clients don't support `oklch()`, so templates use these hex values. They are the sRGB equivalents of the mock colours, and Chromium renders them within the diff's tolerance.

| Role | Mock | Hex |
|---|---|---|
| Page (preview frame only) | `oklch(0.965 0.003 286)` | `#f3f3f5` |
| Card | `#ffffff` | `#ffffff` |
| Text | `oklch(0.21 0.01 286)` | `#18181d` |
| Secondary text | `oklch(0.42 0.01 286)` | `#4c4c52` |
| Tertiary text | `oklch(0.52 0.01 286)` | `#68686f` |
| Lines | `oklch(0.9 0.004 286)` | `#dedee0` |

## Type

- `font-family: 'Geist', -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif`. The code uses `'Geist Mono', ui-monospace, 'SF Mono', Menlo, Consolas, monospace`.
- Include a `<style>` block with `@font-face` for Geist from `https://id.org.ai/fonts/geist/…` (absolute URLs). Clients that support web fonts render Geist; the rest fall back. The gallery preview always has Geist, so the diff is exact.

| Element | Size and style |
|---|---|
| Heading | 22px/28px, 600, letter-spacing -0.02em |
| Body | 15px/24px, secondary text |
| Code (8a) | mono 36px/44px, 500, letter-spacing 0.18em, padding 16px 0, rules above and below in the line colour; shown as `482 913` |
| Button | 44px tall, padding 0 20px, radius 10px, background = text colour, white 14px/500 text |
| Key/value box (8c) | 1px line border, radius 10px, padding 14px 16px, rows 14px with gap 6px; keys in tertiary text |
| Footer line | 12px/18px, tertiary text |

## Layout

- The card: white, `1px solid #dedee0`, radius 12px, padding 40px 44px, with 22px between blocks. At the top, the org.ai mark (18px) plus "id.org.ai" (14px/600, gap 8px).
- Build with tables (role="presentation") and inline styles for client support. Reproduce the mock's box model exactly: the same paddings, widths and line-heights. Spacing that the mock does with `gap` becomes padding on table rows.
- Width: the card fills its container up to 584px (the mock's 640px frame minus 28px padding on each side).
- Every email ships with a plain-text part.

## Gallery preview

- `/__design/8a-email-sign-in-code` (and 8b, 8c) renders the preview frame from the mock (page colour, padding 28px, the From/Subject lines, gap 16px), then the template's HTML, then the footer line.
- The frame is gallery-only markup.
- These preview routes are dev-only and send **no** `style-src` restriction, because the templates are inline-styled. Every other gallery page uses the production CSP.
- Diff target: 0 px. A difference from hex conversion that pixelmatch's threshold doesn't absorb counts as an engine-rounding exception (≤4 px, documented).
