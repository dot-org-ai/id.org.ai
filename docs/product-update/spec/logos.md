# Logos

## What the mocks show
- **id.org.ai**: the org.ai mark, already in the repo at `worker/public/orgLogo.svg` and `site/public/orgLogo.svg`. Use it as is.
- **Apps** (Codex, Claude Code, headless.ly, startups.studio, api.sb, auto.dev, agent-tools.dev, Drivly):
  - The mocks show a **letter monogram or an icon** in the 56px app tile (for example "Cx", "h", or a terminal or bot icon).
  - These are placeholders. They are **not** the final marks.
- **Sign-in providers** (GitHub, Google, Microsoft, Apple): the mocks show a **dashed 18px slot** where each official mark goes.

## How it works in production
1. **Third-party apps bring their own logo.** id.org.ai already reads `logo_uri` from the client's metadata:
   - CIMD document: `src/sdk/oauth/cimd.ts`, https only.
   - DCR registration: `logo_uri` in `POST /oauth/register`.
   
   The consent, device and admin screens render that image inside the app tile. Nobody places Codex's or Claude Code's logo by hand; the client supplies it.
2. **Fallback**: when a client has no `logo_uri`, or the image fails to load, show the monogram, as the mocks do:
   - one or two letters from the display name;
   - or an icon for first-party CLIs (terminal) and agents (bot).
3. **Unverified clients** (3c) still show their own `logo_uri` (it's their claim). The name shown is the host, and the warning callout makes the trust level clear.
4. **First-party .do apps** (headless.ly, auto.dev, startups.studio, api.sb, .do) get a `brand.mark` in `src/sdk/oauth/clients.ts`, used for branded sign-in (1g) and their tiles.
   - These marks are the company's own assets. Add the files to `worker/ui/static/brand/`.
   - Until they exist, use the monogram.
5. **Provider marks**: use each provider's official sign-in mark from their brand guidelines, at 18px, in the dashed slot's position:
   - GitHub mark
   - Google "G"
   - Microsoft four squares
   - Apple
   
   `worker/views/provider-picker.ts` already carries inline marks for all four (GitHub, Google, Microsoft, Apple). Move them into the provider-button component, render them at 18px, and check each against the provider's current brand guidelines.

## Rules
- Never redraw or approximate a third-party logo in SVG or CSS. Use the official file, or the monogram.
- Render logos as `<img>` with `width`/`height` set, `alt=""` (the app name is next to the tile), `referrerpolicy="no-referrer"` and `object-fit: contain`. Don't add a background behind transparent logos: the tile is the background.
- An app's logo never replaces id.org.ai's own mark in the header, except on branded first-party sign-in (1g).
- The visual-diff fixtures use the monograms, so the diffs stay stable. Test real logos separately with an image-load test.
