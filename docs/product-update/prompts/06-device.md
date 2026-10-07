# Phase 6 · Device flow v2 and CLI output

> **For agentic workers:** run this phase from `../autopilot.md`. Write tests first.

**Goal:**
- `/device` becomes 4c (enter a code) and 4b (confirm), with device metadata, a workspace choice, permissions and a CSRF-protected decision endpoint.
- The live state machine runs exactly as in the mock.
- 4d is the no-JS result.
- The `id.org.ai` CLI prints the 4a output.

**Depends on:** Phases 3, 4 and 5 (scope registry, `org_id`).

**Read first:**
- `../spec/backend.md#b3`
- `../spec/screens.md#4--cli-and-devices`
- `../spec/motion.md#device-confirm-4b-the-reference-state-machine`
- `../mocks/screens/4b-device-confirm.html`: its inline logic class is the reference for the timers.

## Tasks

### Task 1 · Codes and metadata
- [ ] Display codes as `XXXX-XXXX`. Normalise input by stripping hyphens and spaces and uppercasing. `verification_uri_complete` becomes `…/device?code=XXXX-XXXX`; keep accepting `user_code`.
- [ ] Capture metadata at `POST /oauth/device`:
  - `os` from the User-Agent, or the new optional `device_name` param;
  - `city`, `region` and `country` from `request.cf`;
  - `ip`;
  - `requestedAt`.
  - Store it on the device record.
- [ ] Format the meta line as "{os} · {city}, {region} · requested {n} min ago". Unknown parts are omitted, along with their separators.

### Task 2 · Pages and decision endpoint
- [ ] `GET /device` with no code renders 4c. With a code, it renders 4b (sign in first when there is no session; the code survives the round trip).
- [ ] An expired or used code renders the 7b content in place.
- [ ] `POST /device/decision`:
  - takes `{code, org_id, decision}` plus CSRF (header for fetch, field for a form);
  - returns JSON for fetch, or a 303 to 4d / cancelled for a form;
  - is idempotent;
  - stores `org_id` on the approval, which flows into the tokens.
- [ ] Remove the CSRF-less POST path from `handleDeviceVerification`.
- [ ] Add `slow_down` polling and `POST /device/:id/revoke`.

### Task 3 · Live behaviour
- [ ] Wire `device-confirm.ts` (phase 2) to the real endpoint. Exact timings:
  - Confirm: busy at once.
  - Server OK: `done`, then the signed content swaps in 2150ms later.
  - Cancel: `broken`, then the cancelled content 1820ms later.
  - Errors: `broken`, then the 7b content.
- [ ] The card stays pinned to the top (`pinTop`).

### Task 4 · CLI output (4a)
- [ ] `src/sdk/cli/` login: print exactly what `../spec/cli-output.md` specifies. That covers the layout, colours, `NO_COLOR` and non-TTY output, the `c`/`o` keys, the spinner, polling with `slow_down`, outcomes and exit codes.
- [ ] Send `device_name` (OS and hostname).
- [ ] Snapshot-test the output with a fake TTY and a non-TTY.
- [ ] `spec/cli-output.md` is also the handoff for the auto.dev and headless.ly CLIs, which live in other repos. Add a follow-up line for each in PROGRESS; don't touch other repos.

## Acceptance
- Tests:
  - code formats;
  - metadata captured and rendered;
  - the decision without CSRF is refused;
  - approve → poll → tokens with `org_id`;
  - deny → `access_denied`;
  - `slow_down`;
  - revoke;
  - client-side timings with fake timers.
- A route-level test in the workers pool covers device authorization, confirm and poll.
- A browser-level check against `wrangler dev` (WorkOS stub via `WORKOS_API_BASE`, fixture session) drives `POST /oauth/device`, opens the page, clicks Confirm, and sees signed. A second run clicks Cancel and sees cancelled. Never use `pnpm test:e2e`.
- The visual diff for 4b (6 states), 4c and 4d is still 0 px.

## Commit
- `feat(device): readable codes and device metadata`
- `feat(device): confirm page, decision endpoint with CSRF`
- `feat(device): live confirm state machine`
- `feat(cli): login output`

Push.
