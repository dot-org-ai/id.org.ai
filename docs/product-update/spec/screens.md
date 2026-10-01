# Screens

There is one entry per screen. Each entry gives:

- **Mock**: the reference files in `../mocks/screens/` (`.html` is the source of truth; `../mocks/png/` holds the 1x screenshots).
- **Route**: where it renders.
- **Shown when**: the exact condition.
- **Data**: the props the presentational component takes. The fixture values are the strings in the mock.
- **Actions**: what each control does.
- **Server**: the backend capability it depends on (see `backend.md`).
- **States**: variants beyond the default.

Shared conventions:

- Every screen uses the page shell and card from `layout.md`.
- "Switch" in a who row links to `/account/choose` with the current request preserved.
- Every form posts with a CSRF token (`security.md`).
- Without JS every flow still works: forms post, and the server renders the next page.

The flow that ties these together is in `flows.md`.

---

## 0 · Flow map (reference only)
- Mock: `0-flow-map.html`. This is not a page. It shows the pipeline every sign-in runs (`flows.md`).

---

## 1 · Sign in

Shown only when there is no id.org.ai session, or the app asked for a fresh one (`prompt=login`). It is email first: a known SSO domain routes to SSO, and everything else gets a 6-digit code. The same screens sign people up; first run asks only for a name and a workspace.

<a id="1a"></a>

### 1a · Sign in
- Mock: `1a-sign-in.html`.
- Route: `GET /login?continue=&client_id=&login_hint=&prompt=`. This replaces `worker/views/provider-picker.ts`.
- Shown when: there is no session, or `prompt=login`, or the person chose "Use another account".
- Data:
  - `app` (the name and tile of the app being signed in to, from `client_id` or the `continue` host; for example headless.ly).
  - `emailPrefill` (from a valid `login_hint`).
  - `lastUsedProvider` (cookie `id_last_provider`, which shows the "Last used" pill).
  - `providers` (GitHub, Google, Microsoft, Apple; each can be turned off).
  - `passkeysEnabled`.
- Actions:
  - **Continue with email**: `POST /login/email`. It goes to 1c for an SSO domain; otherwise it sends a code and goes to 1b.
  - **Provider buttons**: `GET /login?provider=…` (today's WorkOS path, with `login_hint` forwarded).
    - GitHub and Google go direct, as today.
    - Microsoft and Apple go direct (`MicrosoftOAuth`, `AppleOAuth`) once they are enabled in the WorkOS dashboard (an owner step). Until then they keep today's `provider=authkit` route.
  - **Sign in with a passkey**:
    - With `FEATURE_PASSKEYS=1`: WebAuthn get (B7).
    - With it off: the same button hands off to hosted AuthKit (`/login?provider=authkit&…`), which supports passkeys, so existing AuthKit passkey users keep working (D2).
- Server: B4, B7.
- Notes:
  - The connector shows id.org.ai → app.
  - The "or" divider is the labelled dotted rule.
  - Foot: "New here? Any option above creates your account."

<a id="1b"></a>

### 1b · Email code
- Mock: `1b-email-code.html`.
- Route: `GET/POST /login/code/:flow`. The existing RP-initiated `GET /magic-link/:flow` renders this same screen.
- Shown when: after `POST /login/email` for a non-SSO domain, or after the magic-link API starts a flow.
- Data:
  - `email` (shown in full; this is the person's own address).
  - `expiresInMinutes` (10).
  - `resendAvailableIn` (seconds). It counts down "Resend in 0:42" in m:ss, always fg-3, then becomes a "Resend code" link. Frozen in the gallery.
  - `app`.
  - `error?` (wrong code, too many tries).
- Actions:
  - **Verify** posts the code.
  - **Use a different email** returns to 1a with the email cleared.
  - **Resend** posts to `/login/code/:flow/resend` (send budget in B4).
  - The link in the email opens `/login/code/:flow?code=…`, which prefills the boxes (it never auto-submits).
- States:
  - Wrong code: the error is shown under the boxes in accent text (no shake animation); the boxes clear and focus returns to the first one; the guess budget applies.
  - Expired: 7b.
- Server: B4 (reuses the magic-flow records, cookie binding and budgets).

<a id="1c"></a>

### 1c · SSO domain
- Mock: `1c-sso.html`.
- Route: `GET /login/sso?email=&continue=`.
- Shown when: the email's domain belongs to an organisation with an active SSO connection.
- Data:
  - `email`.
  - `org { name, domain }`.
  - `idpName` (Okta, Entra ID, Google Workspace…; from the connection type).
  - `app`.
- Actions:
  - **Continue with {idp}**: WorkOS authorize with `organization_id` (or `connection_id`) and `login_hint`.
  - **Use a different email**: back to 1a.
- Notes: the lock note reads "Your admin controls this account. Personal sign-in methods are turned off for it." Show it only when the org enforces SSO.
- Server: B4.

<a id="1d"></a>

### 1d · First run
- Mock: `1d-first-run.html`.
- Route: `GET/POST /welcome?continue=`.
- Shown when: the first successful sign-in creates a new identity.
- Data:
  - `name` (prefilled from the provider; the right hint shows the source, for example "From GitHub").
  - `workspaceName` (prefilled with the personal workspace name).
  - `provider` and `providerUsername` (for the line "Signed in with GitHub as bryant22. Not you?").
- Actions:
  - **Create account** saves the name (the WorkOS user's first and last name) and renames the personal workspace, then continues.
  - **Not you?** signs this session out and returns to 1a.
- Notes: the head is the single id.org.ai tile (no connector).
- Server: B6.

<a id="1e"></a>

### 1e · Email already has an account
- Mock: `1e-link-account.html`.
- Route: `GET /login/link?flow=`.
- Shown when: a sign-in resolves to an email that already belongs to a different id.org.ai identity, for example one created by claim-by-commit or under another WorkOS user. See D6.
- Data:
  - `email`.
  - `existingProvider` (for example GitHub).
  - `newProvider` (for example Google).
  - `identity { name, email }`.
- Actions:
  - **Continue with {existingProvider}** proves the old method; then link and sign in.
  - **Use a different email**.
- Notes: the lock note reads "We only link accounts after you prove you own both. Nothing is merged until then."
- Server: B7.

<a id="1f"></a>

### 1f · Provider sign-in failed
- Mock: `1f-provider-fallback.html`.
- Route: rendered by `GET /api/callback` when the upstream provider returns an error. Today that returns a JSON 400 (`worker/routes/auth.ts`).
- Shown when: the provider refuses or fails (tenant policy, consent denied by an admin, provider outage).
- Data:
  - `provider` (Microsoft).
  - `reason` (one plain sentence, mapped from the upstream error code).
  - `emailPrefill?`.
- Actions:
  - **Email me a code**: `POST /login/email`.
  - **Try Microsoft again**: restarts the provider flow.
- States: the connector shows `fail`.
- Server: B4.

<a id="1g"></a>

### 1g · Branded sign-in
- Mock: `1g-branded-sign-in.html`.
- Route: `GET /login` when the client has a configured brand.
- Shown when: the requesting client is first-party, for example headless.ly. Third-party clients never get branded sign-in.
- Data: `brand { name, mark }`, plus everything in 1a.
- Notes:
  - The header shows the app's brand instead of id.org.ai.
  - The footer reads "Secured by id.org.ai".
  - An app can set its name and mark only. Colours, layout and the Secured line stay fixed, so people can trust the page.
- Server: B4.

---

## 2 · Account and workspace

<a id="2a"></a>

### 2a · Choose account
- Mock: `2a-account-chooser.html`.
- Route: `GET/POST /account/choose?continue=`.
- Shown when: there are 2+ accounts signed in in this browser and no remembered account for this client, or the app sends `prompt=select_account`. This is how one id.org.ai login uses a different account per app.
- Data:
  - `app`.
  - `accounts[] { sessionId, name, email, avatar?, lastUsedHere: boolean }`.
- Actions:
  - **Account row**: `POST` `{session}`. It makes that session active for this request and remembers it for the client.
  - **Use another account**: `/login?prompt=login&continue=` (adds a session).
  - **Sign out of all accounts**: `POST /signout` `{scope: 'browser'}`.
- Notes: the description reads "to continue to startups.studio. It only sees the account you pick."
- Server: B5.

<a id="2b"></a>

### 2b · Choose workspace
- Mock: `2b-workspace-chooser.html`.
- Route: `GET/POST /workspace/choose?continue=`.
- Shown when: the person belongs to 2+ workspaces, the request has no `organization_id` hint, and nothing is remembered for this client.
- Also shown at sign-in when WorkOS returns `organization_selection_required` (`worker/routes/auth.ts` `/api/callback` and `worker/routes/magic-link.ts`), replacing `worker/views/org-picker.ts`. In that mode it posts to the existing `POST /api/org-select` contract (`pendingAuthenticationToken`, `state`, `organization_id`), so the WorkOS exchange is unchanged.
- Data:
  - `app`.
  - `account`.
  - `workspaces[] { id, name, role }` (role shown as Owner, Admin, Member, or "Just you" for personal).
  - `selectedId`.
  - `remember` (default on).
- Actions:
  - **Continue** stores the choice (if remembered) and continues. The choice goes into the token as `org_id`.
  - **New workspace**: `/workspace/new` (a derived screen: 1d with only the Workspace field, title "Create a workspace", primary "Create workspace").
- Server: B6.

<a id="2c"></a>

### 2c · Handing off
- Mock: `2c-handoff.html`.
- Route: returned as the final response when the browser leaves id.org.ai for the app after an interactive step.
- Shown when: the redirect back to the app follows a choice the person made on id.org.ai. It is never shown for silent sign-ins.
- Data: `app`, `account.name`, `workspace.name`, `target` (the redirect URL).
- Behaviour:
  - `location.replace(target)` runs in the next animation frame.
  - `<meta http-equiv="refresh" content="1;url=…">` is the no-JS fallback.
  - The foot link "Continue to {app}" points to the same URL.
  - The connector shows `connecting`.
  - In the gallery (frozen mode) there is no redirect and no meta refresh.
- Server: B5 (it only wraps the redirect).

<a id="2d"></a>

### 2d · Connect motion (reference only)
- Mock: `2d-connect-motion.html`. See `motion.md`.

<a id="2e"></a>

### 2e · Accept invitation
- Mock: `2e-invitation.html`.
- Route: `GET/POST /invite/:token`.
- Shown when: someone opens an invitation link (sent by email, 8b).
- Data:
  - `inviter { name }`.
  - `workspace { name }`.
  - `role`.
  - `invitedEmail`.
  - `expiresIn`.
  - `account` (the signed-in identity).
- Actions:
  - **Join workspace** accepts and continues to 2c, then on to the workspace's app (or the id.org.ai home).
  - **Decline** declines; it shows a short confirmation in place.
- States: if `account.email` ≠ `invitedEmail`, show the who row's Switch prominently and disable Join. The rule: invites belong to one email; a mismatch prompts Switch account.
- Server: B6.

---

## 3 · Authorize apps

Consent is shown for third-party apps on first use, for any new permission, and always for apps running on this computer (loopback). It always shows who is signed in and which workspace. Act permissions are a choice, not a third button. Unverified apps flip the buttons so Cancel is primary. First-party .do apps skip consent, except for `sb:*` scopes (the server already enforces this).

<a id="3a"></a>

### 3a · Authorize app (read + act)
- Mock: `3a-consent.html`, plus `--copied`.
- Route: `GET /oauth/authorize` (existing). This replaces `renderConsentPage` in `src/sdk/oauth/provider.ts`.
- Shown when: consent is required and the request includes an API resource scope (`sb:read` / `sb:do`).
- Data:
  - `client { displayName, host, logoUrl?, verified, runsOnThisComputer, redirectHost, cimdUrl?, privacyUrl?, termsUrl? }`.
  - `resource` (api.sb).
  - `account`.
  - `workspaces[]` and `selectedWorkspaceId`.
  - `access`: `'read' | 'act'` (the default comes from the requested scopes; `act` when `sb:do` is requested).
  - `permissions[]` from the scope registry.
- Actions:
  - **Allow** posts the existing hidden fields plus `org_id` and `access`. `access=read` maps to today's `approved=read` downgrade.
  - **Cancel** returns `access_denied`.
  - Granting `sb:do` with a sign-in older than 10 minutes goes to 6a first (B5).
- Notes:
  - Title: "{App} wants to use {resource} as you".
  - Description: "Choose what it can do. You can change this or revoke it anytime."
  - The source row shows the CIMD URL (or `client_id`) with copy. Its details hold Runs on, Returns to, Identified by, and the app's privacy and terms links.
- Server: B2.

<a id="3b"></a>

### 3b · Sign in with id.org.ai
- Mock: `3b-consent-basic.html`, plus `--copied`.
- Route: `GET /oauth/authorize`.
- Shown when: consent is required and only identity scopes are requested (`openid profile email`).
- Data: `client`, `account`, `scopesSummary` ("name, email address and profile photo").
- Actions:
  - **Continue as {first name}** allows.
  - **Cancel** denies.
- Server: B2.

<a id="3c"></a>

### 3c · Unverified app
- Mock: `3c-consent-unverified.html`, plus `--copied`.
- Route: `GET /oauth/authorize`.
- Shown when: the client is not verified (D3). That is every DCR client, and any CIMD host not on the verified list.
- Notes:
  - The displayed name is the host, never the self-asserted `client_name`.
  - The warning callout reads "id.org.ai can't vouch for this app".
  - The buttons are flipped: Allow is secondary and Cancel is primary.
  - Source details include "Verified: No".
- Server: B2.

<a id="3d"></a>

### 3d · Admin approves an app
- Mock: `3d-admin-approve.html`, plus `--copied`.
- Route: `GET/POST /admin/requests/:id`.
- Shown when: a workspace admin opens an access request (sent by 7c).
- Data:
  - `requester { name }`.
  - `client`.
  - `workspace`.
  - `note?`.
  - `permissions[]`.
  - `scope`: `'everyone' | 'requester'` (default `requester`).
  - `admin` (who row).
- Actions: **Approve** and **Decline**. Both notify the requester.
- Server: B11.

---

## 4 · CLI and devices

Codes are confirmed, not typed: the CLI opens the link with the code filled in, and typing is the fallback. The confirm page names the app, device and location to blunt code phishing. It is the same flow for the id.org.ai, auto.dev and headless.ly CLIs.

<a id="4a"></a>

### 4a · CLI login (terminal)
- Mock: `4a-cli-terminal.html` (reference for CLI output; not a web page).
- Applies to: `id.org.ai login` in `src/sdk/cli/` here. auto.dev and headless.ly CLIs get the same text spec (B3).
- Output, in order:
  1. The app line.
  2. `Code WDJB-MJHT`.
  3. `Confirm https://id.org.ai/device?code=WDJB-MJHT`.
  4. "Opened in your browser." with the keys `c` copy link and `o` open again.
  5. A spinner line "Waiting for you to confirm in the browser · expires in 29:52".
  6. On success: "✓ Signed in as {name} <{email}>", "Workspace {name}", "Stored in macOS Keychain · {app}", "Switch {cli} login --account".

<a id="4b"></a>

### 4b · Confirm device code (live)
- Mock: `4b-device-confirm.html` (live), plus `--connecting`, `--verdict`, `--signed`, `--cancelling` and `--cancelled`.
- Route: `GET /device?code=WDJB-MJHT` (also accept `user_code=`).
- Shown when: a valid pending code is in the URL, or after 4c.
- Data:
  - `code` (shown as `XXXX-XXXX`).
  - `client { displayName, icon }`.
  - `device { os, city, region, requestedAgo }`.
  - `account`.
  - `workspaces[]`.
  - `permissions[]`.
- Actions:
  - **Confirm** and **Cancel**. With JS, both go through `fetch`: `POST /device/decision` `{code, org_id, decision}` returns `{ok, state}`. The state machine is in `motion.md#device-confirm-4b-the-reference-state-machine`.
  - Without JS the form posts and the server renders 4d or the cancelled page.
- States:
  - `idle`, `connecting`, `verdict`, `signed` (= 4d content in place), `cancelling`, `cancelled`.
  - Error: the code expired or was already used. Show 7b content in place.
- Notes:
  - The page is pinned to the top.
  - The safety line reads "Never confirm a code someone sent you."
- Server: B3.

<a id="4c"></a>

### 4c · Enter device code
- Mock: `4c-device-entry.html`.
- Route: `GET /device` (no code).
- Data: `error?`.
- Actions: **Continue** goes to 4b with the code.
- Notes: "Codes look like WDJB-MJHT and last 30 minutes." Accept pasted codes with or without the hyphen.
- Server: B3.

<a id="4d"></a>

### 4d · Device connected
- Mock: `4d-device-done.html`.
- Route: `GET /device/done?code=` (the no-JS result of 4b). It re-reads the code: approved by this identity shows 4d; denied shows the cancelled card (`GET /device/cancelled?code=`); anything else shows 7b.
- Data: `client`, `account.email`, `workspace.name`, `device`.
- Notes:
  - The connector shows `ok`.
  - Foot: "Wasn't you? Sign this device out". It links to the device's revoke action (B3 adds `POST /device/:id/revoke`; the dashboard is out of scope).

---

## 5 · Agents

Approve an agent once, with a trust level, spend limit and expiry. Trusted agents ask per action by push; the approval page is built for a phone. Claim turns a sandbox an agent built into a real workspace in one click; claim-by-commit stays as the repo path.

<a id="5a"></a>

### 5a · Approve an agent
- Mock: `5a-agent-approve.html`, plus `--copied`.
- Route: `GET/POST /agents/approve/:agentId`. The agent or CLI prints this link.
- Shown when: a delegated agent registers and is `pending` (today's AAP flow; approval is DO-RPC only).
- Data:
  - `agent { name, host, os, askedAgo, keyType, fingerprint }`.
  - `workspace`.
  - `trustLevels[]`: Sandboxed, Trusted (default) and Privileged (accent).
  - `spendLimits[]`: $50 a month (default), $0 — no spending, $250 a month, No limit.
  - `expiries[]`: In 30 days (default), 7 days, 90 days, Never.
- Actions:
  - **Approve agent** stores the policy and activates the agent. Privileged requires a passkey confirmation every 7 days (B9).
  - **Reject**.
- Notes: the source row shows the key fingerprint (mono) with copy. Its details hold Host, Asked and Workspace.
- Server: B9.

<a id="5b"></a>

### 5b · Approve an action (phone)
- Mock: `5b-action-approval.html` (390px).
- Route: `GET/POST /approvals/:requestId`. The link arrives by push, email or the CLI.
- Shown when: a Trusted agent asks to send, delete or spend.
- Data:
  - `agent { name, role, app, workspace }`.
  - `action`: a typed preview. For email this is To, From, Subject, body excerpt and a "View full email" link.
  - `expiresAt` (drives the header countdown).
  - `alwaysAllowLabel` ("Always allow Susan to send renewal emails").
- Actions:
  - **Approve and send** approves.
  - **Deny** denies.
  - The checkbox creates a standing rule.
- States: expired, where the countdown hits 0. Show the 7b template with "This request expired". Unanswered requests expire as a no.
- Notes:
  - The connector direction is agent → id.org.ai.
  - On phones the buttons stack with the primary on top (the reference for the phone rule).
- Server: B9.

<a id="5c"></a>

### 5c · Claim agent work
- Mock: `5c-claim.html`.
- Route: `GET/POST /claim/:token`, as HTML when `Accept` includes `text/html`. JSON stays for API callers.
- Data:
  - `agent { name }`.
  - `app`.
  - `stats[]` (contacts, deals, workflows: counts from the tenant).
  - `sandboxEndsIn`.
  - `account`.
  - `workspaces[]` plus "New workspace…".
- Actions:
  - **Claim workspace** links the tenant to the chosen workspace and identity (B10).
  - **Claim from a repo** goes to 5d.
- Server: B10.

<a id="5d"></a>

### 5d · Claim from a repository
- Mock: `5d-claim-repo.html`, plus `--copied`.
- Route: `GET /claim/:token/repo`.
- Data:
  - `claimToken`.
  - `command` (`npx id.org.ai claim clm_…`).
  - `workflowYaml`.
  - `repo` (when known).
  - `status`: `waiting | pending | claimed`.
- Behaviour:
  - Poll `GET /api/claim/:token/status` every 5s.
  - The status list and the connector update in place (`connecting` → `done` → `ok`).
  - The foot reads "Prefer one click? Claim with your account instead".
- Server: B10 (claim-by-commit exists today).

---

## 6 · Security and sign out

Step-up applies when granting act permissions, approving a Privileged agent, or for anything with `max_age`, when the last sign-in is older than the limit. Sign out defaults to this app only.

<a id="6a"></a>

### 6a · Confirm it's you
- Mock: `6a-step-up.html`.
- Route: `GET/POST /step-up?resume=<id>&reason=<code>`.
  - `resume` is the id of a single-use server-side resume record (`takeOnce`), never a URL.
  - `reason` is an enum code: `act_permissions`, `privileged_agent`, `max_age` or `sign_out_everywhere`. The sentence shown comes from a catalogue, never from the query string.
- Data:
  - `app`.
  - `reason` ("Letting Codex act in your name needs a fresh check.").
  - `account`.
  - `lastConfirmedAgo`.
  - `factors` (passkey and/or email code).
- Actions:
  - **Use passkey**: WebAuthn get.
  - **Email me a code**: goes to 1b in step-up mode.
  - Both refresh `auth_time` and continue.
- Server: B5, B7.

<a id="6b"></a>

### 6b · Sign out
- Mock: `6b-sign-out.html`.
- Route: `GET/POST /signout?client_id=&return_url=`. This is new. The existing `GET /logout` keeps working for apps (B8).
- Data: `app`, `account`, `scope` (default `app`).
- Actions:
  - **Sign out** with scope `app`, `browser` or `everywhere` (`everywhere` is accent).
  - **Cancel** returns to `return_url`.
- Server: B8.

<a id="6c"></a>

### 6c · Add a passkey
- Mock: `6c-add-passkey.html`.
- Route: `GET/POST /passkeys/new?continue=`.
- Shown when: offered once, right after a code sign-in, if the browser supports WebAuthn and the person has no passkey.
- Actions:
  - **Add a passkey**: WebAuthn create, then continue.
  - **Not now**: remember the dismissal (per identity, 30 days), then continue.
- Server: B7.

<a id="6d"></a>

### 6d · Two-step code
- Mock: `6d-two-step.html`.
- Route: `GET/POST /login/two-step/:flow`.
- Shown when: a workspace requires two-step and WorkOS returns an MFA challenge.
- Actions:
  - **Verify** sends the TOTP.
  - **Use a passkey instead**.
  - **Use a recovery code** (D8).
- Server: B7.

---

## 7 · Errors

One template replaces every JSON error a browser can see. The human reason comes first, with developer details folded underneath and a copyable request ID. The connector shows the X verdict.

<a id="7a"></a>

### 7a · Misconfigured app
- Mock: `7a-error-app.html`, plus `--copied`.
- Shown when: the redirect URI is unregistered, the client is unknown, or the CIMD document is invalid. **Never redirect to an unvalidated URI.**
- Data:
  - `app?`.
  - `title`, `reason`.
  - `details { error, reason, client, redirect, request }`.
  - The primary action ("Go to id.org.ai").
- Server: B1.

<a id="7b"></a>

### 7b · Expired link
- Mock: `7b-error-expired.html`.
- Shown when: a magic-link or code flow, device code, invite or approval has expired or was already used.
- Data: a title and reason per kind, and the primary and secondary actions per kind.
- Server: B1.

<a id="7c"></a>

### 7c · Blocked by workspace policy
- Mock: `7c-error-blocked.html`.
- Shown when: the chosen workspace only allows approved apps and this client is not approved.
- Actions:
  - **Request access** creates the request (B11) and shows "Request sent" in place.
  - **Use another workspace** goes to 2b.
- Notes: the textarea note is optional (max 500 characters). The safety line reads "Admins get an email and can approve in one click."
- Server: B11.

The same template covers all of these, with copy written per case: generic server error (500), rate limited (429, "Too many tries. Try again in N minutes."), CSRF failure ("This page expired. Start again."), and not found.

---

## 8 · Emails

Emails are light, so they read well in any inbox. The code goes in the subject for autofill. The sign-in alert links straight to revoking that device. The mocks show an inbox preview frame (From, Subject) around the email; the template is the white card inside it.

<a id="8a"></a>

### 8a · Sign-in code email
- Mock: `8a-email-sign-in-code.html`.
- Subject: "Your id.org.ai code: 482913".
- Body:
  - The code (mono 36px, with a space after the third digit).
  - "Enter this code to sign in to {app}. It expires in 10 minutes and works once."
  - The "Didn't try to sign in?" line.
  - "Requested from {browser} on {os} · {city, region}".
- Server: B12.

<a id="8b"></a>

### 8b · Invitation email
- Mock: `8b-email-invitation.html`.
- Subject: "{Inviter} invited you to {workspace}".
- Button: Accept invitation, linking to `/invite/:token`.
- Server: B12.

<a id="8c"></a>

### 8c · New sign-in alert
- Mock: `8c-email-sign-in-alert.html`.
- Subject: "New sign-in: {app} on {os}".
- Contents: a key/value box (App, Device, Where, When) and the button "This wasn't me", which links to a one-click revoke for that session or device.
- Server: B12.
