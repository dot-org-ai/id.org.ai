# Flows

Mock: `../mocks/screens/0-flow-map.html`.

## One pipeline for every sign-in

Every entry point runs the same steps in the same order. A step is skipped unless its condition holds, so a returning person on a trusted app sees nothing at all.

**Entry points:**

| Entry point | How it enters |
|---|---|
| App or website | OAuth redirect to `/oauth/authorize` |
| CLI or device | Device code at `/device` |
| Agent link | Approval or claim (`/agents/approve/:id`, `/claim/:token`, `/approvals/:id`) |
| Email link | One-time code (`/login/code/:flow`, `/invite/:token`) |

**The pipeline:**

| # | Step | Runs only when | Screen |
|---|---|---|---|
| 1 | Sign in | There is no session, or `prompt=login` | 1a, then 1b / 1c / provider. 1d on first run. 1e and 1f when needed. 6d when two-step is required. |
| 2 | Choose account | 2+ sessions in this browser and none remembered for this client, or `prompt=select_account` | 2a |
| 3 | Choose workspace | 2+ workspaces, no `organization_id` hint, and none remembered for this client | 2b |
| 4 | Authorize | First use by a third-party app, new permissions, an app on this computer (loopback), or any `sb:*` scope | 3a / 3b / 3c. 7c when workspace policy blocks the app. |
| 5 | Confirm it's you | Act permissions (`sb:do`), a Privileged agent, or `max_age`, when the last sign-in is older than the limit (10 minutes for act permissions) | 6a |
| 6 | Back to the app | Always | A redirect with the code, via 2c after an interactive step. For devices, "Go back to your terminal" (4d). |

**Cross-cutting rules:**

- **Errors**: one HTML page, never JSON, for browser requests. With an untrusted redirect, never send the person back to it (7a).
- **Agents**: approve the trust level once (5a), then per-action approvals by push (5b).
- **Sign out**: this app only by default; this browser or everywhere on request (6b).
- **Passkey offer** (6c): once, right after a code sign-in, before step 6.

## Sequence: an app signs someone in (OAuth)

```
App ──▶ GET /oauth/authorize?client_id&redirect_uri&scope&state&code_challenge&resource[&prompt][&organization_id][&login_hint]
          │ validate client (DCR or CIMD) + redirect_uri ──fail──▶ 7a (never redirect)
          │ no session / prompt=login ──▶ /login (1a) ──▶ 1b|1c|provider ──▶ [1d first run] ──▶ [6d two-step] ──▶ back
          │ multiple sessions, none remembered / prompt=select_account ──▶ 2a ──▶ back
          │ org needed and ambiguous ──▶ 2b ──▶ back
          │ workspace policy blocks client ──▶ 7c
          │ consent required ──▶ 3a|3b|3c ──Allow──▶ [6a if sb:do and auth_time > 10 min] ──▶ issue code
          ▼
        302 redirect_uri?code&state&iss   (via 2c when the person just made a choice on id.org.ai)
```

## Sequence: a CLI signs in (device flow)

```
CLI ── POST /oauth/device {client_id, scope} (+ User-Agent, IP → device metadata) ──▶ {device_code, user_code, verification_uri_complete}
CLI prints 4a, opens verification_uri_complete in the browser
Browser ── GET /device?code=WDJB-MJHT ──▶ [sign in] ──▶ 4b ──Confirm──▶ POST /device/decision ──▶ signed (4d in place)
CLI polls POST /oauth/token (device_code) ──▶ authorization_pending … ──▶ tokens ──▶ prints "✓ Signed in as …"
```

## Sequence: an agent asks to work as you

```
Agent ── POST /agent/register (delegated) ──▶ status pending + approval URL
Person ── GET /agents/approve/:id (5a) ──Approve (trust, spend, expiry)──▶ [6a if Privileged] ──▶ agent active
Later: agent wants to send/delete/spend ──▶ approval request ──▶ push/email link ──▶ 5b ──Approve──▶ action proceeds
```

## Sequence: claim

```
Agent provisions sandbox ──▶ claim token clm_…
Person ── GET /claim/:token (5c) ──Claim workspace──▶ tenant linked to identity + workspace
     or ── GET /claim/:token/repo (5d) ──commit workflow──▶ GitHub webhook / Action OIDC ──▶ claimed (page updates live)
```
