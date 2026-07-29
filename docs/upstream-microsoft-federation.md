# Upstream Microsoft federation — runbook

**Status: code shipped, app registration NOT created.** Everything in `src/sdk/federation/`
and `worker/routes/federation.ts` is merged-ready and tested. It is inert until an Entra
app registration exists and `MICROSOFT_CLIENT_ID` is set — until then
`/federation/microsoft/start` redirects to the email-code fallback and
`/federation/status` reports `microsoft.configured: false`. Nothing 500s.

Creating the app registration is the one step an agent cannot do; see
[The 5-minute step](#the-5-minute-step-owner-only).

---

## What this is

`id.org.ai` acts as the **broker**. Microsoft Entra terminates *here*; downstream
consumers verify an id.org.ai token and never talk to Microsoft.

```
alice@zebra.com
   │
   ├─ /federation/microsoft/start ─→ login.microsoftonline.com/organizations
   │                                    │  (Entra sees zebra.com is federated)
   │                                    └─→ Ping Identity ─→ back to Entra
   │  ←─ /federation/microsoft/callback ─┘   (id_token)
   │
   └─ [tenant blocks consent] ─→ /federation/email ─→ 6-digit code
   │
   ▼
id.org.ai identity row + id.org.ai JWT in the `auth` cookie
   │
   ▼
consumer verifies via POST /auth/verify   (never touches Microsoft)
```

**We never integrate Ping.** Zebra's Entra tenant federates to Ping internally. A standard
multi-tenant "Sign in with Microsoft" gets that traversal for free — Entra does home-realm
discovery on the email domain and bounces the user to Ping itself. Integrating Ping directly
would need a per-customer connection that only Zebra IT could set up.

## Scopes: `openid profile email`, and nothing else

This is a survival strategy, not minimalism. Those three are OIDC standard scopes that most
tenants' user-consent policies let a user grant themselves. Add one Graph scope
(`User.Read`, `offline_access`) and a tenant with "user consent disabled" or "consent only
for verified publishers" converts the sign-in into an **admin consent request**, which no
viewer can complete alone.

`test/federation-microsoft.test.ts` asserts the scope string and asserts the absence of
`offline_access` / `User.Read` / Graph, so widening it fails in CI rather than in a
customer's tenant.

## The two assurance levels

| | `federated-idp` | `email-code` |
|---|---|---|
| Proof | Entra signed an id_token we verified (sig + per-tenant issuer + audience + nonce) | The viewer returned a code sent to their mailbox |
| Proves | The directory authenticated them, under their own MFA/conditional-access policy | Mailbox custody at one instant |
| Capability ceiling | L2 | L1 |
| Principal id | `human:ms:<tid>:<oid>` | `human:email:<email>` |

`AuthBroker` **clamps** a federated identity's level to its assurance ceiling at read time.
This matters because `IdentityService.update` enforces level monotonicity — a level can only
go up. Without the clamp, a viewer who first arrived through Entra at L2 and later returned
through the weaker email path would keep L2 forever on strictly weaker evidence.

A resource can also demand assurance directly:

```ts
auth.check(identity, { minLevel: 2, minAssurance: 'federated-idp' })
// → { ok: false, reason: 'insufficient-assurance' } for an email-code viewer
```

`insufficient-assurance` is distinct from `insufficient-level` on purpose: the cure is
re-authentication through the stronger path, not a capability grant.

---

## The 5-minute step (owner only)

An agent cannot do this. The local Azure CLI session is signed in as a **guest**
(`nathan_do.industries#EXT#@bryantdo.onmicrosoft.com`) in a tenant that is not ours, holds
**zero directory roles** (`/me/memberOf` → `[]`), and `az ad app list --all` returns
`Insufficient privileges`. Even with the privilege, registering our production identity app
inside a third party's directory would hand them control of it.

### In the Entra portal — https://entra.microsoft.com

Do this in **a tenant you own** (not `bryantdo.onmicrosoft.com`).

1. **Applications → App registrations → New registration**
2. **Name:** `id.org.ai` — this exact string is what a Zebra employee reads on the consent
   screen. Make it the one you want them to see.
3. **Supported account types:** *Accounts in any organizational directory (Any Microsoft
   Entra ID tenant — Multitenant)*. This is the whole point; single-tenant would admit only
   your own directory.
4. **Redirect URI:** platform **Web**, value exactly:
   ```
   https://id.org.ai/federation/microsoft/callback
   ```
   Entra matches this verbatim. `GET https://id.org.ai/federation/status` echoes the value
   the running worker expects — paste from there if in doubt.
5. **Register.** Copy the **Application (client) ID**.
6. **Certificates & secrets → New client secret** → copy the **Value** (not the ID; it is
   shown once). Optional: skip this and register as a public client instead — PKCE alone
   authenticates the exchange, and the code supports both.
7. **API permissions:** Entra adds Microsoft Graph `User.Read` to new registrations by
   default. **Remove it.** It is not requested at runtime, but its presence invites someone
   to "helpfully" add it to the scope string later, which is the failure mode this whole
   design avoids.

### Then, on the worker

```bash
# 1. Set the client ID (public value — it appears in every authorization URL)
#    Edit worker/wrangler.jsonc → vars → uncomment and fill MICROSOFT_CLIENT_ID.

# 2. Set the secret (skip for a public-client registration)
cd worker && npx wrangler secret put MICROSOFT_CLIENT_SECRET

# 3. Allow the deck gate's host as a post-sign-in destination
#    worker/wrangler.jsonc → vars → "FEDERATION_CONTINUE_HOSTS": "pitch.visibility.cloud"

# 4. Deploy
cd .. && pnpm deploy

# 5. Verify
curl -s https://id.org.ai/federation/status | jq
npx vitest run --config test-e2e/vitest.config.ts test-e2e/federation.e2e.test.ts
```

### Optional, and worth it before a wide send

**Publisher verification** (Entra admin center → *Branding & properties* → *Publisher
verification*). A verified-publisher app passes some tenants' "allow user consent only for
verified publishers" policy that an unverified one does not. It needs a Microsoft Partner
Network account, so it is not a 5-minute step — but it is the single highest-leverage thing
for consent success across enterprises, and it can be added later without changing the
client ID.

---

## The Zebra consent risk, stated plainly

**We cannot know, before a zebra.com user actually tries, whether Zebra's tenant will let
them sign in.** Entra tenants can be configured to require **admin consent even for
`openid profile email`** — the setting is *User consent for applications: Do not allow user
consent*, and large regulated enterprises commonly use it or its verified-publisher variant.
When that is on, the viewer sees "Approval required" and cannot proceed, no matter how
correct our integration is. Only Zebra IT can approve the app in their directory.

This is not a bug we can fix and not a risk we can test away from outside. It is why the
email-code fallback exists and why it is the more heavily tested of the two paths.

Behaviour when it happens: Entra returns `AADSTS65001` / `AADSTS90094` / `consent_required`,
`classifyMicrosoftError` recognises it, and the callback redirects to
`/federation/email?reason=consent-required` — a page that explains in one line that their
organisation blocks unapproved apps and immediately offers the code. The viewer never sees
an error page and never needs to contact anyone.

**What remains untestable from outside**, precisely:

- Zebra's tenant consent policy (above).
- Zebra's conditional-access policy — a tenant can require a compliant/managed device for
  any external app; that surfaces as `AADSTS530xxx` and routes to the same fallback.
- Whether Zebra's Entra releases an `email` claim. Many tenants do not; the mapper falls
  back to `preferred_username` and then `upn`, which for work accounts is the work email.
  If all three are absent the viewer is told to use the code path.
- Ping's own MFA prompts. They happen inside Zebra's session and are invisible to us — by
  design, that is what federating means.

---

## Files

| Path | What |
|---|---|
| `src/sdk/federation/types.ts` | `AssuranceLevel`, `FederationProvenance`, `FederatedPrincipal`, the level ceiling |
| `src/sdk/federation/microsoft.ts` | Authorization URL, code exchange, id_token verification, principal mapping, AADSTS classification |
| `src/sdk/federation/email-code.ts` | `EmailCodeChannel` seam + WorkOS Magic Auth transport + send throttling |
| `worker/routes/federation.ts` | The six routes; `issueFederatedSession` is the single exit |
| `worker/views/email-code.ts` | The fallback page |
| `src/sdk/auth/broker.ts` / `broker-impl.ts` | `minAssurance`, `insufficient-assurance`, the assurance clamp |
| `src/sdk/auth/verify-token.ts` | Projects `assurance` / `emailDomain` / `federationTenantId` for downstream consumers |
| `test/federation-*.test.ts`, `test/auth-broker-assurance.test.ts` | 106 unit + integration tests |
| `test-e2e/federation.e2e.test.ts` | Live three-layer smoke test, skips cleanly per missing prerequisite |

## For a consuming gate

```ts
// 1. Send an unauthenticated viewer here.
`https://id.org.ai/federation/microsoft/start?continue=${encodeURIComponent(deckUrl)}`
// (add the gate's host to FEDERATION_CONTINUE_HOSTS first, or continue is dropped to "/")

// 2. On return, the `auth` cookie holds an id.org.ai JWT. Verify it:
const res = await fetch('https://id.org.ai/auth/verify', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ token: jwtFromCookie }),
})
const { valid, identity } = await res.json()

// 3. Authorise on the VERIFIED domain, not on a claimed email string.
if (!valid) return deny()
if (identity.emailDomain !== 'zebra.com') return deny()
// Optional: require the stronger path for the most sensitive material.
// if (identity.assurance !== 'federated-idp') return deny()
```
