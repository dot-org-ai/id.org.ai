/**
 * What the consent screen shows (docs/product-update/spec/backend.md#b2).
 *
 * At GET /oauth/authorize the provider builds a ConsentViewModel and hands it
 * to the host's renderer: id.org.ai's worker renders 3a, 3b or 3c
 * (worker/ui/screens/Consent.tsx) with the signed-in person and their
 * workspaces. A provider constructed without a renderer serves
 * `renderConsentFallback`, a minimal unstyled form with the same contract.
 *
 * Everything here is either what id.org.ai checked (the client it resolved,
 * the registered redirect_uri, the RFC 8707 resource) or the client's own
 * claims (its name, logo and links). A screen shows the claims as the app's
 * only when `client.verified` (D3, security.md).
 */
import type { OAuthProviderClient } from './provider'
import { isLoopbackUri, looksLikeCimdClientId } from './cimd'
import { SB_SCOPE_DO, SB_SCOPE_READ, SCOPE_DESCRIPTIONS } from './delegation'

const IDENTITY_SCOPES: ReadonlySet<string> = new Set(['openid', 'profile', 'email'])

export interface ConsentViewModel {
  client: {
    id: string
    /** The client's self-asserted client_name. Show it only when `verified`. */
    displayName: string
    /** What id.org.ai identifies the client by: the CIMD host, or the registered redirect host for DCR. */
    host: string
    /** https only. */
    logoUrl?: string
    /** A first-party seeded client, or a CIMD host on the verified list (D3). Every DCR client is unverified. */
    verified: boolean
    /** The client metadata document URL (CIMD clients). */
    cimdUrl?: string
    /** https only (CIMD `policy_uri` / `tos_uri`). */
    privacyUrl?: string
    termsUrl?: string
  }
  /** The validated redirect_uri. */
  redirect: { uri: string; host: string; origin: string; loopback: boolean }
  /** The scopes as validated and bound (the form posts them back). */
  scopes: string[]
  /** The RFC 8707 resource the grant is bound to. */
  resource?: string
  /** `basic` (3b) when every scope is an identity scope; `full` otherwise. Unverified clients render 3c either way. */
  request: 'basic' | 'full'
  /**
   * The access level (Read only / Read and act). `choice` when `sb:do` is
   * requested (the default is then `act`); a read-only sb request posts `read`.
   * Absent without sb scopes.
   */
  access?: { default: 'read' | 'act'; choice: boolean }
  /** The hidden fields the form posts back: client_id, redirect_uri, scope, state, code_challenge(_method), nonce, resource. */
  fields: Record<string, string>
  /** The signed-in person. */
  identityId: string
  /** `organization_id` from the authorization request, preselecting a workspace. */
  orgHint?: string
  /** The workspace this client was last consented for: preselected when the request names none. */
  rememberedOrgId?: string
}

export interface ConsentViewInput {
  client: OAuthProviderClient
  verifiedHosts: ReadonlySet<string>
  redirectUri: string
  scopes: string[]
  state?: string
  codeChallenge?: string
  codeChallengeMethod?: string
  nonce?: string
  resource?: string
  identityId: string
  orgHint?: string
  rememberedOrgId?: string
}

function hostOf(uri: string): string {
  try {
    return new URL(uri).host
  } catch {
    return uri
  }
}

// DCR doesn't type-check logo_uri, so a stored value may not even be a string.
const https = (u: unknown) => (typeof u === 'string' && u.startsWith('https://') ? u : undefined)

export function buildConsentViewModel(i: ConsentViewInput): ConsentViewModel {
  const cimd = looksLikeCimdClientId(i.client.id)
  const host = cimd ? hostOf(i.client.id) : hostOf(i.redirectUri)
  const verified = i.client.trusted || (cimd && i.verifiedHosts.has(host.toLowerCase()))
  let origin = ''
  try {
    origin = new URL(i.redirectUri).origin
  } catch {
    /* validated already; never reached */
  }
  const fields: Record<string, string> = { client_id: i.client.id, redirect_uri: i.redirectUri, scope: i.scopes.join(' ') }
  if (i.state) fields.state = i.state
  if (i.codeChallenge) fields.code_challenge = i.codeChallenge
  if (i.codeChallengeMethod) fields.code_challenge_method = i.codeChallengeMethod
  if (i.nonce) fields.nonce = i.nonce
  if (i.resource) fields.resource = i.resource
  const logoUrl = https(i.client.logo)
  const privacyUrl = https(i.client.policyUri)
  const termsUrl = https(i.client.tosUri)
  return {
    client: {
      id: i.client.id,
      displayName: i.client.name,
      host,
      verified,
      ...(logoUrl && { logoUrl }),
      ...(cimd && { cimdUrl: i.client.id }),
      ...(privacyUrl && { privacyUrl }),
      ...(termsUrl && { termsUrl }),
    },
    redirect: { uri: i.redirectUri, host: hostOf(i.redirectUri), origin, loopback: isLoopbackUri(i.redirectUri) },
    scopes: i.scopes,
    ...(i.resource !== undefined && { resource: i.resource }),
    request: i.scopes.length > 0 && i.scopes.every((s) => IDENTITY_SCOPES.has(s)) ? 'basic' : 'full',
    ...(i.scopes.includes(SB_SCOPE_DO)
      ? { access: { default: 'act' as const, choice: true } }
      : i.scopes.includes(SB_SCOPE_READ)
        ? { access: { default: 'read' as const, choice: false } }
        : {}),
    fields,
    identityId: i.identityId,
    ...(i.orgHint && { orgHint: i.orgHint }),
    ...(i.rememberedOrgId && { rememberedOrgId: i.rememberedOrgId }),
  }
}

/** The name a screen shows for the client: its own name only when verified, otherwise the host (D3). */
export function consentClientName(vm: ConsentViewModel): string {
  return vm.client.verified ? vm.client.displayName : vm.client.host
}

const esc = (v: string) =>
  v.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;')

/**
 * The minimal consent form for a provider without a renderer: unstyled, the
 * same POST contract (the hidden fields, approved=true|read|false), every
 * value escaped (a client chooses its own scope names and this page is served
 * from the issuer's origin), and never framed.
 */
export function renderConsentFallback(vm: ConsentViewModel): Response {
  const name = consentClientName(vm)
  const scopes = vm.scopes.map((s) => `<li>${esc(SCOPE_DESCRIPTIONS[s] ?? s)}</li>`).join('')
  const hidden = Object.entries(vm.fields)
    .map(([k, v]) => `<input type="hidden" name="${esc(k)}" value="${esc(v)}">`)
    .join('\n    ')
  const readOnly = vm.access?.choice ? '<button type="submit" name="approved" value="read">Allow read only</button>' : ''
  const html = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Authorize ${esc(name)}</title></head>
<body>
  <h1>Authorize application</h1>
  <div class="app-name">${esc(name)}</div>
  ${vm.client.cimdUrl && !vm.client.verified ? `<p>Calls itself “${esc(vm.client.displayName)}” · ${esc(vm.client.id)}</p>` : ''}
  <p>Returns to ${esc(vm.redirect.host)}</p>
  ${vm.resource ? `<p>Access for ${esc(hostOf(vm.resource))}</p>` : ''}
  <ul>${scopes}</ul>
  <form method="POST" action="/oauth/authorize">
    ${hidden}
    <button type="submit" name="approved" value="false">Deny</button>
    ${readOnly}
    <button type="submit" name="approved" value="true">Allow</button>
  </form>
</body>
</html>`
  return new Response(html, {
    status: 200,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      // A framed "Allow" can be clicked by someone who never saw what it grants.
      'X-Frame-Options': 'DENY',
      'Content-Security-Policy': "frame-ancestors 'none'",
      'Cache-Control': 'no-store',
    },
  })
}
