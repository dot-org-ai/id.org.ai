/**
 * Phase 5 · Consent v2 (docs/product-update/spec/backend.md#b2) through the
 * real worker: /oauth/authorize renders 3a, 3b or 3c from the provider's view
 * model, with the signed-in person, their active workspaces (one preselected),
 * the access level and the CSRF binding. WorkOS and the client metadata host
 * are faked with fetchMock.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { SELF, fetchMock, env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test'
import worker from '../worker/index'
import type { Env } from '../worker/types'
import { buildConsentViewModel } from '../src/sdk/oauth/consent-view'
import { consentProps } from '../worker/ui/consent-props'
import { Consent } from '../worker/ui/screens/Consent'
import { renderHtml } from '../worker/ui/render'

const BASE = 'https://id.org.ai'
const WORKOS = 'https://api.workos.com'
const VERIFIED_APP = 'https://app.verified.example/oauth/client.json'
const VERIFIED_REDIRECT = 'https://app.verified.example/cb'
const DCR_REDIRECT = 'https://dcr-app.example/cb'

const b64url = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
async function challenge(): Promise<string> {
  const verifier = b64url(crypto.getRandomValues(new Uint8Array(32)))
  return b64url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))))
}
function setCookies(res: Response): Record<string, string> {
  const out: Record<string, string> = {}
  for (const line of res.headers.getSetCookie()) {
    const [pair] = line.split(';')
    const i = pair!.indexOf('=')
    out[pair!.slice(0, i).trim()] = pair!.slice(i + 1)
  }
  return out
}
const cookieHeader = (c: Record<string, string>) =>
  Object.entries(c)
    .filter(([, v]) => v !== '')
    .map(([k, v]) => `${k}=${v}`)
    .join('; ')
const unescape = (v: string) => v.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&')
function hiddenFields(html: string): Record<string, string> {
  const f: Record<string, string> = {}
  for (const m of html.matchAll(/<input type="hidden" name="([^"]+)" value="([^"]*)"\s*\/?>/g)) f[m[1]!] = unescape(m[2]!)
  return f
}
const formOf = (html: string) => html.match(/<form[\s\S]*<\/form>/)![0]

/** A person who signed in with WorkOS, with active memberships in Acme and Beta and an inactive one in Gamma. */
async function signIn(userId: string): Promise<Record<string, string>> {
  fetchMock
    .get(WORKOS)
    .intercept({ method: 'GET', path: '/user_management/organization_memberships', query: { user_id: userId, limit: '100' } })
    .reply(
      200,
      JSON.stringify({
        data: [
          { id: 'om_a', user_id: userId, organization_id: 'org_ACME', role: { slug: 'admin' }, status: 'active', created_at: 't', updated_at: 't' },
          { id: 'om_b', user_id: userId, organization_id: 'org_BETA', role: { slug: 'member' }, status: 'active', created_at: 't', updated_at: 't' },
          { id: 'om_c', user_id: userId, organization_id: 'org_GAMMA', role: { slug: 'member' }, status: 'inactive', created_at: 't', updated_at: 't' },
        ],
      }),
      { headers: { 'content-type': 'application/json' } },
    )
    .persist()
  const login = await SELF.fetch(`${BASE}/login?provider=GitHubOAuth`, { redirect: 'manual' })
  const state = new URL(login.headers.get('location')!).searchParams.get('state')!
  fetchMock
    .get(WORKOS)
    .intercept({ method: 'POST', path: '/user_management/authenticate' })
    .reply(
      200,
      JSON.stringify({ access_token: 'at_w', refresh_token: 'rt_w', user: { id: userId, email: `${userId.toLowerCase()}@example.com`, first_name: 'Ada', last_name: 'Lovelace' }, authentication_method: 'GitHubOAuth' }),
      { headers: { 'content-type': 'application/json' } },
    )
  const cb = await SELF.fetch(`${BASE}/api/callback?code=wos_code&state=${encodeURIComponent(state)}`, { redirect: 'manual' })
  expect(cb.status).toBe(302)
  return { auth: setCookies(cb).auth! }
}

function authorizeUrl(clientId: string, redirectUri: string, ch: string, extra: Record<string, string> = {}): string {
  const u = new URL(`${BASE}/oauth/authorize`)
  for (const [k, v] of Object.entries({ response_type: 'code', client_id: clientId, redirect_uri: redirectUri, scope: 'openid profile email', state: 'client-state', code_challenge: ch, code_challenge_method: 'S256', ...extra }))
    u.searchParams.set(k, v)
  return u.toString()
}

async function register(name: string): Promise<string> {
  const res = await SELF.fetch(`${BASE}/oauth/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ client_name: name, redirect_uris: [DCR_REDIRECT], token_endpoint_auth_method: 'none' }),
  })
  expect(res.status).toBe(201)
  return ((await res.json()) as { client_id: string }).client_id
}

/** The worker with env overrides (VERIFIED_CLIENT_HOSTS), as a browser navigation. */
async function workerPage(url: string, cookies: Record<string, string>, extra: Partial<Env> = {}): Promise<Response> {
  const ctx = createExecutionContext()
  const res = await worker.fetch(new Request(url, { redirect: 'manual', headers: { cookie: cookieHeader(cookies), accept: 'text/html' } }), { ...(env as unknown as Env), ...extra } as never, ctx)
  await waitOnExecutionContext(ctx)
  return res
}

beforeAll(() => {
  fetchMock.activate()
  fetchMock.disableNetConnect()
  fetchMock.get(WORKOS).intercept({ path: '/organizations/org_ACME' }).reply(200, JSON.stringify({ id: 'org_ACME', name: 'Acme', domains: [] }), { headers: { 'content-type': 'application/json' } }).persist()
  fetchMock.get(WORKOS).intercept({ path: '/organizations/org_BETA' }).reply(200, JSON.stringify({ id: 'org_BETA', name: 'Beta', domains: [] }), { headers: { 'content-type': 'application/json' } }).persist()
  fetchMock.get(WORKOS).intercept({ path: /^\/user_management\/users\// }).reply(500, '').persist()
  // A CIMD client whose host the tests list as verified.
  fetchMock
    .get('https://app.verified.example')
    .intercept({ path: '/oauth/client.json' })
    .reply(
      200,
      JSON.stringify({
        client_id: VERIFIED_APP,
        client_name: 'Verified <img src=x onerror=alert(1)> App',
        redirect_uris: [VERIFIED_REDIRECT],
        token_endpoint_auth_method: 'none',
        policy_uri: 'https://app.verified.example/privacy',
        tos_uri: 'https://app.verified.example/terms',
      }),
      { headers: { 'content-type': 'application/json', 'cache-control': 'max-age=3600' } },
    )
    .persist()
})
afterAll(() => fetchMock.deactivate())

describe('consent v2: /oauth/authorize renders the new screens', () => {
  it('an unverified DCR client asking for sb:do gets 3c: its host as name, the person, their active workspaces, act preselected', async () => {
    const cookies = await signIn('user_01CONSENT_A')
    const clientId = await register('Codex')
    const url = authorizeUrl(clientId, DCR_REDIRECT, await challenge(), { scope: 'openid sb:read sb:do', resource: 'https://api.sb/mcp' })
    const page = await SELF.fetch(url, { redirect: 'manual', headers: { cookie: cookieHeader(cookies) } })
    expect(page.status).toBe(200)
    expect(page.headers.get('x-frame-options')).toBe('DENY')
    // The POST answers with a redirect to the app, so form-action allows its origin.
    expect(page.headers.get('content-security-policy')).toMatch(/form-action 'self' https:\/\/dcr-app\.example/)
    const html = await page.text()

    expect(html).toMatch(/>dcr-app\.example wants to use api\.sb as you</)
    expect(html).not.toContain('Codex') // a DCR client's own name, never shown
    expect(html).toContain('id.org.ai can’t vouch for this app')
    expect(html).toContain('user_01consent_a@example.com')
    // Active workspaces only, named; the inactive one is left out.
    expect(html).toMatch(/<option value="org_ACME"[^>]*>Acme<\/option>/)
    expect(html).toMatch(/<option value="org_BETA"[^>]*>Beta<\/option>/)
    expect(html).not.toContain('org_GAMMA')
    expect(html).toMatch(/id="consent-access-act"[^>]*checked/)
    // 3c's flipped buttons: Allow comes first, outlined; Cancel is the primary.
    expect(html.indexOf('value="true"')).toBeLessThan(html.indexOf('value="false"'))
    expect(html).toMatch(/class="id-btn id-btn--primary[^"]*"[^>]*name="approved" value="false"/)

    // CSRF: the cookie, and the form's state bound to it (the client's own state is wrapped, not shown).
    const csrf = setCookies(page).__csrf
    expect(csrf).toBeTruthy()
    const fields = hiddenFields(html)
    expect(fields.state).not.toBe('client-state')
    expect(fields.csrf).toBe(csrf)
  })

  it('the route renders exactly what the screen renders from the same props', async () => {
    const cookies = await signIn('user_01CONSENT_B')
    const clientId = await register('Same props')
    const url = authorizeUrl(clientId, DCR_REDIRECT, await challenge(), { scope: 'openid sb:read', resource: 'https://api.sb/mcp', organization_id: 'org_BETA' })
    const page = await SELF.fetch(url, { redirect: 'manual', headers: { cookie: cookieHeader(cookies) } })
    const html = await page.text()
    const f = hiddenFields(html)

    const vm = buildConsentViewModel({
      client: { id: clientId, name: 'Same props', redirectUris: [DCR_REDIRECT], grantTypes: ['authorization_code'], responseTypes: ['code'], scopes: [], trusted: false, tokenEndpointAuthMethod: 'none', createdAt: 0 },
      verifiedHosts: new Set(),
      redirectUri: DCR_REDIRECT,
      scopes: f.scope!.split(' '),
      state: f.state,
      codeChallenge: f.code_challenge,
      codeChallengeMethod: 'S256',
      resource: f.resource,
      identityId: 'unused',
      orgHint: 'org_BETA',
    })
    const props = consentProps(vm, {
      account: { name: 'Ada Lovelace', email: 'user_01consent_b@example.com' },
      workspaces: [
        { id: 'org_ACME', name: 'Acme' },
        { id: 'org_BETA', name: 'Beta' },
      ],
      selectedOrgId: 'org_BETA',
      switchHref: `/login?prompt=login&continue=${encodeURIComponent(new URL(url).pathname + new URL(url).search)}`,
      fields: { client_id: f.client_id!, redirect_uri: f.redirect_uri!, scope: f.scope!, state: f.state!, code_challenge: f.code_challenge!, code_challenge_method: f.code_challenge_method!, resource: f.resource! },
      csrf: f.csrf!,
    })
    const expected = await renderHtml(Consent(props), { title: 't' })
    expect(formOf(html)).toBe(formOf(expected))
    // organization_id preselects Beta.
    expect(html).toMatch(/<option value="org_BETA" selected[^>]*>Beta<\/option>/)
  })

  it('a verified CIMD client gets 3a for sb scopes and 3b for identity scopes, under its own (escaped) name', async () => {
    const cookies = await signIn('user_01CONSENT_C')
    const verified = { VERIFIED_CLIENT_HOSTS: 'app.verified.example' }

    const full = await workerPage(authorizeUrl(VERIFIED_APP, VERIFIED_REDIRECT, await challenge(), { scope: 'openid sb:read sb:do', resource: 'https://api.sb/mcp' }), cookies, verified)
    expect(full.status).toBe(200)
    const a = await full.text()
    expect(a).toContain('Verified &lt;img src=x onerror=alert(1)&gt; App wants to use api.sb as you')
    expect(a).not.toContain('<img src=x')
    expect(a).not.toContain('can’t vouch')
    expect(a).toContain('Verified &lt;img src=x onerror=alert(1)&gt; App privacy policy')
    expect(a).toContain('href="https://app.verified.example/terms"')

    const basic = await workerPage(authorizeUrl(VERIFIED_APP, VERIFIED_REDIRECT, await challenge()), cookies, verified)
    const b = await basic.text()
    expect(b).toMatch(/>Sign in to Verified &lt;img src=x onerror=alert\(1\)&gt; App</)
    expect(b).toContain('Continue as Ada')

    // The same client unlisted is unverified: its host, 3c.
    const unlisted = await workerPage(authorizeUrl(VERIFIED_APP, VERIFIED_REDIRECT, await challenge()), cookies, { VERIFIED_CLIENT_HOSTS: '' })
    const c = await unlisted.text()
    expect(c).toMatch(/>app\.verified\.example wants to /)
    expect(c).not.toContain('Verified &lt;img')
  })
})
