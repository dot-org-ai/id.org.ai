/**
 * id.org.ai as the authorization server for api.sb and remote MCP clients,
 * through the real worker (SELF, real IdentityDO + KV; WorkOS faked):
 *
 *   - discovery advertises RFC 9207 `iss` and the sb scopes, and keeps
 *     everything existing clients read (DCR, device flow, introspection, the
 *     ID-JAG entry);
 *   - an MCP client (DCR, PKCE) asks for sb:read on https://api.sb/mcp: the
 *     consent screen (CSRF-bound) names it, the code comes back with its exact
 *     state and `iss`, the token introspects with aud = https://api.sb/mcp, and
 *     id.org.ai's own /mcp refuses it (wrong audience);
 *   - api.sb's LoginFlows sign-in (a confidential client, openid profile email,
 *     no resource) is unchanged but for the added `iss`;
 *   - a code redeems once, through the IdentityDO's takeOnce.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { SELF, fetchMock } from 'cloudflare:test'

const BASE = 'https://id.org.ai'
const WORKOS = 'https://api.workos.com'
const MCP_REDIRECT = 'https://mcp-client.example/oauth/callback'
const SB_REDIRECT = 'https://api.sb/callback'

function b64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}
async function pkce(): Promise<{ verifier: string; challenge: string }> {
  const verifier = b64url(crypto.getRandomValues(new Uint8Array(32)))
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
  return { verifier, challenge: b64url(new Uint8Array(hash)) }
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
function consentFields(html: string): Record<string, string> {
  const f: Record<string, string> = {}
  for (const m of html.matchAll(/<input type="hidden" name="([^"]+)" value="([^"]*)">/g)) {
    f[m[1]!] = m[2]!.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&')
  }
  return f
}
async function register(meta: Record<string, unknown>): Promise<{ client_id: string; client_secret?: string }> {
  const res = await SELF.fetch(`${BASE}/oauth/register`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(meta) })
  expect(res.status).toBe(201)
  return (await res.json()) as { client_id: string; client_secret?: string }
}

let seq = 0
async function signIn(): Promise<Record<string, string>> {
  const userId = `user_01MCPAS${++seq}`
  const login = await SELF.fetch(`${BASE}/login?provider=GitHubOAuth`, { redirect: 'manual' })
  const state = new URL(login.headers.get('location')!).searchParams.get('state')!
  fetchMock
    .get(WORKOS)
    .intercept({ method: 'POST', path: '/user_management/authenticate' })
    .reply(
      200,
      JSON.stringify({
        access_token: 'at_opaque_workos',
        refresh_token: 'rt_workos',
        user: { id: userId, email: `${userId.toLowerCase()}@example.com`, first_name: 'Ada', last_name: 'Lovelace' },
        organization_id: 'org_01TEST',
        authentication_method: 'GitHubOAuth',
      }),
      { headers: { 'content-type': 'application/json' } },
    )
  const cb = await SELF.fetch(`${BASE}/api/callback?code=wos_code&state=${encodeURIComponent(state)}`, { redirect: 'manual' })
  expect(cb.status).toBe(302)
  return { auth: setCookies(cb).auth! }
}

function authorizeUrl(clientId: string, redirectUri: string, challenge: string, state: string, extra: Record<string, string> = {}): string {
  const u = new URL(`${BASE}/oauth/authorize`)
  for (const [k, v] of Object.entries({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: redirectUri,
    scope: 'openid profile email',
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    ...extra,
  }))
    u.searchParams.set(k, v)
  return u.toString()
}

/** GET the consent page, POST approval with its CSRF cookie; returns the redirect back. */
async function consent(url: string, cookies: Record<string, string>, approved = 'true'): Promise<URL> {
  const page = await SELF.fetch(url, { redirect: 'manual', headers: { cookie: cookieHeader(cookies) } })
  if (page.status === 302) return new URL(page.headers.get('location')!)
  expect(page.status).toBe(200)
  const csrf = setCookies(page).__csrf!
  const html = await page.text()
  const res = await SELF.fetch(`${BASE}/oauth/authorize`, {
    method: 'POST',
    redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: cookieHeader({ ...cookies, __csrf: csrf }) },
    body: new URLSearchParams({ ...consentFields(html), approved }).toString(),
  })
  expect(res.status).toBe(302)
  return new URL(res.headers.get('location')!)
}

async function token(body: Record<string, string>, headers: Record<string, string> = {}) {
  const res = await SELF.fetch(`${BASE}/oauth/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers },
    body: new URLSearchParams(body).toString(),
  })
  return { status: res.status, body: (await res.json()) as Record<string, any> }
}
async function introspect(t: string): Promise<Record<string, any>> {
  const res = await SELF.fetch(`${BASE}/oauth/introspect`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ token: t }).toString(),
  })
  return (await res.json()) as Record<string, any>
}

beforeAll(() => {
  fetchMock.activate()
  fetchMock.disableNetConnect()
  fetchMock.get(WORKOS).intercept({ path: /^\/user_management\/users\// }).reply(500, '').persist()
  fetchMock.get(WORKOS).intercept({ path: /^\/organizations\// }).reply(500, '').persist()
})
afterAll(() => fetchMock.deactivate())

describe('discovery', () => {
  for (const path of ['/.well-known/oauth-authorization-server', '/.well-known/openid-configuration']) {
    it(`${path} advertises iss and the sb scopes, and keeps what clients rely on`, async () => {
      const res = await SELF.fetch(`${BASE}${path}`)
      expect(res.status).toBe(200)
      const d = (await res.json()) as Record<string, any>
      expect(d.issuer).toBe(BASE)
      expect(d.authorization_response_iss_parameter_supported).toBe(true)
      expect(d.scopes_supported).toEqual(['openid', 'profile', 'email', 'offline_access', 'sb:read', 'sb:do'])
      // unchanged
      expect(d.registration_endpoint).toBe(`${BASE}/oauth/register`)
      expect(d.introspection_endpoint).toBe(`${BASE}/oauth/introspect`)
      expect(d.device_authorization_endpoint).toBe(`${BASE}/oauth/device`)
      expect(d.code_challenge_methods_supported).toEqual(['S256'])
      expect(d.token_endpoint_auth_methods_supported).toEqual(['none', 'client_secret_basic', 'client_secret_post'])
      expect(d.grant_types_supported).toEqual(['authorization_code', 'refresh_token', 'client_credentials', 'urn:ietf:params:oauth:grant-type:device_code'])
    })
  }

  it('the AS metadata keeps its ID-JAG entry and agent_auth block (auth.md check)', async () => {
    const d = (await (await SELF.fetch(`${BASE}/.well-known/oauth-authorization-server`)).json()) as Record<string, any>
    expect(d.subject_token_types_supported).toEqual(['urn:ietf:params:oauth:token-type:id-jag'])
    expect(d.agent_auth.identity_endpoint).toBe(`${BASE}/agent/identity`)
  })

  it("id.org.ai's own /mcp protected-resource metadata is unchanged", async () => {
    const d = (await (await SELF.fetch(`${BASE}/.well-known/oauth-protected-resource`)).json()) as Record<string, any>
    expect(d).toEqual({ resource: `${BASE}/mcp`, authorization_servers: [BASE], scopes_supported: ['openid', 'profile', 'email'], bearer_methods_supported: ['header'] })
  })
})

describe('an MCP client delegated sb:read for api.sb', () => {
  it('consent → code with state and iss → token with aud https://api.sb/mcp, refused at id.org.ai/mcp', async () => {
    const client = await register({ client_name: 'Some MCP Client', redirect_uris: [MCP_REDIRECT], token_endpoint_auth_method: 'none', grant_types: ['authorization_code', 'refresh_token'] })
    const { verifier, challenge } = await pkce()
    const cookies = await signIn()
    const STATE = 'mcp-state-Zz9'
    const url = authorizeUrl(client.client_id, MCP_REDIRECT, challenge, STATE, { scope: 'sb:read', resource: 'https://api.sb/mcp' })

    const page = await SELF.fetch(url, { redirect: 'manual', headers: { cookie: cookieHeader(cookies) } })
    expect(page.status).toBe(200)
    expect(page.headers.get('x-frame-options')).toBe('DENY')
    const html = await page.text()
    expect(html).toContain('Read your Startups on api.sb')
    expect(html).toContain('Access for api.sb')

    const back = await consent(url, cookies)
    expect(`${back.origin}${back.pathname}`).toBe(MCP_REDIRECT)
    expect(back.searchParams.get('state')).toBe(STATE)
    expect(back.searchParams.get('iss')).toBe(BASE)
    const code = back.searchParams.get('code')!

    const t = await token({ grant_type: 'authorization_code', code, redirect_uri: MCP_REDIRECT, client_id: client.client_id, code_verifier: verifier, resource: 'https://api.sb/mcp' })
    expect(t.status).toBe(200)
    expect(t.body.scope).toBe('sb:read')
    const i = await introspect(t.body.access_token)
    expect(i).toMatchObject({ active: true, aud: 'https://api.sb/mcp', scope: 'sb:read', client_id: client.client_id })
    expect(i.sub).toBeTruthy()

    // Minted for api.sb: id.org.ai's own /mcp refuses it (RFC 8707 audience).
    const mcp = await SELF.fetch(`${BASE}/mcp`, { method: 'POST', headers: { authorization: `Bearer ${t.body.access_token}`, 'content-type': 'application/json' }, body: '{}' })
    expect(mcp.status).toBe(401)
    expect(mcp.headers.get('www-authenticate')).toContain('invalid_token')
  })

  it('a token for id.org.ai/mcp still works there (unchanged)', async () => {
    const client = await register({ client_name: 'Old MCP Client', redirect_uris: [MCP_REDIRECT], token_endpoint_auth_method: 'none' })
    const { verifier, challenge } = await pkce()
    const cookies = await signIn()
    const back = await consent(authorizeUrl(client.client_id, MCP_REDIRECT, challenge, 's', { resource: `${BASE}/mcp` }), cookies)
    expect(back.searchParams.get('iss')).toBe(BASE)
    const t = await token({ grant_type: 'authorization_code', code: back.searchParams.get('code')!, redirect_uri: MCP_REDIRECT, client_id: client.client_id, code_verifier: verifier })
    expect(t.status).toBe(200)
    expect((await introspect(t.body.access_token)).aud).toBe(`${BASE}/mcp`)
    const mcp = await SELF.fetch(`${BASE}/mcp`, { headers: { authorization: `Bearer ${t.body.access_token}` } })
    expect(mcp.status).not.toBe(401)
  })

  it('a code redeems once, even in parallel', async () => {
    const client = await register({ client_name: 'Racer', redirect_uris: [MCP_REDIRECT], token_endpoint_auth_method: 'none' })
    const { verifier, challenge } = await pkce()
    const cookies = await signIn()
    const back = await consent(authorizeUrl(client.client_id, MCP_REDIRECT, challenge, 's'), cookies)
    const code = back.searchParams.get('code')!
    const body = { grant_type: 'authorization_code', code, redirect_uri: MCP_REDIRECT, client_id: client.client_id, code_verifier: verifier }
    const results = await Promise.all(Array.from({ length: 6 }, () => token(body)))
    expect(results.filter((r) => r.status === 200)).toHaveLength(1)
  })
})

describe("api.sb's LoginFlows sign-in is unchanged", () => {
  it('confidential client, openid profile email, nonce, no resource: code (+ iss) → tokens → introspect/userinfo', async () => {
    // Registered the way api.sb's OAUTH_CLIENT_ID is: confidential, its /callback.
    const client = await register({
      client_name: 'api.sb',
      redirect_uris: [SB_REDIRECT],
      token_endpoint_auth_method: 'client_secret_basic',
      grant_types: ['authorization_code', 'refresh_token'],
      scope: 'openid profile email',
    })
    const { verifier, challenge } = await pkce()
    const cookies = await signIn()
    const STATE = 'Sb_state_0123456789'
    const back = await consent(authorizeUrl(client.client_id, SB_REDIRECT, challenge, STATE, { nonce: 'sb-nonce' }), cookies)
    expect(back.searchParams.get('state')).toBe(STATE)
    expect(back.searchParams.get('iss')).toBe(BASE)
    expect([...back.searchParams.keys()].sort()).toEqual(['code', 'iss', 'state'])

    const basic = `Basic ${btoa(`${encodeURIComponent(client.client_id)}:${encodeURIComponent(client.client_secret!)}`)}`
    const t = await token({ grant_type: 'authorization_code', code: back.searchParams.get('code')!, redirect_uri: SB_REDIRECT, code_verifier: verifier, client_id: client.client_id }, { authorization: basic })
    expect(t.status).toBe(200)
    expect(t.body.id_token).toBeTruthy()
    expect(t.body.scope).toBe('openid profile email')
    const i = await introspect(t.body.access_token)
    expect(i.active).toBe(true)
    expect(i.aud).toBeUndefined()
    const ui = await SELF.fetch(`${BASE}/oauth/userinfo`, { headers: { authorization: `Bearer ${t.body.access_token}` } })
    expect(ui.status).toBe(200)
    expect(((await ui.json()) as any).email).toMatch(/@example\.com$/)
  })
})
