/**
 * Part 2 through the real worker (SELF, real IdentityDO + KV + signing keys;
 * WorkOS and client-metadata hosts faked with fetchMock):
 *
 *   - discovery advertises CIMD; DCR and the ID-JAG entry stay;
 *   - Claude Code's published CIMD document signs in over a loopback port;
 *     the fetcher refuses private hosts, redirects, oversized and non-JSON
 *     documents;
 *   - an api.sb access token is an RFC 9068 JWT that verifies against
 *     /.well-known/jwks.json, and is refused as a Person credential at every
 *     identity entry point (AuthService, AuthIdentity, /auth/verify, /me, the
 *     `auth` cookie, /dash, /api/*);
 *   - AuthService.exchangeToken (the binding) names the agent in `act`;
 *   - GET /api/grants and POST /api/grants/revoke.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { SELF, fetchMock, env, createExecutionContext } from 'cloudflare:test'
import * as jose from 'jose'
import { authService } from './helpers/auth-service'
import { AuthIdentity } from '../worker/index'

const BASE = 'https://id.org.ai'
const WORKOS = 'https://api.workos.com'
const CLAUDE_CODE = 'https://claude.ai/oauth/claude-code-client-metadata'
const REDIRECT = 'https://mcp-client-2.example/cb'

const b64url = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
async function pkce() {
  const verifier = b64url(crypto.getRandomValues(new Uint8Array(32)))
  return { verifier, challenge: b64url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)))) }
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
const decode = (jwt: string) => {
  const dec = (s: string) => JSON.parse(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4)))
  const [h, p] = jwt.split('.')
  return { header: dec(h!), payload: dec(p!) }
}

let seq = 0
async function signIn(): Promise<Record<string, string>> {
  const userId = `user_01MCPAS2_${++seq}`
  const login = await SELF.fetch(`${BASE}/login?provider=GitHubOAuth`, { redirect: 'manual' })
  const state = new URL(login.headers.get('location')!).searchParams.get('state')!
  fetchMock
    .get(WORKOS)
    .intercept({ method: 'POST', path: '/user_management/authenticate' })
    .reply(
      200,
      JSON.stringify({ access_token: 'at_w', refresh_token: 'rt_w', user: { id: userId, email: `${userId.toLowerCase()}@example.com`, first_name: 'Ada', last_name: 'L' }, organization_id: 'org_01TEST', authentication_method: 'GitHubOAuth' }),
      { headers: { 'content-type': 'application/json' } },
    )
  const cb = await SELF.fetch(`${BASE}/api/callback?code=wos_code&state=${encodeURIComponent(state)}`, { redirect: 'manual' })
  expect(cb.status).toBe(302)
  return { auth: setCookies(cb).auth! }
}

function authorizeUrl(clientId: string, redirectUri: string, challenge: string, extra: Record<string, string> = {}) {
  const u = new URL(`${BASE}/oauth/authorize`)
  for (const [k, v] of Object.entries({ response_type: 'code', client_id: clientId, redirect_uri: redirectUri, scope: 'openid profile email', state: 'st-2', code_challenge: challenge, code_challenge_method: 'S256', ...extra }))
    u.searchParams.set(k, v)
  return u.toString()
}

async function consent(url: string, cookies: Record<string, string>): Promise<URL> {
  const page = await SELF.fetch(url, { redirect: 'manual', headers: { cookie: cookieHeader(cookies) } })
  if (page.status === 302) return new URL(page.headers.get('location')!)
  expect(page.status).toBe(200)
  const csrf = setCookies(page).__csrf!
  const res = await SELF.fetch(`${BASE}/oauth/authorize`, {
    method: 'POST',
    redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: cookieHeader({ ...cookies, __csrf: csrf }) },
    body: new URLSearchParams({ ...consentFields(await page.text()), approved: 'true' }).toString(),
  })
  expect(res.status).toBe(302)
  return new URL(res.headers.get('location')!)
}

async function token(body: Record<string, string>) {
  const res = await SELF.fetch(`${BASE}/oauth/token`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(body).toString() })
  return { status: res.status, body: (await res.json()) as Record<string, any> }
}
async function introspect(t: string) {
  return (await (await SELF.fetch(`${BASE}/oauth/introspect`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ token: t }).toString() })).json()) as Record<string, any>
}
async function register(meta: Record<string, unknown>) {
  const res = await SELF.fetch(`${BASE}/oauth/register`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(meta) })
  expect(res.status).toBe(201)
  return (await res.json()) as { client_id: string }
}

/** A signed-in Person with an sb:read sb:do grant to a DCR client: the JWT, refresh token and cookies. */
async function sbTokens() {
  const client = await register({ client_name: 'sb client', redirect_uris: [REDIRECT], token_endpoint_auth_method: 'none' })
  const { verifier, challenge } = await pkce()
  const cookies = await signIn()
  const back = await consent(authorizeUrl(client.client_id, REDIRECT, challenge, { scope: 'openid sb:read sb:do', resource: 'https://api.sb/mcp' }), cookies)
  const t = await token({ grant_type: 'authorization_code', code: back.searchParams.get('code')!, redirect_uri: REDIRECT, client_id: client.client_id, code_verifier: verifier })
  expect(t.status).toBe(200)
  return { clientId: client.client_id, cookies, ...t.body }
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
    it(`${path} advertises CIMD and keeps DCR`, async () => {
      const d = (await (await SELF.fetch(`${BASE}${path}`)).json()) as Record<string, any>
      expect(d.client_id_metadata_document_supported).toBe(true)
      expect(d.registration_endpoint).toBe(`${BASE}/oauth/register`)
      expect(d.token_endpoint_auth_methods_supported).toContain('none')
      expect(d.authorization_response_iss_parameter_supported).toBe(true)
      // token exchange is RPC-only: not advertised on the HTTP token endpoint
      expect(d.grant_types_supported).not.toContain('urn:ietf:params:oauth:grant-type:token-exchange')
    })
  }
})

describe('Client ID Metadata Documents through the worker', () => {
  it("Claude Code's published document signs in on a loopback port", async () => {
    fetchMock
      .get('https://claude.ai')
      .intercept({ path: '/oauth/claude-code-client-metadata', method: 'GET' })
      .reply(
        200,
        JSON.stringify({ client_id: CLAUDE_CODE, client_name: 'Claude Code', client_uri: 'https://claude.ai', redirect_uris: ['http://localhost/callback', 'http://127.0.0.1/callback'], grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'], token_endpoint_auth_method: 'none' }),
        { headers: { 'content-type': 'application/json', 'cache-control': 'max-age=3600' } },
      )
    const { verifier, challenge } = await pkce()
    const cookies = await signIn()
    const redirect = 'http://localhost:54321/callback'
    const url = authorizeUrl(CLAUDE_CODE, redirect, challenge, { scope: 'sb:read', resource: 'https://api.sb/mcp' })
    const page = await SELF.fetch(url, { redirect: 'manual', headers: { cookie: cookieHeader(cookies) } })
    expect(page.status).toBe(200)
    const html = await page.text()
    expect(html).toContain('<div class="app-name">claude.ai</div>')
    const back = await consent(url, cookies) // served from the cache: the mock answered once
    expect(`${back.origin}${back.pathname}`).toBe(redirect)
    expect(back.searchParams.get('iss')).toBe(BASE)
    const t = await token({ grant_type: 'authorization_code', code: back.searchParams.get('code')!, redirect_uri: redirect, client_id: CLAUDE_CODE, code_verifier: verifier })
    expect(t.status).toBe(200)
    expect(decode(t.body.access_token).payload.client_id).toBe(CLAUDE_CODE)
  })

  const refused: Array<[string, string, (() => void) | null]> = [
    ['a private host', 'https://10.0.0.1/client.json', null],
    ['a loopback name', 'https://localhost/client.json', null],
    ['a metadata address', 'https://169.254.169.254/latest', null],
    [
      'a redirect',
      'https://redirecting.example/client.json',
      () => fetchMock.get('https://redirecting.example').intercept({ path: '/client.json' }).reply(302, '', { headers: { location: 'https://10.0.0.1/x' } }),
    ],
    [
      'an oversized document',
      'https://big.example/client.json',
      () => fetchMock.get('https://big.example').intercept({ path: '/client.json' }).reply(200, JSON.stringify({ client_id: 'https://big.example/client.json', pad: 'x'.repeat(20000) }), { headers: { 'content-type': 'application/json' } }),
    ],
    [
      'a non-JSON document',
      'https://html.example/client.json',
      () => fetchMock.get('https://html.example').intercept({ path: '/client.json' }).reply(200, '<html></html>', { headers: { 'content-type': 'text/html' } }),
    ],
    [
      'a 404',
      'https://missing.example/client.json',
      () => fetchMock.get('https://missing.example').intercept({ path: '/client.json' }).reply(404, ''),
    ],
  ]
  for (const [why, clientId, mock] of refused) {
    it(`refuses ${why}`, async () => {
      mock?.()
      const { challenge } = await pkce()
      const res = await SELF.fetch(authorizeUrl(clientId, 'http://localhost:1/callback', challenge), { redirect: 'manual' })
      expect(res.status).toBe(400)
      expect(((await res.json()) as any).error).toBe('invalid_client')
    })
  }
})

describe('JWT access tokens for api.sb', () => {
  it('verify against /.well-known/jwks.json (jose, typ at+jwt, crit aud_bound, aud, iss)', async () => {
    const t = await sbTokens()
    const jwks = jose.createLocalJWKSet((await (await SELF.fetch(`${BASE}/.well-known/jwks.json`)).json()) as jose.JSONWebKeySet)
    const { payload, protectedHeader } = await jose.jwtVerify(t.access_token, jwks, { issuer: BASE, audience: 'https://api.sb/mcp', typ: 'at+jwt', crit: { aud_bound: true } })
    expect(protectedHeader.typ).toBe('at+jwt')
    expect(payload).toMatchObject({ client_id: t.clientId, scope: 'openid sb:read sb:do', aud: 'https://api.sb/mcp' })
    expect(String(payload.sub)).toMatch(/^human:/)
    expect(payload.exp! - payload.iat!).toBe(900)
    expect((await introspect(t.access_token))).toMatchObject({ active: true, aud: 'https://api.sb/mcp' })
  })

  it('is refused as a Person credential at every identity entry point', async () => {
    const t = await sbTokens()
    const jwt = t.access_token
    // AuthService.verifyToken (other workers' env.AUTH / AUTH_SERVICE)
    expect((await authService().verifyToken(jwt)).valid).toBe(false)
    // AuthIdentity.verifyToken (api.sb's AUTH binding)
    const identity = new AuthIdentity(createExecutionContext(), env as never)
    expect((await identity.verifyToken(jwt)).valid).toBe(false)
    // POST /auth/verify
    expect((await SELF.fetch(`${BASE}/auth/verify`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ token: jwt }) })).status).toBe(401)
    // /me as bearer and as the auth cookie
    expect((await SELF.fetch(`${BASE}/me`, { headers: { authorization: `Bearer ${jwt}` } })).status).toBe(401)
    expect((await SELF.fetch(`${BASE}/me`, { headers: { cookie: `auth=${jwt}` } })).status).toBe(401)
    // the auth cookie does not sign anyone in at /oauth/authorize, /dash or /api/*
    const { challenge } = await pkce()
    const az = await SELF.fetch(authorizeUrl(t.clientId, REDIRECT, challenge), { redirect: 'manual', headers: { cookie: `auth=${jwt}` } })
    expect(new URL(az.headers.get('location')!).pathname).toBe('/login')
    const dash = await SELF.fetch(`${BASE}/dash/profile`, { redirect: 'manual', headers: { cookie: `auth=${jwt}` } })
    expect(dash.status).toBe(302)
    expect(dash.headers.get('location')).toBe('/')
    expect((await SELF.fetch(`${BASE}/api/grants`, { headers: { cookie: `auth=${jwt}` } })).status).toBe(401)
    // …while the Person's real session cookie still works there.
    expect((await SELF.fetch(`${BASE}/me`, { headers: { cookie: cookieHeader(t.cookies) } })).status).toBe(200)
  })
})

describe('token exchange through the AuthService binding', () => {
  it('names the agent in act, keeps the Person in sub', async () => {
    const t = await sbTokens()
    const r = await authService().exchangeToken({ subject_token: t.access_token, subject_token_type: 'urn:ietf:params:oauth:token-type:access_token', actor: { sub: 'workers/sextant' }, scope: 'sb:read' })
    expect(r.ok).toBe(true)
    if (!r.ok) return
    const p = decode(r.access_token).payload
    expect(p).toMatchObject({ sub: decode(t.access_token).payload.sub, client_id: t.clientId, act: { sub: 'workers/sextant' }, scope: 'sb:read', aud: 'https://api.sb/mcp' })
    expect((await introspect(r.access_token)).act).toEqual({ sub: 'workers/sextant' })
  })

  it('the token endpoint does not accept token exchange over HTTP', async () => {
    const t = await sbTokens()
    const r = await token({ grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange', subject_token: t.access_token, subject_token_type: 'urn:ietf:params:oauth:token-type:access_token' })
    expect(r.status).toBe(400)
    expect(r.body.error).toBe('unsupported_grant_type')
  })
})

describe('grants', () => {
  it('a Person lists and revokes a client grant; its refresh token then fails', async () => {
    const t = await sbTokens()
    const list = await SELF.fetch(`${BASE}/api/grants`, { headers: { cookie: cookieHeader(t.cookies) } })
    expect(list.status).toBe(200)
    const grants = ((await list.json()) as any).grants as Array<{ client_id: string; scopes: string[] }>
    expect(grants.find((g) => g.client_id === t.clientId)?.scopes).toEqual(['openid', 'sb:read', 'sb:do'])

    const rev = await SELF.fetch(`${BASE}/api/grants/revoke`, { method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(t.cookies) }, body: JSON.stringify({ client_id: t.clientId }) })
    expect(rev.status).toBe(200)
    expect(((await rev.json()) as any).revoked).toBe(true)
    expect((await introspect(t.access_token)).active).toBe(false)
    const r = await token({ grant_type: 'refresh_token', refresh_token: t.refresh_token, client_id: t.clientId })
    expect(r.status).toBe(400)
    expect(r.body.error).toBe('invalid_grant')
  })

  it('needs a signed-in Person', async () => {
    expect((await SELF.fetch(`${BASE}/api/grants`)).status).toBe(401)
    expect((await SELF.fetch(`${BASE}/api/grants/revoke`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"client_id":"x"}' })).status).toBe(401)
  })
})

describe('CIMD fetch budget', () => {
  it('an address that keeps naming new client_ids is cut off after the budget, without poisoning the cache', async () => {
    const ip = '203.0.113.77'
    const { challenge } = await pkce()
    let last = 0
    for (let i = 0; i < 31; i++) {
      const host = `spray${i}.example`
      fetchMock.get(`https://${host}`).intercept({ path: '/c.json' }).reply(404, '')
      const res = await SELF.fetch(authorizeUrl(`https://${host}/c.json`, 'http://localhost:1/callback', challenge), { redirect: 'manual', headers: { 'cf-connecting-ip': ip } })
      expect(res.status).toBe(400)
      const body = (await res.json()) as any
      if (i === 30) expect(body.error_description).toContain('too many client metadata fetches')
      last = i
    }
    expect(last).toBe(30)
    // Another address is unaffected.
    fetchMock.get('https://spray30.example').intercept({ path: '/c.json' }).reply(404, '')
    const other = await SELF.fetch(authorizeUrl('https://spray30.example/c.json', 'http://localhost:1/callback', challenge), { redirect: 'manual', headers: { 'cf-connecting-ip': '203.0.113.78' } })
    expect(((await other.json()) as any).error_description).toContain('HTTP 404')
  })
})

describe('PR #31 review round 1: revocation vs a client that keeps refreshing', () => {
  it('B1: across 8 trials, no refresh token or access token survives POST /api/grants/revoke', async () => {
    let survivors = 0
    for (let trial = 0; trial < 8; trial++) {
      const t = await sbTokens()
      let rt = t.refresh_token as string
      let at = t.access_token as string
      let stop = false
      const loop = (async () => {
        while (!stop) {
          const r = await token({ grant_type: 'refresh_token', refresh_token: rt, client_id: t.clientId })
          if (r.status !== 200) break
          rt = r.body.refresh_token
          at = r.body.access_token
        }
      })()
      await new Promise((r) => setTimeout(r, trial * 3))
      const rev = await SELF.fetch(`${BASE}/api/grants/revoke`, { method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(t.cookies) }, body: JSON.stringify({ client_id: t.clientId }) })
      expect(rev.status).toBe(200)
      stop = true
      await loop
      // Whatever the last rotation wrote is dead.
      const after = await token({ grant_type: 'refresh_token', refresh_token: rt, client_id: t.clientId })
      if (after.status === 200 || (await introspect(at)).active) survivors++
    }
    expect(survivors).toBe(0)
  })

  it('B1: an opaque token at id.org.ai/mcp and userinfo stops working when its grant is revoked', async () => {
    const client = await register({ client_name: 'mcp revoke', redirect_uris: [REDIRECT], token_endpoint_auth_method: 'none' })
    const { verifier, challenge } = await pkce()
    const cookies = await signIn()
    const back = await consent(authorizeUrl(client.client_id, REDIRECT, challenge, { resource: `${BASE}/mcp` }), cookies)
    const t = await token({ grant_type: 'authorization_code', code: back.searchParams.get('code')!, redirect_uri: REDIRECT, client_id: client.client_id, code_verifier: verifier })
    expect((await SELF.fetch(`${BASE}/mcp`, { headers: { authorization: `Bearer ${t.body.access_token}` } })).status).not.toBe(401)
    expect((await SELF.fetch(`${BASE}/oauth/userinfo`, { headers: { authorization: `Bearer ${t.body.access_token}` } })).status).toBe(200)
    await SELF.fetch(`${BASE}/api/grants/revoke`, { method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(cookies) }, body: JSON.stringify({ client_id: client.client_id }) })
    expect((await SELF.fetch(`${BASE}/mcp`, { headers: { authorization: `Bearer ${t.body.access_token}` } })).status).toBe(401)
    expect((await SELF.fetch(`${BASE}/oauth/userinfo`, { headers: { authorization: `Bearer ${t.body.access_token}` } })).status).toBe(401)
  })
})
