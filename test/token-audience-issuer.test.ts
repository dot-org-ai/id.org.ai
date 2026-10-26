/**
 * Security review 2026-10, H2 + M1, through the real worker (SELF, real
 * IdentityDO + KV; WorkOS faked).
 *
 * H2: an id_token is issued with `aud` = the OAuth client and signed with the
 * same key as the sign-in session JWT. Registration is open, so any
 * third-party client a Person signs into holds one. It used to verify as that
 * Person at AuthService (verifyToken / authenticate / getUser), AuthIdentity,
 * POST /auth/verify, /me and the `auth` worker. Now only the sign-in session
 * (no `aud`) is a Person credential; an audience-bound token verifies only for
 * a caller that names that audience; the `auth` worker pins the issuer.
 *
 * M1: an unauthenticated `X-Issuer` header used to set the `iss` of signed
 * tokens, the RFC 9207 `iss` parameter and the discovery documents, and to
 * waive the consent CSRF check. Now the issuer is pinned to
 * https://id.org.ai and the header has no effect anywhere.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { SELF, fetchMock, env, createExecutionContext } from 'cloudflare:test'
import * as jose from 'jose'
import { AuthIdentity } from '../worker/index'
import { getSigningKeyManager } from '../worker/middleware/tenant'
import authWorker from '../workers/auth/index'
import { authService } from './helpers/auth-service'
import type { Env } from '../worker/types'

const BASE = 'https://id.org.ai'
const WORKOS = 'https://api.workos.com'
const EVIL = 'https://evil.example'
const REDIRECT = 'https://third-party.example/oauth/callback'

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
  for (const m of html.matchAll(/<input type="hidden" name="([^"]+)" value="([^"]*)"\s*\/?>/g)) {
    f[m[1]!] = m[2]!.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&')
  }
  return f
}
async function register(meta: Record<string, unknown>): Promise<{ client_id: string }> {
  const res = await SELF.fetch(`${BASE}/oauth/register`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(meta) })
  expect(res.status).toBe(201)
  return (await res.json()) as { client_id: string }
}

let seq = 0
async function signIn(): Promise<Record<string, string>> {
  const userId = `user_01H2M1${++seq}`
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

function authorizeUrl(clientId: string, challenge: string, extra: Record<string, string> = {}): string {
  const u = new URL(`${BASE}/oauth/authorize`)
  for (const [k, v] of Object.entries({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: REDIRECT,
    scope: 'openid profile email',
    state: 'st-1',
    nonce: 'n-1',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    ...extra,
  }))
    u.searchParams.set(k, v)
  return u.toString()
}

/** GET the consent page and POST approval with its CSRF cookie; `headers` ride on both. */
async function consent(url: string, cookies: Record<string, string>, headers: Record<string, string> = {}): Promise<URL> {
  const page = await SELF.fetch(url, { redirect: 'manual', headers: { cookie: cookieHeader(cookies), ...headers } })
  expect(page.status).toBe(200)
  const csrf = setCookies(page).__csrf
  expect(csrf).toBeTruthy()
  const res = await SELF.fetch(`${BASE}/oauth/authorize`, {
    method: 'POST',
    redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: cookieHeader({ ...cookies, __csrf: csrf! }), ...headers },
    body: new URLSearchParams({ ...consentFields(await page.text()), approved: 'true' }).toString(),
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
  expect(res.status).toBe(200)
  return (await res.json()) as Record<string, string>
}

/** A Person signs into a third-party DCR client with openid: what that client holds. */
async function thirdPartyTokens(headers: Record<string, string> = {}, extra: Record<string, string> = {}) {
  const client = await register({ client_name: 'Some third-party app', redirect_uris: [REDIRECT], token_endpoint_auth_method: 'none' })
  const { verifier, challenge } = await pkce()
  const cookies = await signIn()
  const back = await consent(authorizeUrl(client.client_id, challenge, extra), cookies, headers)
  const tokens = await token({ grant_type: 'authorization_code', code: back.searchParams.get('code')!, redirect_uri: REDIRECT, client_id: client.client_id, code_verifier: verifier }, headers)
  expect(tokens.id_token).toBeTruthy()
  return { clientId: client.client_id, cookies, back, tokens }
}

const claimsOf = (jwt: string) => jose.decodeJwt(jwt)
const identity = () => new AuthIdentity(createExecutionContext(), env as never)
const verifyHttp = (body: Record<string, unknown>) =>
  SELF.fetch(`${BASE}/auth/verify`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })

beforeAll(() => {
  fetchMock.activate()
  fetchMock.disableNetConnect()
  fetchMock.get(WORKOS).intercept({ path: /^\/user_management\/users\// }).reply(500, '').persist()
  fetchMock.get(WORKOS).intercept({ path: /^\/organizations\// }).reply(500, '').persist()
})
afterAll(() => fetchMock.deactivate())

// ── M1 ───────────────────────────────────────────────────────────────────────

describe('M1: an X-Issuer header has no effect', () => {
  for (const path of ['/.well-known/openid-configuration', '/.well-known/oauth-authorization-server']) {
    it(`${path} names id.org.ai`, async () => {
      const res = await SELF.fetch(`${BASE}${path}`, { headers: { 'X-Issuer': EVIL } })
      const text = await res.text()
      expect(text).not.toContain('evil.example')
      const d = JSON.parse(text) as Record<string, string>
      expect(d.issuer).toBe(BASE)
      expect(d.token_endpoint).toBe(`${BASE}/oauth/token`)
      expect(d.authorization_endpoint).toBe(`${BASE}/oauth/authorize`)
    })
  }

  it('/.well-known/oauth-protected-resource names id.org.ai as the authorization server', async () => {
    for (const path of ['/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp']) {
      const d = (await (await SELF.fetch(`${BASE}${path}`, { headers: { 'X-Issuer': EVIL } })).json()) as { authorization_servers: string[] }
      expect(d.authorization_servers).toEqual([BASE])
    }
  })

  it('the code redirect, the id_token and a refreshed id_token all carry iss https://id.org.ai', async () => {
    const x = { 'X-Issuer': EVIL }
    const { clientId, back, tokens } = await thirdPartyTokens(x)
    expect(back.searchParams.get('iss')).toBe(BASE)
    expect(claimsOf(tokens.id_token!).iss).toBe(BASE)
    const refreshed = await token({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token!, client_id: clientId }, x)
    expect(claimsOf(refreshed.id_token!).iss).toBe(BASE)
  })

  it('an RFC 9068 access token carries iss https://id.org.ai', async () => {
    const { tokens } = await thirdPartyTokens({ 'X-Issuer': EVIL }, { scope: 'openid sb:read', resource: 'https://api.sb/mcp' })
    expect(jose.decodeProtectedHeader(tokens.access_token!).typ).toBe('at+jwt')
    expect(claimsOf(tokens.access_token!).iss).toBe(BASE)
  })

  it('a denial redirect carries iss https://id.org.ai', async () => {
    const client = await register({ client_name: 'Deny me', redirect_uris: [REDIRECT], token_endpoint_auth_method: 'none' })
    const { challenge } = await pkce()
    const cookies = await signIn()
    const page = await SELF.fetch(authorizeUrl(client.client_id, challenge), { redirect: 'manual', headers: { cookie: cookieHeader(cookies), 'X-Issuer': EVIL } })
    const res = await SELF.fetch(`${BASE}/oauth/authorize`, {
      method: 'POST',
      redirect: 'manual',
      headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: cookieHeader({ ...cookies, __csrf: setCookies(page).__csrf! }), 'X-Issuer': EVIL },
      body: new URLSearchParams({ ...consentFields(await page.text()), approved: 'false' }).toString(),
    })
    expect(new URL(res.headers.get('location')!).searchParams.get('iss')).toBe(BASE)
  })

  it('does not waive the consent CSRF check: the GET is CSRF-bound and a POST without the pair is refused', async () => {
    const client = await register({ client_name: 'Header proxy', redirect_uris: [REDIRECT], token_endpoint_auth_method: 'none' })
    const { challenge } = await pkce()
    const cookies = await signIn()
    const page = await SELF.fetch(authorizeUrl(client.client_id, challenge), { redirect: 'manual', headers: { cookie: cookieHeader(cookies), 'X-Issuer': BASE } })
    expect(page.status).toBe(200)
    expect(setCookies(page).__csrf).toBeTruthy()
    const res = await SELF.fetch(`${BASE}/oauth/authorize`, {
      method: 'POST',
      redirect: 'manual',
      headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: cookieHeader(cookies), 'X-Issuer': BASE },
      body: new URLSearchParams({ client_id: client.client_id, redirect_uri: REDIRECT, scope: 'openid profile email', state: 'st-1', code_challenge: challenge, code_challenge_method: 'S256', approved: 'true' }).toString(),
    })
    expect(res.status).toBe(403)
    expect(res.headers.get('location')).toBeNull()
    expect(await res.text()).toContain('CSRF')
  })
})

// ── H2 ───────────────────────────────────────────────────────────────────────

describe('H2: an id_token issued to a third-party client is not a Person credential', () => {
  it('AuthService refuses it: verifyToken, getUser, authenticate (bearer and cookie)', async () => {
    const { tokens } = await thirdPartyTokens()
    const idToken = tokens.id_token!
    const svc = authService()
    expect((await svc.verifyToken(idToken)).valid).toBe(false)
    expect(await svc.getUser(idToken)).toBeNull()
    expect((await svc.authenticate(`Bearer ${idToken}`)).ok).toBe(false)
    expect((await svc.authenticate(null, `auth=${idToken}`)).ok).toBe(false)
  })

  it('AuthIdentity refuses it, unless the caller names its own client as the audience', async () => {
    const { clientId, tokens } = await thirdPartyTokens()
    const idToken = tokens.id_token!
    expect((await identity().verifyToken(idToken)).valid).toBe(false)
    expect((await identity().verifyToken(idToken, { audience: 'some_other_client' })).valid).toBe(false)
    // The relying party it was issued to verifies it at its callback.
    const own = await identity().verifyToken(idToken, { audience: clientId })
    expect(own.valid).toBe(true)
    if (own.valid) expect(own.identity.audience).toBe(clientId)
  })

  it('POST /auth/verify refuses it, unless the body names its audience', async () => {
    const { clientId, tokens } = await thirdPartyTokens()
    const idToken = tokens.id_token!
    const res = await verifyHttp({ token: idToken })
    expect(res.status).toBe(401)
    expect(((await res.json()) as { valid: boolean }).valid).toBe(false)
    expect((await verifyHttp({ token: idToken, audience: 'some_other_client' })).status).toBe(401)
    expect((await verifyHttp({ token: idToken, audience: clientId })).status).toBe(200)
    expect((await verifyHttp({ token: idToken, audience: 42 })).status).toBe(400)
  })

  it('/me and /api/me refuse it as a bearer and as the auth cookie', async () => {
    const { tokens } = await thirdPartyTokens()
    const idToken = tokens.id_token!
    expect((await SELF.fetch(`${BASE}/me`, { headers: { authorization: `Bearer ${idToken}` } })).status).toBe(401)
    expect((await SELF.fetch(`${BASE}/me`, { headers: { cookie: `auth=${idToken}` } })).status).toBe(401)
    expect(await (await SELF.fetch(`${BASE}/api/me`, { headers: { cookie: `auth=${idToken}` } })).json()).toEqual({ authenticated: false })
  })

  it('a JWT on the id.org.ai key under any other issuer is refused', async () => {
    const forged = await getSigningKeyManager(env as unknown as Env).sign({ sub: 'user_01VICTIM', email: 'victim@example.com' }, { issuer: EVIL, expiresIn: 600 })
    expect((await authService().verifyToken(forged)).valid).toBe(false)
    expect((await identity().verifyToken(forged)).valid).toBe(false)
    expect((await verifyHttp({ token: forged })).status).toBe(401)
  })

  it("the Person's own sign-in session still verifies everywhere", async () => {
    const cookies = await signIn()
    const session = cookies.auth!
    expect((await authService().verifyToken(session)).valid).toBe(true)
    expect((await authService().authenticate(null, `auth=${session}`)).ok).toBe(true)
    expect((await identity().verifyToken(session)).valid).toBe(true)
    expect((await verifyHttp({ token: session })).status).toBe(200)
    expect((await SELF.fetch(`${BASE}/me`, { headers: { authorization: `Bearer ${session}` } })).status).toBe(200)
    expect(((await (await SELF.fetch(`${BASE}/api/me`, { headers: { cookie: `auth=${session}` } })).json()) as { authenticated: boolean }).authenticated).toBe(true)
  })
})

describe('H2: the legacy oauth.do issuer path admits only a session', () => {
  // oauth.do, id.org.ai and auth.headless.ly publish the same key set, so a
  // JWT on the id.org.ai key with `iss` https://oauth.do verifies against
  // oauth.do's JWKS. Before M1, `X-Issuer: https://oauth.do` minted id_tokens
  // with exactly that issuer.
  const LEGACY = 'https://oauth.do'
  const sign = (claims: Record<string, unknown>, audience?: string) =>
    getSigningKeyManager(env as unknown as Env).sign({ sub: 'human:user_01VICTIM', email: 'victim@example.com', ...claims }, { issuer: LEGACY, audience, expiresIn: 600 })

  beforeAll(async () => {
    const published = await (await SELF.fetch(`${BASE}/.well-known/jwks.json`)).text()
    fetchMock.get(LEGACY).intercept({ path: '/.well-known/jwks.json' }).reply(200, published, { headers: { 'content-type': 'application/json' } }).persist()
  })

  it('an audience-bound token with iss https://oauth.do is refused by verifyToken, getUser and authenticate', async () => {
    const idToken = await sign({}, 'cid_attacker')
    const svc = authService()
    expect((await svc.verifyToken(idToken)).valid).toBe(false)
    expect(await svc.getUser(idToken)).toBeNull()
    expect((await svc.authenticate(`Bearer ${idToken}`)).ok).toBe(false)
    expect((await svc.authenticate(null, `auth=${idToken}`)).ok).toBe(false)
  })

  it('a legacy oauth.do session (no aud) still verifies', async () => {
    const session = await sign({ sub: 'user_01LEGACY', email: 'legacy@example.com' })
    const r = await authService().verifyToken(session)
    expect(r.valid).toBe(true)
    if (r.valid) expect(r.user.id).toBe('user_01LEGACY')
  })
})

describe('H2: the auth worker pins the issuer and refuses id_tokens', () => {
  const AUTH_ENV = { WORKOS_CLIENT_ID: 'client_h2m1' }
  const verify = async (t: string) =>
    (await (await authWorker.request('/verify', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ token: t }) }, AUTH_ENV)).json()) as { valid: boolean; user?: { id: string } }

  beforeAll(async () => {
    // The auth worker reads id.org.ai's published JWKS (served at auth.headless.ly) and WorkOS's.
    const published = await (await SELF.fetch(`${BASE}/.well-known/jwks.json`)).text()
    fetchMock.get('https://auth.headless.ly').intercept({ path: '/.well-known/jwks.json' }).reply(200, published, { headers: { 'content-type': 'application/json' } }).persist()
    fetchMock.get(WORKOS).intercept({ path: '/sso/jwks/client_h2m1' }).reply(200, JSON.stringify({ keys: [] }), { headers: { 'content-type': 'application/json' } }).persist()
  })

  it('a sign-in session verifies', async () => {
    const cookies = await signIn()
    const r = await verify(cookies.auth!)
    expect(r.valid).toBe(true)
    expect(r.user?.id).toBe(claimsOf(cookies.auth!).sub)
  })

  it('a third-party id_token is refused', async () => {
    const { tokens } = await thirdPartyTokens()
    expect((await verify(tokens.id_token!)).valid).toBe(false)
  })

  it('a JWT on the id.org.ai key under any other issuer is refused', async () => {
    const forged = await getSigningKeyManager(env as unknown as Env).sign({ sub: 'user_01VICTIM' }, { issuer: EVIL, expiresIn: 600 })
    expect((await verify(forged)).valid).toBe(false)
  })
})
