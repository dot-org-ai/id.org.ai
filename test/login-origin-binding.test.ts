/**
 * Login ceremony: origin binding, browser binding, redirect and issuer hardening.
 *
 * The origin of a login flow is whatever host served /login, as this worker saw
 * it (the tenant host when a front Worker forwards over its service binding,
 * id.org.ai on a direct hit). It is recorded server-side and every later leg is
 * held to it. No domain list is involved anywhere, so the tenant hosts below are
 * arbitrary.
 *
 * Replays the ceremony in-process via SELF (real IDENTITY DO); only the WorkOS
 * upstream is mocked. No network.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { SELF, fetchMock } from 'cloudflare:test'
import * as jose from 'jose'
import { sameOriginRedirect, isSafeRedirectUrl } from '../src/sdk/csrf'
import { resolveEffectiveIssuer } from '../src/sdk/oauth/provider'

const ID = 'https://id.org.ai'
const TENANT = 'https://portal.tenant-example.com'
const ATTACKER = 'https://attacker.example'
const USER_ID = 'user_01TESTLOGINORIGIN'

beforeAll(() => {
  fetchMock.activate()
  fetchMock.disableNetConnect()
  fetchMock
    .get('https://api.workos.com')
    .intercept({ method: 'POST', path: '/user_management/authenticate' })
    .reply(
      200,
      JSON.stringify({
        access_token: 'at_opaque_test_access_token',
        refresh_token: 'rt_test_refresh_token',
        user: { id: USER_ID, email: 'origin@example.com', first_name: 'Origin', last_name: 'Test' },
        organization_id: 'org_01TESTORG',
      }),
      { headers: { 'content-type': 'application/json' } },
    )
    .persist()
  fetchMock.get('https://api.workos.com').intercept({ path: /^\/user_management\/users\// }).reply(500, '').persist()
  fetchMock.get('https://api.workos.com').intercept({ path: /^\/organizations\// }).reply(500, '').persist()
})

afterAll(() => {
  fetchMock.deactivate()
})

// ── helpers ────────────────────────────────────────────────────────────────

function b64urlDecode(s: string): Record<string, unknown> {
  const padded = s.replace(/-/g, '+').replace(/_/g, '/') + '=='.slice(0, (4 - (s.length % 4)) % 4)
  return JSON.parse(atob(padded))
}
function b64urlEncode(obj: unknown): string {
  return btoa(JSON.stringify(obj)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

function setCookies(res: Response): string[] {
  return res.headers.getSetCookie()
}

function cookieValue(res: Response, name: string): string | null {
  for (const sc of setCookies(res)) {
    const [pair] = sc.split(';')
    const eq = pair.indexOf('=')
    if (pair.slice(0, eq).trim() === name) return pair.slice(eq + 1)
  }
  return null
}

/** Start a login on `origin`; return the WorkOS state and the nonce cookie set on that host. */
async function startLogin(origin: string, cont = '/app') {
  const res = await SELF.fetch(`${origin}/login?provider=GitHubOAuth&continue=${encodeURIComponent(cont)}`, { redirect: 'manual' })
  expect(res.status).toBe(302)
  const authUrl = new URL(res.headers.get('location')!)
  expect(authUrl.hostname).toBe('api.workos.com')
  const state = authUrl.searchParams.get('state')!
  const nonce = cookieValue(res, '__Host-auth_nonce')
  return { res, state, nonce, authUrl }
}

/** WorkOS returns the browser to the one registered callback on id.org.ai. */
function apiCallback(state: string, cookie?: string) {
  return SELF.fetch(`${ID}/api/callback?code=wos_code&state=${encodeURIComponent(state)}`, {
    redirect: 'manual',
    headers: cookie ? { cookie } : {},
  })
}

async function jwksSet() {
  const jwks = await (await SELF.fetch(`${ID}/.well-known/jwks.json`)).json()
  return jose.createLocalJWKSet(jwks as jose.JSONWebKeySet)
}

// ── regression: the forged-state session theft no longer works ─────────────

describe('regression: forged state origin cannot divert the one-time code', () => {
  it('ignores an attacker-supplied origin in state; the code never leaves id.org.ai', async () => {
    const { state, nonce } = await startLogin(ID)
    const decoded = b64urlDecode(state)
    // state is opaque: it carries only the csrf key, never the origin or continue URL
    expect(decoded.origin).toBeUndefined()
    expect(decoded.continue).toBeUndefined()

    const forged = b64urlEncode({ csrf: decoded.csrf, continue: '/app', origin: ATTACKER })
    const cb = await apiCallback(forged, `__Host-auth_nonce=${nonce}`)
    expect(cb.status).toBe(302)
    const location = cb.headers.get('location')!
    // No bounce to the attacker, no one-time code in any URL
    expect(location).not.toContain('attacker.example')
    expect(location).not.toContain('_auth_code')
    expect(location).toBe('/app')
    // The session is set on id.org.ai itself, for id.org.ai
    const jwt = cookieValue(cb, 'auth')!
    expect(jwt).toBeTruthy()
    const { payload } = await jose.jwtVerify(jwt, await jwksSet(), { issuer: ID, audience: ID })
    expect(payload.sub).toBe(USER_ID)
  })

  it('a code issued for a tenant cannot be redeemed on the public id.org.ai /callback (403)', async () => {
    const { state, nonce } = await startLogin(TENANT)
    const cb = await apiCallback(state)
    expect(cb.status).toBe(302)
    const bounce = new URL(cb.headers.get('location')!)
    expect(bounce.origin).toBe(TENANT)
    const code = bounce.searchParams.get('_auth_code')!

    const redeem = await SELF.fetch(`${ID}/callback?_auth_code=${code}`, {
      redirect: 'manual',
      headers: { cookie: `__Host-auth_nonce=${nonce}` },
    })
    expect(redeem.status).toBe(403)
    expect(cookieValue(redeem, 'auth')).toBeNull()

    // ...and the misdirected attempt burned the code
    const retry = await SELF.fetch(`${TENANT}/callback?_auth_code=${code}`, {
      redirect: 'manual',
      headers: { cookie: `__Host-auth_nonce=${nonce}` },
    })
    expect(retry.status).toBe(400)
  })

  it('rejects `/\\evil.com` and cross-origin continue targets', () => {
    expect(isSafeRedirectUrl('/\\evil.com')).toBe(false)
    expect(isSafeRedirectUrl('/\t/evil.com')).toBe(false)
    expect(sameOriginRedirect('/\\evil.com', ID)).toBe('/')
    expect(sameOriginRedirect('https://evil.example/x', ID)).toBe('/')
    expect(sameOriginRedirect('//evil.example/x', ID)).toBe('/')
    expect(sameOriginRedirect('javascript:alert(1)', ID)).toBe('/')
  })
})

// ── fix guards ─────────────────────────────────────────────────────────────

describe('tenant-host login: origin + browser binding', () => {
  it('/login sets a host-only __Host-auth_nonce cookie on the serving host', async () => {
    const { res, nonce } = await startLogin(TENANT)
    expect(nonce).toBeTruthy()
    const sc = setCookies(res).find((c) => c.startsWith('__Host-auth_nonce='))!
    expect(sc).toContain('HttpOnly')
    expect(sc).toContain('Path=/')
    expect(sc).toContain('Secure')
    expect(sc).not.toMatch(/Domain=/i)
  })

  it('redeems on the tenant host that served /login, with that browser\'s nonce; aud = tenant origin', async () => {
    const { state, nonce } = await startLogin(TENANT, `${TENANT}/dashboard`)
    const cb = await apiCallback(state)
    const bounce = new URL(cb.headers.get('location')!)
    expect(bounce.origin).toBe(TENANT)
    expect(bounce.pathname).toBe('/callback')

    const redeem = await SELF.fetch(`${TENANT}/callback?_auth_code=${bounce.searchParams.get('_auth_code')}`, {
      redirect: 'manual',
      headers: { cookie: `__Host-auth_nonce=${nonce}` },
    })
    expect(redeem.status).toBe(302)
    expect(redeem.headers.get('location')).toBe(`${TENANT}/dashboard`)
    const jwt = cookieValue(redeem, 'auth')!
    expect(jwt).toBeTruthy()
    // nonce is single-use: cleared on success
    expect(setCookies(redeem).some((c) => c.startsWith('__Host-auth_nonce=;') && /Max-Age=0/.test(c))).toBe(true)

    const jwks = await jwksSet()
    // Existing issuer-only verifiers keep working...
    const { payload } = await jose.jwtVerify(jwt, jwks, { issuer: ID })
    expect(payload.sub).toBe(USER_ID)
    expect(payload.aud).toBe(TENANT)
    // ...and an audience-checking verifier on another host rejects it.
    await expect(jose.jwtVerify(jwt, jwks, { issuer: ID, audience: ID })).rejects.toThrow()
  })

  it('refuses a tenant code presented without the login nonce cookie (login fixation)', async () => {
    const { state } = await startLogin(TENANT)
    const cb = await apiCallback(state)
    const code = new URL(cb.headers.get('location')!).searchParams.get('_auth_code')!
    const redeem = await SELF.fetch(`${TENANT}/callback?_auth_code=${code}`, { redirect: 'manual' })
    expect(redeem.status).toBe(403)
    expect(cookieValue(redeem, 'auth')).toBeNull()
  })

  it('refuses a tenant code presented with another login\'s nonce', async () => {
    const { state } = await startLogin(TENANT)
    const other = await startLogin(TENANT)
    const cb = await apiCallback(state)
    const code = new URL(cb.headers.get('location')!).searchParams.get('_auth_code')!
    const redeem = await SELF.fetch(`${TENANT}/callback?_auth_code=${code}`, {
      redirect: 'manual',
      headers: { cookie: `__Host-auth_nonce=${other.nonce}` },
    })
    expect(redeem.status).toBe(403)
  })

  it('refuses a tenant code on a different arbitrary host', async () => {
    const { state, nonce } = await startLogin(TENANT)
    const cb = await apiCallback(state)
    const code = new URL(cb.headers.get('location')!).searchParams.get('_auth_code')!
    const redeem = await SELF.fetch(`https://other-tenant.example.net/callback?_auth_code=${code}`, {
      redirect: 'manual',
      headers: { cookie: `__Host-auth_nonce=${nonce}` },
    })
    expect(redeem.status).toBe(403)
  })

  it('drops a cross-origin continue URL at /login (falls back to the default page)', async () => {
    const { state, nonce } = await startLogin(TENANT, `${ATTACKER}/phish`)
    const cb = await apiCallback(state)
    const code = new URL(cb.headers.get('location')!).searchParams.get('_auth_code')!
    const redeem = await SELF.fetch(`${TENANT}/callback?_auth_code=${code}`, {
      redirect: 'manual',
      headers: { cookie: `__Host-auth_nonce=${nonce}` },
    })
    expect(redeem.status).toBe(302)
    expect(redeem.headers.get('location')).toBe('/dash/profile')
  })
})

describe('logout return_url', () => {
  it.each([
    ['/\\evil.com', '/'],
    [`${ATTACKER}/x`, '/'],
    ['//evil.example', '/'],
    ['/goodbye', '/goodbye'],
    [`${TENANT}/bye`, `${TENANT}/bye`],
  ])('return_url=%s → %s', async (returnUrl, expected) => {
    const res = await SELF.fetch(`${TENANT}/logout?return_url=${encodeURIComponent(returnUrl)}`, { redirect: 'manual' })
    expect(res.status).toBe(302)
    expect(res.headers.get('location')).toBe(expected)
  })
})

describe('X-Issuer is not proof of anything', () => {
  it('resolveEffectiveIssuer honours X-Issuer only when it names the request\'s own origin', () => {
    const def = ID
    const direct = new Request(`${ID}/oauth/token`, { headers: { 'X-Issuer': ATTACKER } })
    expect(resolveEffectiveIssuer(direct, def)).toBe(def)
    const viaBinding = new Request(`${TENANT}/oauth/token`, { headers: { 'X-Issuer': `${TENANT}/` } })
    expect(resolveEffectiveIssuer(viaBinding, def)).toBe(TENANT)
    const mismatched = new Request(`${TENANT}/oauth/token`, { headers: { 'X-Issuer': ATTACKER } })
    expect(resolveEffectiveIssuer(mismatched, def)).toBe(def)
    expect(resolveEffectiveIssuer(new Request(`${ID}/x`), def)).toBe(def)
  })

  it('discovery on the public host ignores a foreign X-Issuer', async () => {
    const res = await SELF.fetch(`${ID}/.well-known/oauth-authorization-server`, { headers: { 'X-Issuer': ATTACKER } })
    expect(res.status).toBe(200)
    const meta = (await res.json()) as { issuer: string }
    expect(meta.issuer).toBe(ID)
  })

  it('POST /oauth/authorize with X-Issuer still requires the consent CSRF token', async () => {
    // Get a real id.org.ai session
    const { state, nonce } = await startLogin(ID)
    const cb = await apiCallback(state, `__Host-auth_nonce=${nonce}`)
    const jwt = cookieValue(cb, 'auth')!
    expect(jwt).toBeTruthy()

    const res = await SELF.fetch(`${ID}/oauth/authorize`, {
      method: 'POST',
      redirect: 'manual',
      headers: {
        cookie: `auth=${jwt}`,
        'X-Issuer': ID,
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        client_id: 'any-client',
        redirect_uri: `${ATTACKER}/cb`,
        scope: 'openid',
        state: 'xyz',
        approved: 'true',
      }).toString(),
    })
    expect(res.status).toBe(403)
    const body = (await res.json()) as { error_description?: string; message?: string; error?: unknown }
    expect(JSON.stringify(body)).toMatch(/CSRF/i)
  })
})
