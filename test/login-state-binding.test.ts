/**
 * /login → WorkOS → /api/callback: the destination and the cookie-bounce
 * origin are bound server-side to the CSRF record, not read from the
 * (unsigned) state; one-time `_auth_code`s and login transactions expire even
 * though DO storage ignores expirationTtl; `_auth_result` reads only keys
 * /api/org-select wrote.
 *
 * The attack this closes: an attacker calls /login once to obtain a real csrf,
 * re-encodes the state with `origin: https://evil.example`, and gets a victim
 * to complete the WorkOS sign-in with it. /api/callback then sent the victim's
 * one-time `_auth_code` to https://evil.example/callback, and the attacker
 * redeemed it at id.org.ai/callback for the victim's session cookie.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { SELF, fetchMock, env } from 'cloudflare:test'
import type { Env } from '../worker/types'
import { getStubForIdentity } from '../worker/middleware/tenant'
import { LOGIN_CSRF_MAX_AGE_MS } from '../worker/routes/auth'

const BASE = 'https://id.org.ai'
const WORKOS = 'https://api.workos.com'

function b64urlJson(value: unknown): string {
  return btoa(JSON.stringify(value)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

function decodeState(state: string): Record<string, any> {
  const padded = state.replace(/-/g, '+').replace(/_/g, '/')
  return JSON.parse(atob(padded + '='.repeat((4 - (padded.length % 4)) % 4)))
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

let seq = 0
function mockWorkOSAuthenticate(): string {
  const id = `user_01BIND${++seq}`
  fetchMock
    .get(WORKOS)
    .intercept({ method: 'POST', path: '/user_management/authenticate' })
    .reply(
      200,
      JSON.stringify({
        access_token: 'at_opaque_workos',
        refresh_token: 'rt_workos',
        user: { id, email: `${id.toLowerCase()}@example.com`, first_name: 'Ada', last_name: 'Lovelace' },
        organization_id: 'org_01TEST',
        authentication_method: 'GitHubOAuth',
      }),
      { headers: { 'content-type': 'application/json' } },
    )
  return id
}

/** Start a login on `origin` and return the state /login handed WorkOS. */
async function startLogin(origin: string, cont?: string): Promise<string> {
  const qs = new URLSearchParams({ provider: 'GitHubOAuth' })
  if (cont) qs.set('continue', cont)
  const res = await SELF.fetch(`${origin}/login?${qs}`, { redirect: 'manual' })
  expect(res.status).toBe(302)
  return new URL(res.headers.get('location')!).searchParams.get('state')!
}

function oauthStorage() {
  return getStubForIdentity(env as unknown as Env, 'oauth')
}

beforeAll(() => {
  fetchMock.activate()
  fetchMock.disableNetConnect()
  fetchMock.get(WORKOS).intercept({ path: /^\/user_management\/users\// }).reply(500, '').persist()
  fetchMock.get(WORKOS).intercept({ path: /^\/organizations\// }).reply(500, '').persist()
})

afterAll(() => {
  fetchMock.deactivate()
})

describe('a forged login state cannot redirect or steal the session', () => {
  it('rewriting origin/continue in the state changes nothing: no bounce, the bound continue is used', async () => {
    const real = decodeState(await startLogin(BASE, '/dash/keys'))
    const forged = b64urlJson({ ...real, origin: 'https://evil.example', continue: 'https://evil.example/after' })
    mockWorkOSAuthenticate()
    const cb = await SELF.fetch(`${BASE}/api/callback?code=wos_code&state=${encodeURIComponent(forged)}`, { redirect: 'manual' })
    expect(cb.status).toBe(302)
    const location = cb.headers.get('location')!
    expect(location).not.toContain('evil.example')
    expect(location).not.toContain('_auth_code')
    expect(new URL(location, BASE).pathname).toBe('/dash/keys')
    // The session cookie is set here, on id.org.ai, not handed off.
    expect(setCookies(cb).auth).toBeTruthy()
  })

  it('a legitimate service-binding origin still bounces through its /callback, once', async () => {
    const origin = 'https://internal-rp.example'
    const state = await startLogin(origin, '/app')
    expect(decodeState(state).origin).toBe(origin)
    mockWorkOSAuthenticate()
    const cb = await SELF.fetch(`${BASE}/api/callback?code=wos_code&state=${encodeURIComponent(state)}`, { redirect: 'manual' })
    expect(cb.status).toBe(302)
    const bounce = new URL(cb.headers.get('location')!)
    expect(bounce.origin).toBe(origin)
    expect(bounce.pathname).toBe('/callback')
    const code = bounce.searchParams.get('_auth_code')!
    expect(code).toBeTruthy()

    const redeem = await SELF.fetch(`${origin}/callback?_auth_code=${code}`, { redirect: 'manual' })
    expect(redeem.status).toBe(302)
    expect(redeem.headers.get('location')).toBe('/app')
    expect(setCookies(redeem).auth).toBeTruthy()

    const again = await SELF.fetch(`${origin}/callback?_auth_code=${code}`, { redirect: 'manual' })
    expect(again.status).toBe(400)
  })
})

describe('expiry is enforced on read (DO storage ignores expirationTtl)', () => {
  it('an _auth_code past its minute, or without expiresAt, is refused', async () => {
    const stub = oauthStorage()
    const legacy = crypto.randomUUID()
    const old = crypto.randomUUID()
    await stub.oauthStorageOp({ op: 'put', key: `auth-code:${legacy}`, value: { jwt: 'x.y.z', continueUrl: '/' } })
    await stub.oauthStorageOp({ op: 'put', key: `auth-code:${old}`, value: { jwt: 'x.y.z', continueUrl: '/', expiresAt: Date.now() - 1 } })
    for (const code of [legacy, old]) {
      const res = await SELF.fetch(`${BASE}/callback?_auth_code=${code}`, { redirect: 'manual' })
      expect(res.status, code).toBe(400)
      expect(res.headers.getSetCookie().some((c) => c.startsWith('auth=x.y.z'))).toBe(false)
    }
  })

  it('a login transaction older than LOGIN_CSRF_MAX_AGE_MS is refused', async () => {
    const csrf = crypto.randomUUID()
    await oauthStorage().oauthStorageOp({
      op: 'put',
      key: `login-csrf:${csrf}`,
      value: { csrf, createdAt: Date.now() - LOGIN_CSRF_MAX_AGE_MS - 1000, continue: '/', origin: BASE },
    })
    const state = b64urlJson({ csrf, continue: '/', origin: BASE })
    const res = await SELF.fetch(`${BASE}/api/callback?code=wos_code&state=${encodeURIComponent(state)}`, { redirect: 'manual' })
    expect(res.status).toBe(403)
  })

  it('a pre-binding record (csrf only) gets no bounce and a policy-checked continue', async () => {
    const csrf = crypto.randomUUID()
    await oauthStorage().oauthStorageOp({ op: 'put', key: `login-csrf:${csrf}`, value: { csrf, createdAt: Date.now() } })
    const state = b64urlJson({ csrf, continue: 'https://evil.example/x', origin: 'https://evil.example' })
    mockWorkOSAuthenticate()
    const res = await SELF.fetch(`${BASE}/api/callback?code=wos_code&state=${encodeURIComponent(state)}`, { redirect: 'manual' })
    expect(res.status).toBe(302)
    expect(res.headers.get('location')).not.toContain('evil.example')
  })
})

describe('_auth_result reads only org-select keys', () => {
  it('an arbitrary storage key is refused before it is read', async () => {
    const state = await startLogin(BASE)
    for (const key of ['client:anything', 'login-csrf:x', 'auth-result:not-a-uuid']) {
      const res = await SELF.fetch(`${BASE}/api/callback?_auth_result=${encodeURIComponent(key)}&state=${encodeURIComponent(state)}`, { redirect: 'manual' })
      expect(res.status, key).toBe(400)
    }
  })
})

describe('R4-2: an _auth_code only ever travels to an https origin', () => {
  it('a login started over plain http gets no _auth_code bounce, and no code is minted', async () => {
    const origin = 'http://internal-rp.example'
    const state = await startLogin(origin, '/app')
    mockWorkOSAuthenticate()
    const before = await oauthStorage().oauthStorageOp({ op: 'list', options: { prefix: 'auth-code:' } })
    const cb = await SELF.fetch(`${BASE}/api/callback?code=wos_code&state=${encodeURIComponent(state)}`, { redirect: 'manual' })
    const location = cb.headers.get('location') ?? ''
    expect(location).not.toContain('_auth_code')
    expect(location.startsWith('http:')).toBe(false)
    expect(cb.status).toBe(400)
    const after = await oauthStorage().oauthStorageOp({ op: 'list', options: { prefix: 'auth-code:' } })
    expect((after.entries as unknown[]).length).toBe((before.entries as unknown[]).length)
  })

  it('the same login started over https still bounces', async () => {
    const state = await startLogin('https://internal-rp.example', '/app')
    mockWorkOSAuthenticate()
    const cb = await SELF.fetch(`${BASE}/api/callback?code=wos_code&state=${encodeURIComponent(state)}`, { redirect: 'manual' })
    expect(cb.status).toBe(302)
    const bounce = new URL(cb.headers.get('location')!)
    expect(bounce.protocol).toBe('https:')
    expect(bounce.searchParams.get('_auth_code')).toBeTruthy()
  })
})

describe('R4-3: an _auth_code redeems exactly once, however many redemptions race', () => {
  it('20 parallel redemptions of one code: exactly one session', async () => {
    const origin = 'https://race-rp.example'
    const state = await startLogin(origin, '/app')
    mockWorkOSAuthenticate()
    const cb = await SELF.fetch(`${BASE}/api/callback?code=wos_code&state=${encodeURIComponent(state)}`, { redirect: 'manual' })
    const code = new URL(cb.headers.get('location')!).searchParams.get('_auth_code')!
    expect(code).toBeTruthy()

    const results = await Promise.all(
      Array.from({ length: 20 }, () => SELF.fetch(`${origin}/callback?_auth_code=${code}`, { redirect: 'manual' })),
    )
    const sessions = results.filter((r) => r.status === 302 && !!setCookies(r).auth)
    expect(sessions.length).toBe(1)
    expect(results.filter((r) => r.status === 400).length).toBe(19)
  })

  it('a code that is not a minted code shape is refused without touching storage', async () => {
    const stub = oauthStorage()
    await stub.oauthStorageOp({ op: 'put', key: 'auth-code:not-a-uuid', value: { jwt: 'x.y.z', continueUrl: '/', expiresAt: Date.now() + 60_000 } })
    const res = await SELF.fetch(`${BASE}/callback?_auth_code=not-a-uuid`, { redirect: 'manual' })
    expect(res.status).toBe(400)
    expect(res.headers.getSetCookie().some((c) => c.startsWith('auth=x.y.z'))).toBe(false)
  })
})

describe('R4-3: a state whose csrf is not a string is an invalid state, not a server error', () => {
  it.each([
    ['a number', 123],
    ['an object', { a: 1 }],
    ['an array', ['x']],
    ['null', null],
  ])('csrf as %s -> 400', async (_label, csrf) => {
    const state = b64urlJson({ csrf, continue: '/', origin: BASE })
    mockWorkOSAuthenticate()
    const res = await SELF.fetch(`${BASE}/api/callback?code=wos_code&state=${encodeURIComponent(state)}`, { redirect: 'manual' })
    expect(res.status).toBe(400)
  })

  it('an array csrf cannot stand in for a real one', async () => {
    const real = decodeState(await startLogin(BASE, '/dash/keys'))
    const state = b64urlJson({ ...real, csrf: [real.csrf] })
    mockWorkOSAuthenticate()
    const res = await SELF.fetch(`${BASE}/api/callback?code=wos_code&state=${encodeURIComponent(state)}`, { redirect: 'manual' })
    expect(res.status).toBe(400)
    expect(setCookies(res).auth).toBeFalsy()
  })

  it('a pre-binding record with a non-string continue in the state is not a 500', async () => {
    const csrf = crypto.randomUUID()
    await oauthStorage().oauthStorageOp({ op: 'put', key: `login-csrf:${csrf}`, value: { csrf, createdAt: Date.now() } })
    const state = b64urlJson({ csrf, continue: { toString: 1 }, origin: 7 })
    mockWorkOSAuthenticate()
    const res = await SELF.fetch(`${BASE}/api/callback?code=wos_code&state=${encodeURIComponent(state)}`, { redirect: 'manual' })
    expect(res.status).toBeLessThan(500)
  })
})
