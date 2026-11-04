/**
 * H4 (security review 2026-10): the 30-day session JWT in the `auth` cookie
 * could not be revoked, carried `platformRole: superadmin` for its whole life,
 * and was scoped to whole parent domains.
 *
 * Now every session JWT carries a `sid` and `aud`, backed by a session record
 * in the Person's IdentityDO. Logout and freeze revoke the record, every
 * verification checks it, and privileged roles are re-read from WorkOS at
 * verification instead of trusted from the token. Sessions minted before the
 * change (no `sid`) are accepted until they expire, but logout and freeze
 * revoke them too and their privileged claims are re-read the same way.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { SELF, fetchMock, env } from 'cloudflare:test'
import type { Env } from '../worker/types'
import { getStubForIdentity, getSigningKeyManager, resolveIdentityId } from '../worker/middleware/tenant'
import { getRootDomain } from '../worker/utils/cookies'
import { SESSION_AUDIENCE } from '../worker/utils/session'
import { authService } from './helpers/auth-service'

const BASE = 'https://id.org.ai'
const WORKOS = 'https://api.workos.com'
const PLATFORM_ORG = (env as unknown as Env).PLATFORM_ORG_ID!

function decodeJwt(jwt: string): Record<string, any> {
  const part = jwt.split('.')[1]!.replace(/-/g, '+').replace(/_/g, '/')
  return JSON.parse(atob(part + '='.repeat((4 - (part.length % 4)) % 4)))
}

function setCookieLines(res: Response): string[] {
  return res.headers.getSetCookie()
}

function authCookie(res: Response): string {
  for (const line of setCookieLines(res)) {
    const [pair] = line.split(';')
    if (pair!.startsWith('auth=') && pair!.length > 'auth='.length) return pair!.slice('auth='.length)
  }
  throw new Error('no auth cookie')
}

let seq = 0
function mockWorkOSAuthenticate(orgId: string): string {
  const id = `user_01H4SESSION${++seq}`
  fetchMock
    .get(WORKOS)
    .intercept({ method: 'POST', path: '/user_management/authenticate' })
    .reply(
      200,
      JSON.stringify({
        access_token: 'at_opaque_workos',
        user: { id, email: `${id.toLowerCase()}@example.com`, first_name: 'Ada', last_name: 'Lovelace' },
        organization_id: orgId,
        authentication_method: 'GitHubOAuth',
      }),
      { headers: { 'content-type': 'application/json' } },
    )
  return id
}

function mockMemberships(userId: string, rows: Array<{ org: string; role: string; status?: string }>) {
  fetchMock
    .get(WORKOS)
    .intercept({ method: 'GET', path: '/user_management/organization_memberships', query: { user_id: userId, limit: '100' } })
    .reply(
      200,
      JSON.stringify({
        data: rows.map((r, i) => ({
          id: `om_${i}`,
          user_id: userId,
          organization_id: r.org,
          role: { slug: r.role },
          status: r.status ?? 'active',
          created_at: 't',
          updated_at: 't',
        })),
      }),
      { headers: { 'content-type': 'application/json' } },
    )
}

/** Sign in through /login → WorkOS → /api/callback on id.org.ai; return the session cookie JWT. */
async function signIn(orgId = 'org_01H4TENANT'): Promise<{ userId: string; jwt: string }> {
  const login = await SELF.fetch(`${BASE}/login?provider=GitHubOAuth`, { redirect: 'manual' })
  expect(login.status).toBe(302)
  const state = new URL(login.headers.get('location')!).searchParams.get('state')!
  const userId = mockWorkOSAuthenticate(orgId)
  const cb = await SELF.fetch(`${BASE}/api/callback?code=wos_code&state=${encodeURIComponent(state)}`, { redirect: 'manual' })
  expect(cb.status).toBe(302)
  return { userId, jwt: authCookie(cb) }
}

/** A session JWT as /api/callback signed it before H4: no sid, no aud. */
async function legacySession(claims: Record<string, unknown>): Promise<string> {
  await (await SELF.fetch(`${BASE}/.well-known/jwks.json`)).arrayBuffer()
  return getSigningKeyManager(env as never).sign(claims as never, { issuer: 'https://id.org.ai', expiresIn: 3600 })
}

async function verify(jwt: string): Promise<boolean> {
  return (await authService().verifyToken(jwt)).valid
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

describe('a sign-in mints a revocable session', () => {
  it('the session JWT carries a sid and the session audience', async () => {
    const { jwt } = await signIn()
    const claims = decodeJwt(jwt)
    expect(typeof claims.sid).toBe('string')
    expect(claims.sid.length).toBeGreaterThan(16)
    expect(claims.aud).toBe(SESSION_AUDIENCE)
    expect(await verify(jwt)).toBe(true)
  })

  it('every sign-in gets its own sid', async () => {
    const a = decodeJwt((await signIn()).jwt)
    const b = decodeJwt((await signIn()).jwt)
    expect(a.sid).not.toBe(b.sid)
  })

  it('a signed JWT with the session audience but no record is refused', async () => {
    const forged = await legacySession({ sub: 'user_01H4NORECORD', aud: SESSION_AUDIENCE, sid: 'bs_never_minted' })
    expect(await verify(forged)).toBe(false)
  })
})

describe('logout revokes the session, not just the cookie', () => {
  for (const [label, path, method] of [
    ['GET /logout', '/logout', 'GET'],
    ['POST /logout', '/logout', 'POST'],
    ['POST /api/logout', '/api/logout', 'POST'],
  ] as const) {
    it(`${label}: the same JWT is refused everywhere afterwards`, async () => {
      const { jwt } = await signIn()
      expect(await verify(jwt)).toBe(true)

      const out = await SELF.fetch(`${BASE}${path}`, { method, headers: { cookie: `auth=${jwt}` }, redirect: 'manual' })
      expect([200, 302]).toContain(out.status)

      expect(await verify(jwt)).toBe(false)
      const wire = await SELF.fetch(`${BASE}/auth/verify`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ token: jwt }) })
      expect(wire.status).toBe(401)
      const session = await SELF.fetch(`${BASE}/api/session`, { headers: { cookie: `auth=${jwt}` } })
      expect(session.status).toBe(401)
      const me = await SELF.fetch(`${BASE}/api/me`, { headers: { cookie: `auth=${jwt}` } })
      expect(((await me.json()) as { authenticated: boolean }).authenticated).toBe(false)
      expect(await resolveIdentityId(new Request(`${BASE}/x`, { headers: { cookie: `auth=${jwt}` } }), env as unknown as Env)).toBeNull()
    })
  }

  it('logging out one session leaves the other sessions of that person signed in', async () => {
    const first = await signIn()
    // A second device: same person, its own sid.
    const second = await legacySession({ sub: first.userId })
    await SELF.fetch(`${BASE}/logout`, { method: 'POST', headers: { cookie: `auth=${first.jwt}` } })
    expect(await verify(first.jwt)).toBe(false)
    expect(await verify(second)).toBe(true)
  })

  it('a session minted before sids existed is revoked by logout too', async () => {
    const jwt = await legacySession({ sub: 'user_01H4LEGACYLOGOUT', email: 'legacy@example.com' })
    expect(await verify(jwt)).toBe(true)
    await SELF.fetch(`${BASE}/api/logout`, { method: 'POST', headers: { cookie: `auth=${jwt}` } })
    expect(await verify(jwt)).toBe(false)
  })
})

describe('freezing an identity revokes its sessions', () => {
  it('every session of a frozen identity is refused, with or without a sid', async () => {
    const { userId, jwt } = await signIn()
    const legacy = await legacySession({ sub: userId })
    // Checked before the freeze without going through AuthService, whose
    // cache would hold the answer for SESSION_CACHE_TTL_SECONDS: freeze can't
    // name the tokens to evict, so that brief window is the accepted bound.
    for (const token of [jwt, legacy]) {
      expect((await SELF.fetch(`${BASE}/api/session`, { headers: { cookie: `auth=${token}` } })).status).toBe(200)
    }

    await getStubForIdentity(env as unknown as Env, `human:${userId}`).freezeIdentity(`human:${userId}`)

    expect(await verify(jwt)).toBe(false)
    expect(await verify(legacy)).toBe(false)
    for (const token of [jwt, legacy]) {
      expect((await SELF.fetch(`${BASE}/api/session`, { headers: { cookie: `auth=${token}` } })).status).toBe(401)
    }
    expect(await resolveIdentityId(new Request(`${BASE}/x`, { headers: { cookie: `auth=${jwt}` } }), env as unknown as Env)).toBeNull()
  })
})

describe('privileged roles are re-read, not trusted from the token', () => {
  it('a superadmin removed from the platform org loses platformRole on the very next check', async () => {
    const { userId, jwt } = await signIn(PLATFORM_ORG)
    expect(decodeJwt(jwt).platformRole).toBe('superadmin')

    mockMemberships(userId, [{ org: PLATFORM_ORG, role: 'admin' }])
    expect(await authService().isPlatformAdmin(jwt)).toBe(true)

    mockMemberships(userId, [{ org: 'org_01H4ELSEWHERE', role: 'member' }])
    expect(await authService().isPlatformAdmin(jwt)).toBe(false)
  })

  it('an inactive platform membership is not superadmin', async () => {
    const { userId, jwt } = await signIn(PLATFORM_ORG)
    mockMemberships(userId, [{ org: PLATFORM_ORG, role: 'admin', status: 'inactive' }])
    expect(await authService().isPlatformAdmin(jwt)).toBe(false)
  })

  it('a pre-sid session claiming superadmin is re-read the same way', async () => {
    const jwt = await legacySession({ sub: 'user_01H4LEGACYADMIN', org: { id: PLATFORM_ORG }, platformRole: 'superadmin' })
    mockMemberships('user_01H4LEGACYADMIN', [])
    expect(await authService().isPlatformAdmin(jwt)).toBe(false)
  })

  it('a tenant admin demoted to member loses the admin role', async () => {
    const { userId, jwt } = await signIn('org_01H4TENANTADMIN')
    const legacy = await legacySession({ sub: userId, org: { id: 'org_01H4TENANTADMIN' }, roles: ['admin'], permissions: ['org:admin'] })
    mockMemberships(userId, [{ org: 'org_01H4TENANTADMIN', role: 'member' }])
    const result = await authService().verifyToken(legacy)
    expect(result.valid).toBe(true)
    if (result.valid) {
      expect(result.user.roles).toEqual(['member'])
      expect(result.user.permissions).toEqual([])
    }
    expect(decodeJwt(jwt).sub).toBe(userId)
  })
})

describe('the session cookie is not shared with tenant hosts', () => {
  it('hosts on shared base zones and multi-tenant platform zones get a host-only cookie', () => {
    expect(getRootDomain('acme.svc.st')).toBeNull()
    expect(getRootDomain('svc.st')).toBeNull()
    expect(getRootDomain('api.sb')).toBeNull()
    expect(getRootDomain('acme.api.sb')).toBeNull()
    expect(getRootDomain('acme.hq.com.ai')).toBeNull()
    expect(getRootDomain('foo.workers.do')).toBeNull()
    expect(getRootDomain('dotdo.workers.dev')).toBeNull()
    // workers.dev is a public suffix: one account's scripts share its subdomain, as browsers already enforce.
    expect(getRootDomain('preview.dotdo.workers.dev')).toBe('.dotdo.workers.dev')
    // A Startup's own subdomains still share its cookie, never its neighbours'.
    expect(getRootDomain('auth.acme.svc.st')).toBe('.acme.svc.st')
  })

  it('estate apexes keep their shared cookie (auth.<apex> to apex)', () => {
    expect(getRootDomain('auth.headless.ly')).toBe('.headless.ly')
    expect(getRootDomain('auth.startups.new')).toBe('.startups.new')
    expect(getRootDomain('oauth.do')).toBe('.oauth.do')
    expect(getRootDomain('id.org.ai')).toBeNull()
    expect(getRootDomain('auth.org.ai')).toBeNull()
  })

  it('a sign-in completed on a tenant host sets a host-only cookie and clears the old parent-domain one', async () => {
    const origin = 'https://acme.svc.st'
    const login = await SELF.fetch(`${origin}/login?provider=GitHubOAuth&continue=%2Fapp`, { redirect: 'manual' })
    expect(login.status).toBe(302)
    const state = new URL(login.headers.get('location')!).searchParams.get('state')!
    mockWorkOSAuthenticate('org_01H4TENANT')
    const cb = await SELF.fetch(`${BASE}/api/callback?code=wos_code&state=${encodeURIComponent(state)}`, { redirect: 'manual' })
    const bounce = new URL(cb.headers.get('location')!)
    expect(bounce.origin).toBe(origin)
    const redeem = await SELF.fetch(`${origin}/callback?_auth_code=${bounce.searchParams.get('_auth_code')}`, { redirect: 'manual' })
    expect(redeem.status).toBe(302)
    const lines = setCookieLines(redeem)
    const set = lines.find((l) => /^auth=[^;]+;/.test(l) && !/Max-Age=0/.test(l))!
    expect(set).toBeTruthy()
    expect(set).not.toMatch(/Domain=/i)
    expect(lines.some((l) => l.startsWith('auth=;') && /Domain=\.svc\.st/.test(l) && /Max-Age=0/.test(l))).toBe(true)
  })
})
