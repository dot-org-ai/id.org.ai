/**
 * B13.4 (docs/product-update/spec/backend.md#b13, #b6): switching the session's
 * organization (POST /api/session/organization) kept the previous
 * organization's roles and permissions in the re-minted session. The new
 * session must carry the person's role in the organization they switched to.
 */
import { describe, it, expect, beforeAll, afterEach } from 'vitest'
import { SELF, env, fetchMock } from 'cloudflare:test'
import { getSigningKeyManager } from '../worker/middleware/tenant'

const BASE = 'https://id.org.ai'
const WORKOS = 'https://api.workos.com'

function decodeJwt(jwt: string): Record<string, any> {
  const part = jwt.split('.')[1]!.replace(/-/g, '+').replace(/_/g, '/')
  return JSON.parse(atob(part + '='.repeat((4 - (part.length % 4)) % 4)))
}

function authCookie(res: Response): string {
  for (const line of res.headers.getSetCookie()) {
    const [pair] = line.split(';')
    if (pair!.startsWith('auth=')) return pair!.slice('auth='.length)
  }
  throw new Error('no auth cookie')
}

async function sessionFor(claims: Record<string, unknown>): Promise<string> {
  // Prime the module-level signing manager through a real request first.
  await (await SELF.fetch(`${BASE}/.well-known/jwks.json`)).arrayBuffer()
  return getSigningKeyManager(env as never).sign(claims, { issuer: 'https://id.org.ai', expiresIn: 3600 })
}

function mockMemberships(userId: string, rows: Array<{ org: string; role: string }>) {
  fetchMock
    .get(WORKOS)
    .intercept({ method: 'GET', path: '/user_management/organization_memberships', query: { user_id: userId, limit: '100' } })
    .reply(
      200,
      JSON.stringify({ data: rows.map((r, i) => ({ id: `om_${i}`, user_id: userId, organization_id: r.org, role: { slug: r.role }, status: 'active', created_at: 't', updated_at: 't' })) }),
      { headers: { 'content-type': 'application/json' } },
    )
  fetchMock
    .get(WORKOS)
    .intercept({ method: 'GET', path: '/organizations/org_B' })
    .reply(200, JSON.stringify({ id: 'org_B', name: 'Beta', domains: [] }), { headers: { 'content-type': 'application/json' } })
    .persist()
}

beforeAll(() => {
  fetchMock.activate()
  fetchMock.disableNetConnect()
})
afterEach(() => fetchMock.assertNoPendingInterceptors)

describe('B13.4: POST /api/session/organization refreshes roles for the new org', () => {
  it('an admin of org A who is a member of org B becomes a member, with no org-A permissions', async () => {
    const jwt = await sessionFor({ sub: 'user_sw1', email: 'sw1@example.com', org: { id: 'org_A' }, roles: ['admin'], permissions: ['org:admin', 'members:write'] })
    mockMemberships('user_sw1', [
      { org: 'org_A', role: 'admin' },
      { org: 'org_B', role: 'member' },
    ])
    const res = await SELF.fetch(`${BASE}/api/session/organization`, {
      method: 'POST',
      headers: { cookie: `auth=${jwt}`, 'content-type': 'application/json' },
      body: JSON.stringify({ organizationId: 'org_B' }),
    })
    expect(res.status).toBe(200)
    const body = (await res.json()) as { user: { role: string | null; permissions: string[]; organizationId: string } }
    expect(body.user.organizationId).toBe('org_B')
    expect(body.user.role).toBe('member')
    expect(body.user.permissions).toEqual([])
    const minted = decodeJwt(authCookie(res))
    expect(minted.org.id).toBe('org_B')
    expect(minted.roles).toEqual(['member'])
    expect(minted.permissions ?? []).toEqual([])
  })

  it('still refuses an organization the person isn’t a member of', async () => {
    const jwt = await sessionFor({ sub: 'user_sw2', email: 'sw2@example.com', org: { id: 'org_A' }, roles: ['admin'] })
    mockMemberships('user_sw2', [{ org: 'org_A', role: 'admin' }])
    const res = await SELF.fetch(`${BASE}/api/session/organization`, {
      method: 'POST',
      headers: { cookie: `auth=${jwt}`, 'content-type': 'application/json' },
      body: JSON.stringify({ organizationId: 'org_B' }),
    })
    expect(res.status).toBe(403)
  })
})
