/**
 * B13 security prerequisites (docs/product-update/spec/backend.md#b13):
 *   2. /admin-portal, /fga/* and /pipes/* require authentication plus org
 *      authorisation; LEGACY_OPEN_WORKOS_ROUTES=1 restores the old open routes.
 *   3. Org member and invite routes check membership of :id (reads) and
 *      owner/admin (writes).
 *
 * The route-level guards are exercised through the workos route module with an
 * injected auth context (as test/workos-org-routes.test.ts does); the
 * index-level authentication gate through the whole worker.
 */
import { describe, it, expect, vi, afterEach } from 'vitest'
import { SELF, env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test'
import { Hono } from 'hono'
import worker from '../worker/index'
import { workosRoutes } from '../worker/routes/workos'
import type { Env, Variables } from '../worker/types'

const ORG_A = 'org_A'
const ORG_B = 'org_B'
const PLATFORM = 'org_PLATFORM'

type Who =
  | { kind: 'anon' }
  | { kind: 'key'; scope?: string }
  | { kind: 'user'; workosUserId: string }
  /** A person's own id.org.ai key (oai_/hly_sk_) in X-API-Key, plus an unvalidated `Bearer sk_…`. */
  | { kind: 'native-with-junk-bearer'; workosUserId: string }

function makeEnv(overrides: Partial<Env> = {}): Env {
  return { WORKOS_API_KEY: 'sk_platform_secret', PLATFORM_ORG_ID: PLATFORM, ...overrides } as Env
}

function makeApp(who: Who, envOverrides: Partial<Env> = {}) {
  const app = new Hono<{ Bindings: Env; Variables: Variables }>()
  app.use('*', async (c, next) => {
    if (who.kind === 'key') {
      // What the auth middleware sets for a key WorkOS validated (src/sdk/auth/broker-impl.ts).
      c.set('auth', { authenticated: true, identityId: 'apik_1', tenantId: who.scope, level: 2, scopes: [], capabilities: [] } as never)
      c.set('identity', { id: 'apik_1', type: 'service', name: 'k', verified: true, level: 2, claimStatus: 'claimed', tenantId: who.scope, credential: 'workos-key' } as never)
    } else if (who.kind === 'native-with-junk-bearer') {
      c.set('auth', { authenticated: true, identityId: `id_${who.workosUserId}`, level: 2, scopes: [], capabilities: [] } as never)
      c.set('identity', { id: `id_${who.workosUserId}`, type: 'human', name: 'p', verified: true, level: 2, claimStatus: 'claimed' } as never)
      c.set('identityStub', {
        oauthStorageOp: async () => ({ value: { workosUserId: who.workosUserId } }),
      } as never)
    } else if (who.kind === 'user') {
      c.set('auth', { authenticated: true, identityId: `id_${who.workosUserId}`, level: 2, scopes: [], capabilities: [] } as never)
      c.set('identityStub', {
        oauthStorageOp: async () => ({ value: { workosUserId: who.workosUserId } }),
      } as never)
    } else {
      c.set('auth', { authenticated: false, level: 0, scopes: [], capabilities: [] } as never)
    }
    await next()
  })
  app.route('', workosRoutes)
  return (path: string, init: RequestInit = {}) =>
    app.fetch(
      new Request(`https://id.org.ai${path}`, {
        ...init,
        headers: {
          ...(who.kind === 'key' ? { authorization: 'Bearer sk_test_server_token' } : {}),
          ...(who.kind === 'native-with-junk-bearer' ? { 'x-api-key': 'hly_sk_persons_own_key', authorization: 'Bearer sk_anything_at_all' } : {}),
          'content-type': 'application/json',
          ...(init.headers ?? {}),
        },
      }),
      makeEnv(envOverrides),
    )
}

const MEMBERSHIPS: Record<string, Array<{ organization_id: string; role: string }>> = {
  user_owner_A: [{ organization_id: ORG_A, role: 'owner' }],
  user_editor_A: [{ organization_id: ORG_A, role: 'editor' }],
  user_B: [{ organization_id: ORG_B, role: 'owner' }],
  user_platform: [{ organization_id: PLATFORM, role: 'admin' }],
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

/** A WorkOS double: memberships per user, plus 200s for the operations the routes call. */
function stubWorkOS() {
  const calls: string[] = []
  const fn = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(typeof input === 'string' ? input : input.toString())
    calls.push(`${init?.method ?? 'GET'} ${url.pathname}`)
    if (url.pathname === '/user_management/organization_memberships' && url.searchParams.get('user_id')) {
      const rows = MEMBERSHIPS[url.searchParams.get('user_id')!] ?? []
      return json({ data: rows.map((r, i) => ({ id: `om_${i}`, user_id: url.searchParams.get('user_id'), organization_id: r.organization_id, role: { slug: r.role }, status: 'active', created_at: 't', updated_at: 't' })) })
    }
    if (url.pathname === '/user_management/organization_memberships') return json({ data: [] })
    if (url.pathname === '/user_management/invitations') return json({ data: [] })
    // Every membership and invitation id the tests use lives in ORG_A.
    if (url.pathname.startsWith('/user_management/organization_memberships/')) return json({ id: 'om_9', user_id: 'u', organization_id: ORG_A, role: { slug: 'viewer' }, status: 'active', created_at: 't', updated_at: 't' })
    if (url.pathname.startsWith('/user_management/invitations/')) return json({ id: 'invitation_9', email: 'x@y.z', state: 'pending', organization_id: ORG_A, created_at: 't' })
    if (url.pathname === '/portal/generate_link') return json({ link: 'https://setup.workos.com/portal/x' })
    if (url.pathname.startsWith('/fga/')) return json({ result: 'authorized', warrant_token: 'w', data: [] })
    if (url.pathname.startsWith('/pipes/')) return json({ access_token: 'tok', expires_at: null, data: [] })
    if (url.pathname.startsWith('/sso/jwks/')) return json({ keys: [] })
    throw new Error(`unexpected WorkOS call: ${init?.method ?? 'GET'} ${url.pathname}`)
  })
  vi.stubGlobal('fetch', fn)
  return { fn, calls }
}

afterEach(() => vi.unstubAllGlobals())

describe('B13.2: /admin-portal requires an owner/admin of the organization', () => {
  it('an owner of the org gets the link', async () => {
    stubWorkOS()
    const res = await makeApp({ kind: 'user', workosUserId: 'user_owner_A' })(`/admin-portal?organization_id=${ORG_A}`)
    expect(res.status).toBe(200)
  })

  it('a non-admin member gets 403, and WorkOS is never asked for a link', async () => {
    const { calls } = stubWorkOS()
    const res = await makeApp({ kind: 'user', workosUserId: 'user_editor_A' })(`/admin-portal?organization_id=${ORG_A}`)
    expect(res.status).toBe(403)
    expect(calls).not.toContain('POST /portal/generate_link')
  })

  it('a member of another org gets 403', async () => {
    stubWorkOS()
    expect((await makeApp({ kind: 'user', workosUserId: 'user_B' })(`/admin-portal?organization_id=${ORG_A}`)).status).toBe(403)
  })

  it('an org-scoped key works for its own org only; a platform key for any', async () => {
    stubWorkOS()
    expect((await makeApp({ kind: 'key', scope: ORG_A })(`/admin-portal?organization_id=${ORG_A}`)).status).toBe(200)
    expect((await makeApp({ kind: 'key', scope: ORG_A })(`/admin-portal?organization_id=${ORG_B}`)).status).toBe(403)
    expect((await makeApp({ kind: 'key' })(`/admin-portal?organization_id=${ORG_B}`)).status).toBe(200)
    expect((await makeApp({ kind: 'key', scope: PLATFORM })(`/admin-portal?organization_id=${ORG_B}`)).status).toBe(200)
  })

  it('a platform-org admin is a platform caller', async () => {
    stubWorkOS()
    expect((await makeApp({ kind: 'user', workosUserId: 'user_platform' })(`/admin-portal?organization_id=${ORG_B}`)).status).toBe(200)
  })

  it('anonymous gets 401', async () => {
    stubWorkOS()
    expect((await makeApp({ kind: 'anon' })(`/admin-portal?organization_id=${ORG_A}`)).status).toBe(401)
  })
})

describe('B13.2: /fga/* is platform only', () => {
  it('refuses people and org-scoped keys, allows platform callers', async () => {
    stubWorkOS()
    const check = { resourceType: 'contact', resourceId: 'r', relation: 'viewer', subject: { resourceType: 'user', resourceId: 'u' } }
    for (const who of [{ kind: 'user', workosUserId: 'user_owner_A' }, { kind: 'key', scope: ORG_A }] as Who[]) {
      expect((await makeApp(who)('/fga/check', { method: 'POST', body: JSON.stringify(check) })).status).toBe(403)
      expect((await makeApp(who)('/fga/setup', { method: 'POST' })).status).toBe(403)
      expect((await makeApp(who)('/fga/share', { method: 'POST', body: JSON.stringify({ resourceType: 'contact', resourceId: 'r', targetTenant: ORG_B }) })).status).toBe(403)
      expect((await makeApp(who)('/fga/accessible?type=contact&user=someone_else')).status).toBe(403)
    }
    expect((await makeApp({ kind: 'key' })('/fga/check', { method: 'POST', body: JSON.stringify(check) })).status).toBe(200)
  })

  it('anonymous gets 401', async () => {
    stubWorkOS()
    expect((await makeApp({ kind: 'anon' })('/fga/setup', { method: 'POST' })).status).toBe(401)
  })
})

describe('B13.2: /pipes/* acts for the person themself, or a platform caller', () => {
  it('a person may fetch their own provider token, not someone else’s', async () => {
    stubWorkOS()
    const me = makeApp({ kind: 'user', workosUserId: 'user_owner_A' })
    expect((await me('/pipes/token', { method: 'POST', body: JSON.stringify({ provider: 'github', userId: 'user_owner_A' }) })).status).toBe(200)
    expect((await me('/pipes/token', { method: 'POST', body: JSON.stringify({ provider: 'github', userId: 'user_B' }) })).status).toBe(403)
    expect((await me('/pipes/token', { method: 'POST', body: JSON.stringify({ provider: 'github', userId: 'user_owner_A', organizationId: ORG_B }) })).status).toBe(403)
    expect((await me('/pipes/status?user_id=user_B')).status).toBe(403)
    expect((await me('/pipes/connections?user_id=user_B')).status).toBe(403)
  })

  it('connection-id routes are platform only', async () => {
    stubWorkOS()
    expect((await makeApp({ kind: 'user', workosUserId: 'user_owner_A' })('/pipes/connections/conn_1', { method: 'DELETE' })).status).toBe(403)
    expect((await makeApp({ kind: 'key' })('/pipes/connections/conn_1', { method: 'DELETE' })).status).toBe(200)
  })

  it('anonymous gets 401', async () => {
    stubWorkOS()
    expect((await makeApp({ kind: 'anon' })('/pipes/status?user_id=x')).status).toBe(401)
  })
})

describe('B13.2: LEGACY_OPEN_WORKOS_ROUTES=1 restores the old behaviour', () => {
  it('lets anonymous callers through the route guards', async () => {
    stubWorkOS()
    const open = makeApp({ kind: 'anon' }, { LEGACY_OPEN_WORKOS_ROUTES: '1' })
    expect((await open(`/admin-portal?organization_id=${ORG_A}`)).status).toBe(200)
    expect((await open('/fga/setup', { method: 'POST' })).status).toBe(200)
    expect((await open('/pipes/status?user_id=x')).status).toBe(200)
  })

  it('only the exact value 1 opens them', async () => {
    stubWorkOS()
    for (const v of ['true', 'yes', '0', '']) {
      expect((await makeApp({ kind: 'anon' }, { LEGACY_OPEN_WORKOS_ROUTES: v })(`/admin-portal?organization_id=${ORG_A}`)).status, v).toBe(401)
    }
  })
})

describe('B13.2: the whole worker authenticates these routes', () => {
  async function workerFetch(path: string, extra: Partial<Env> = {}, init?: RequestInit) {
    const ctx = createExecutionContext()
    const res = await worker.fetch(new Request(`https://id.org.ai${path}`, init), { ...(env as unknown as Env), ...extra } as never, ctx)
    await waitOnExecutionContext(ctx)
    return res
  }

  it('anonymous requests are 401 before any WorkOS call', async () => {
    const { fn } = stubWorkOS()
    for (const [path, init] of [
      [`/admin-portal?organization_id=${ORG_A}`, undefined],
      ['/fga/setup', { method: 'POST' }],
      ['/pipes/status?user_id=x', undefined],
    ] as const) {
      const res = await SELF.fetch(`https://id.org.ai${path}`, init)
      expect(res.status, path).toBe(401)
    }
    expect(fn.mock.calls.filter(([u]) => !String(u).includes('/sso/jwks/'))).toHaveLength(0)
  })

  it('with the escape hatch the old open routes come back', async () => {
    stubWorkOS()
    const res = await workerFetch(`/admin-portal?organization_id=${ORG_A}`, { LEGACY_OPEN_WORKOS_ROUTES: '1' })
    expect(res.status).toBe(200)
  })
})

describe('B13.3: org member and invite routes check membership of :id', () => {
  it('reads need membership', async () => {
    stubWorkOS()
    expect((await makeApp({ kind: 'user', workosUserId: 'user_editor_A' })(`/api/orgs/${ORG_A}/members`)).status).toBe(200)
    expect((await makeApp({ kind: 'user', workosUserId: 'user_B' })(`/api/orgs/${ORG_A}/members`)).status).toBe(403)
  })

  it('writes need owner or admin', async () => {
    stubWorkOS()
    const editor = makeApp({ kind: 'user', workosUserId: 'user_editor_A' })
    expect((await editor(`/api/orgs/${ORG_A}/members/om_9`, { method: 'PATCH', body: JSON.stringify({ role: 'admin' }) })).status).toBe(403)
    expect((await editor(`/api/orgs/${ORG_A}/members/om_9`, { method: 'DELETE' })).status).toBe(403)
    expect((await editor(`/api/orgs/${ORG_A}/invites`, { method: 'POST', body: JSON.stringify({ email: 'x@y.z', role: 'viewer' }) })).status).toBe(403)
    const owner = makeApp({ kind: 'user', workosUserId: 'user_owner_A' })
    expect((await owner(`/api/orgs/${ORG_A}/members/om_9`, { method: 'PATCH', body: JSON.stringify({ role: 'viewer' }) })).status).toBe(200)
  })

  it('an org-scoped key can manage its own org only', async () => {
    stubWorkOS()
    expect((await makeApp({ kind: 'key', scope: ORG_A })(`/api/orgs/${ORG_B}/members`)).status).toBe(403)
    expect((await makeApp({ kind: 'key', scope: ORG_A })(`/api/orgs/${ORG_A}/members`)).status).toBe(200)
  })
})

describe('B13.3: a membership or invitation must belong to :id (phase 4 review B1)', () => {
  // user_B owns ORG_B. om_9 and invitation_9 belong to ORG_A.
  const writes = (calls: string[]) => calls.filter((c) => !c.startsWith('GET '))

  it('an owner of another org cannot change a membership of ORG_A through their own org', async () => {
    const { calls } = stubWorkOS()
    const res = await makeApp({ kind: 'user', workosUserId: 'user_B' })(`/api/orgs/${ORG_B}/members/om_9`, { method: 'PATCH', body: JSON.stringify({ role: 'owner' }) })
    expect(res.status).toBe(404)
    expect(writes(calls)).toEqual([])
  })

  it('…nor remove an ORG_A member or rescind an ORG_A invitation', async () => {
    const { calls } = stubWorkOS()
    const b = makeApp({ kind: 'user', workosUserId: 'user_B' })
    expect((await b(`/api/orgs/${ORG_B}/members/om_9`, { method: 'DELETE' })).status).toBe(404)
    expect((await b(`/api/orgs/${ORG_B}/members/invitation_9`, { method: 'DELETE' })).status).toBe(404)
    expect((await b(`/api/orgs/${ORG_B}/members/inv_9`, { method: 'DELETE' })).status).toBe(404) // unknown prefix
    expect(writes(calls)).toEqual([])
  })

  it('an org-scoped key cannot reach another org’s membership either', async () => {
    const { calls } = stubWorkOS()
    const res = await makeApp({ kind: 'key', scope: ORG_B })(`/api/orgs/${ORG_B}/members/om_9`, { method: 'PATCH', body: JSON.stringify({ role: 'owner' }) })
    expect(res.status).toBe(404)
    expect(writes(calls)).toEqual([])
  })

  it('the owner of ORG_A still manages ORG_A’s members and invitations', async () => {
    const { calls } = stubWorkOS()
    const a = makeApp({ kind: 'user', workosUserId: 'user_owner_A' })
    expect((await a(`/api/orgs/${ORG_A}/members/om_9`, { method: 'PATCH', body: JSON.stringify({ role: 'viewer' }) })).status).toBe(200)
    expect((await a(`/api/orgs/${ORG_A}/members/om_9`, { method: 'DELETE' })).status).toBe(200)
    expect((await a(`/api/orgs/${ORG_A}/members/invitation_9`, { method: 'DELETE' })).status).toBe(200)
    expect(writes(calls)).toEqual([
      'PUT /user_management/organization_memberships/om_9',
      'DELETE /user_management/organization_memberships/om_9',
      'POST /user_management/invitations/invitation_9/revoke',
    ])
  })

  it('an id that isn’t a plain WorkOS id is refused before any WorkOS call', async () => {
    const { calls } = stubWorkOS()
    const a = makeApp({ kind: 'user', workosUserId: 'user_owner_A' })
    for (const id of ['..%2F..%2Forganizations%2Forg_B', 'om_9%3Fx%3D1', 'om_9%23', '%2E%2E']) {
      expect((await a(`/api/orgs/${ORG_A}/members/${id}`, { method: 'PATCH', body: JSON.stringify({ role: 'viewer' }) })).status, id).toBe(404)
      expect((await a(`/api/orgs/${ORG_A}/members/${id}`, { method: 'DELETE' })).status, id).toBe(404)
    }
    // Only the caller's own membership list (the role check) is fetched; nothing per member.
    expect(calls.filter((c) => c !== 'GET /user_management/organization_memberships')).toEqual([])
  })
})

describe('B13.2/3: only a key WorkOS validated is a key caller (phase 4 review B2)', () => {
  // The person behind the native key has no memberships at all.
  it('a native key in X-API-Key plus a junk `Bearer sk_` is the person, not the platform', async () => {
    stubWorkOS()
    const junk = makeApp({ kind: 'native-with-junk-bearer', workosUserId: 'user_nobody' })
    expect((await junk(`/admin-portal?organization_id=${ORG_A}`)).status).toBe(403)
    expect((await junk('/fga/setup', { method: 'POST' })).status).toBe(403)
    expect((await junk('/pipes/token', { method: 'POST', body: JSON.stringify({ userId: 'user_victim', provider: 'github' }) })).status).toBe(403)
    expect((await junk(`/api/orgs/${ORG_A}/members/om_9`, { method: 'PATCH', body: JSON.stringify({ role: 'owner' }) })).status).toBe(403)
  })

  it('a WorkOS-validated key is a key caller whichever header carried it', async () => {
    stubWorkOS()
    const viaXApiKey = makeApp({ kind: 'key', scope: ORG_A })
    expect((await viaXApiKey(`/api/orgs/${ORG_A}/members`, { headers: { authorization: '', 'x-api-key': 'sk_test_server_token' } })).status).toBe(200)
  })
})
