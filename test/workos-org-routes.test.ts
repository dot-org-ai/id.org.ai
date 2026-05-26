/**
 * Organization-membership route tests.
 *
 * Mounts the `workosRoutes` Hono sub-app directly and drives requests through
 * `app.fetch(req, env)`. The server-to-server auth path (option b) is exercised
 * by presenting a WorkOS `sk_*` Bearer token; the route validates it against
 * WorkOS, which we intercept by mocking global `fetch`. All WorkOS upstream
 * calls are mocked, so no network is touched.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { Hono } from 'hono'
import { workosRoutes } from '../worker/routes/workos'
import type { Env, Variables } from '../worker/types'
import type { MCPAuthResult } from '../src/sdk/mcp/auth'

const ORG = 'org_acme'
const SERVER_TOKEN = 'sk_test_server_token'

/** Env with WorkOS configured. */
function makeEnv(overrides: Partial<Env> = {}): Env {
  return {
    WORKOS_API_KEY: 'sk_platform_secret',
    WORKOS_CLIENT_ID: 'client_test',
    ...overrides,
  } as Env
}

/** Anonymous auth — forces the route onto the sk_/JWT paths. */
function makeApp(env: Env, auth: MCPAuthResult | null = { authenticated: false, level: 0, scopes: [], capabilities: [] } as MCPAuthResult) {
  const app = new Hono<{ Bindings: Env; Variables: Variables }>()
  app.use('*', async (c, next) => {
    if (auth) c.set('auth', auth as never)
    await next()
  })
  app.route('', workosRoutes)
  return (req: Request) => app.fetch(req, env)
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

/**
 * Route a mocked WorkOS upstream call by URL + method. Returns the matching
 * response or throws (surfacing an unexpected call in the test).
 */
function workosMock(routes: Array<{ match: (url: string, init?: RequestInit) => boolean; res: () => Response }>) {
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString()
    const r = routes.find((x) => x.match(url, init))
    if (!r) throw new Error(`Unexpected fetch: ${init?.method ?? 'GET'} ${url}`)
    return r.res()
  })
}

/** The WorkOS api-key validation route used by the sk_ server-token path. */
const validationRoute = {
  match: (url: string) => url === 'https://api.workos.com/api_keys/validations',
  res: () => jsonResponse({ id: 'key_1', name: 'SaaS.Studio server token', organization_id: ORG }),
}

function authReq(path: string, init: RequestInit = {}): Request {
  return new Request(`https://id.org.ai${path}`, {
    ...init,
    headers: { authorization: `Bearer ${SERVER_TOKEN}`, ...(init.headers ?? {}) },
  })
}

let mockFetch: ReturnType<typeof vi.fn>
afterEach(() => vi.restoreAllMocks())

// ============================================================================
// auth gate
// ============================================================================

describe('org-membership routes - auth', () => {
  it('rejects an unauthenticated request (no sk_ token, no identity, no JWT)', async () => {
    mockFetch = workosMock([])
    vi.stubGlobal('fetch', mockFetch)
    const fetchApp = makeApp(makeEnv())
    const res = await fetchApp(new Request(`https://id.org.ai/api/orgs/${ORG}/members`))
    expect(res.status).toBe(401)
  })

  it('rejects when the sk_ token fails WorkOS validation', async () => {
    mockFetch = workosMock([
      { match: (url) => url === 'https://api.workos.com/api_keys/validations', res: () => jsonResponse({}, 401) },
    ])
    vi.stubGlobal('fetch', mockFetch)
    const fetchApp = makeApp(makeEnv())
    const res = await fetchApp(authReq(`/api/orgs/${ORG}/members`))
    expect(res.status).toBe(401)
  })

  it('503 when WorkOS is not configured', async () => {
    mockFetch = workosMock([])
    vi.stubGlobal('fetch', mockFetch)
    const fetchApp = makeApp(makeEnv({ WORKOS_API_KEY: undefined }))
    const res = await fetchApp(authReq(`/api/orgs/${ORG}/members`))
    expect(res.status).toBe(503)
  })
})

// ============================================================================
// GET /api/orgs/:id/members
// ============================================================================

describe('GET /api/orgs/:id/members', () => {
  it('returns active members (hydrated) + pending invites with aligned DTO fields', async () => {
    mockFetch = workosMock([
      validationRoute,
      {
        match: (url) => url.includes('/user_management/organization_memberships') && url.includes('organization_id='),
        res: () =>
          jsonResponse({
            data: [
              { id: 'om_1', user_id: 'user_1', organization_id: ORG, role: { slug: 'owner' }, status: 'active', created_at: '2026-01-01T00:00:00Z', updated_at: 't' },
              { id: 'om_2', user_id: 'user_2', organization_id: ORG, role: { slug: 'member' }, status: 'active', created_at: '2026-02-01T00:00:00Z', updated_at: 't' },
            ],
          }),
      },
      {
        match: (url) => url.includes('/user_management/invitations') && url.includes('organization_id='),
        res: () =>
          jsonResponse({
            data: [{ id: 'invitation_9', email: 'pending@x.com', state: 'pending', role: { slug: 'editor' }, created_at: '2026-03-01T00:00:00Z' }],
          }),
      },
      {
        match: (url) => url === 'https://api.workos.com/user_management/users/user_1',
        res: () => jsonResponse({ id: 'user_1', email: 'amy@do.industries', first_name: 'Amy', last_name: 'Builder' }),
      },
      {
        match: (url) => url === 'https://api.workos.com/user_management/users/user_2',
        res: () => jsonResponse({ id: 'user_2', email: 'dev@x.com', first_name: 'Dev' }),
      },
    ])
    vi.stubGlobal('fetch', mockFetch)
    const fetchApp = makeApp(makeEnv())

    const res = await fetchApp(authReq(`/api/orgs/${ORG}/members`))
    expect(res.status).toBe(200)
    const body = (await res.json()) as { members: any[] }
    expect(body.members).toHaveLength(3)

    const owner = body.members.find((m) => m.sub === 'user_1')
    expect(owner).toMatchObject({
      id: 'om_1',
      sub: 'user_1',
      email: 'amy@do.industries',
      name: 'Amy Builder',
      display_name: 'Amy Builder',
      role: 'owner',
      status: 'active',
      joined_at: '2026-01-01T00:00:00Z',
    })

    // Legacy `member` slug folds to editor.
    const dev = body.members.find((m) => m.sub === 'user_2')
    expect(dev.role).toBe('editor')

    const pending = body.members.find((m) => m.status === 'pending')
    expect(pending).toMatchObject({ id: 'invitation_9', email: 'pending@x.com', role: 'editor', status: 'pending' })
  })

  it('de-duplicates user-profile lookups for repeated user ids', async () => {
    const userCalls: string[] = []
    mockFetch = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString()
      if (url === 'https://api.workos.com/api_keys/validations') return jsonResponse({ id: 'k', organization_id: ORG })
      if (url.includes('/organization_memberships') && url.includes('organization_id='))
        return jsonResponse({
          data: [
            { id: 'om_1', user_id: 'user_1', organization_id: ORG, role: { slug: 'admin' }, status: 'active', created_at: 't', updated_at: 't' },
            { id: 'om_2', user_id: 'user_1', organization_id: ORG, role: { slug: 'viewer' }, status: 'active', created_at: 't', updated_at: 't' },
          ],
        })
      if (url.includes('/invitations')) return jsonResponse({ data: [] })
      if (url.startsWith('https://api.workos.com/user_management/users/')) {
        userCalls.push(url)
        return jsonResponse({ id: 'user_1', email: 'a@b.com' })
      }
      throw new Error(`Unexpected ${url}`)
    })
    vi.stubGlobal('fetch', mockFetch)
    const fetchApp = makeApp(makeEnv())

    const res = await fetchApp(authReq(`/api/orgs/${ORG}/members`))
    expect(res.status).toBe(200)
    expect(userCalls).toEqual(['https://api.workos.com/user_management/users/user_1'])
  })
})

// ============================================================================
// PATCH /api/orgs/:id/members/:membershipId
// ============================================================================

describe('PATCH /api/orgs/:id/members/:membershipId', () => {
  it('maps the Account role to a WorkOS slug and PUTs it', async () => {
    let putBody: any = null
    mockFetch = workosMock([
      validationRoute,
      {
        match: (url, init) => url === 'https://api.workos.com/user_management/organization_memberships/om_1' && init?.method === 'PUT',
        res: () => jsonResponse({ id: 'om_1', user_id: 'user_1', organization_id: ORG, role: { slug: 'admin' }, status: 'active', created_at: 't', updated_at: 't' }),
      },
    ])
    // Capture the PUT body.
    const orig = mockFetch
    mockFetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method === 'PUT' && init.body) putBody = JSON.parse(init.body as string)
      return orig(input, init)
    })
    vi.stubGlobal('fetch', mockFetch)
    const fetchApp = makeApp(makeEnv())

    const res = await fetchApp(
      authReq(`/api/orgs/${ORG}/members/om_1`, { method: 'PATCH', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ role: 'admin' }) }),
    )
    expect(res.status).toBe(200)
    expect(putBody.role_slug).toBe('admin')
    const body = (await res.json()) as any
    expect(body).toMatchObject({ id: 'om_1', role: 'admin', status: 'active' })
  })

  it('400 when role is missing', async () => {
    mockFetch = workosMock([validationRoute])
    vi.stubGlobal('fetch', mockFetch)
    const fetchApp = makeApp(makeEnv())
    const res = await fetchApp(authReq(`/api/orgs/${ORG}/members/om_1`, { method: 'PATCH', headers: { 'content-type': 'application/json' }, body: '{}' }))
    expect(res.status).toBe(400)
  })

  it('502 when the WorkOS update fails', async () => {
    mockFetch = workosMock([
      validationRoute,
      { match: (url, init) => url.includes('/organization_memberships/om_1') && init?.method === 'PUT', res: () => jsonResponse({}, 404) },
    ])
    vi.stubGlobal('fetch', mockFetch)
    const fetchApp = makeApp(makeEnv())
    const res = await fetchApp(authReq(`/api/orgs/${ORG}/members/om_1`, { method: 'PATCH', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ role: 'viewer' }) }))
    expect(res.status).toBe(502)
  })
})

// ============================================================================
// DELETE /api/orgs/:id/members/:membershipId
// ============================================================================

describe('DELETE /api/orgs/:id/members/:membershipId', () => {
  it('deletes a membership for an om_ id', async () => {
    let calledDelete = ''
    mockFetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString()
      if (url === 'https://api.workos.com/api_keys/validations') return jsonResponse({ id: 'k', organization_id: ORG })
      if (init?.method === 'DELETE') {
        calledDelete = url
        return new Response(null, { status: 204 })
      }
      throw new Error(`Unexpected ${url}`)
    })
    vi.stubGlobal('fetch', mockFetch)
    const fetchApp = makeApp(makeEnv())

    const res = await fetchApp(authReq(`/api/orgs/${ORG}/members/om_42`, { method: 'DELETE' }))
    expect(res.status).toBe(200)
    expect(calledDelete).toBe('https://api.workos.com/user_management/organization_memberships/om_42')
    expect((await res.json()) as any).toEqual({ ok: true })
  })

  it('rescinds an invitation for an invitation_ id', async () => {
    let calledRevoke = ''
    mockFetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString()
      if (url === 'https://api.workos.com/api_keys/validations') return jsonResponse({ id: 'k', organization_id: ORG })
      if (url.endsWith('/revoke') && init?.method === 'POST') {
        calledRevoke = url
        return jsonResponse({ id: 'invitation_7', state: 'revoked' })
      }
      throw new Error(`Unexpected ${url}`)
    })
    vi.stubGlobal('fetch', mockFetch)
    const fetchApp = makeApp(makeEnv())

    const res = await fetchApp(authReq(`/api/orgs/${ORG}/members/invitation_7`, { method: 'DELETE' }))
    expect(res.status).toBe(200)
    expect(calledRevoke).toBe('https://api.workos.com/user_management/invitations/invitation_7/revoke')
  })
})

// ============================================================================
// POST /api/orgs/:id/invites (+ /invitations alias)
// ============================================================================

describe('POST /api/orgs/:id/invites', () => {
  it('maps role to slug, sends the invite, and returns a pending member DTO', async () => {
    let inviteBody: any = null
    mockFetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString()
      if (url === 'https://api.workos.com/api_keys/validations') return jsonResponse({ id: 'k', organization_id: ORG })
      if (url === 'https://api.workos.com/user_management/invitations' && init?.method === 'POST') {
        inviteBody = JSON.parse(init.body as string)
        return jsonResponse({ id: 'invitation_new', email: inviteBody.email, state: 'pending' })
      }
      if (url.includes('/user_management/invitations') && url.includes('organization_id='))
        return jsonResponse({ data: [{ id: 'invitation_new', email: 'dev@example.com', state: 'pending', role: { slug: 'editor' }, created_at: '2026-05-01T00:00:00Z' }] })
      throw new Error(`Unexpected ${url}`)
    })
    vi.stubGlobal('fetch', mockFetch)
    const fetchApp = makeApp(makeEnv())

    const res = await fetchApp(
      authReq(`/api/orgs/${ORG}/invites`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: 'Dev@Example.com', role: 'editor' }) }),
    )
    expect(res.status).toBe(201)
    expect(inviteBody).toMatchObject({ email: 'dev@example.com', organization_id: ORG, role_slug: 'editor' })
    const body = (await res.json()) as any
    expect(body).toMatchObject({ id: 'invitation_new', email: 'dev@example.com', role: 'editor', status: 'pending' })
  })

  it('400 when email is missing', async () => {
    mockFetch = workosMock([validationRoute])
    vi.stubGlobal('fetch', mockFetch)
    const fetchApp = makeApp(makeEnv())
    const res = await fetchApp(authReq(`/api/orgs/${ORG}/invites`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' }))
    expect(res.status).toBe(400)
  })

  it('is reachable via the /invitations alias too', async () => {
    mockFetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString()
      if (url === 'https://api.workos.com/api_keys/validations') return jsonResponse({ id: 'k', organization_id: ORG })
      if (url === 'https://api.workos.com/user_management/invitations' && init?.method === 'POST') return jsonResponse({ id: 'invitation_a', state: 'pending' })
      if (url.includes('/user_management/invitations')) return jsonResponse({ data: [] })
      throw new Error(`Unexpected ${url}`)
    })
    vi.stubGlobal('fetch', mockFetch)
    const fetchApp = makeApp(makeEnv())
    const res = await fetchApp(authReq(`/api/orgs/${ORG}/invitations`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: 'x@y.com', role: 'viewer' }) }))
    expect(res.status).toBe(201)
  })
})

// ============================================================================
// POST /api/orgs — account auto-create (idempotent)
// ============================================================================

describe('POST /api/orgs', () => {
  it('creates a new org + owner membership and returns 201 with created:true', async () => {
    let createdMembership: any = null
    mockFetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString()
      if (url === 'https://api.workos.com/api_keys/validations') return jsonResponse({ id: 'k', organization_id: ORG })
      // findOwnedOrg → user has no memberships yet
      if (url.includes('/organization_memberships') && url.includes('user_id=')) return jsonResponse({ data: [] })
      if (url === 'https://api.workos.com/organizations' && init?.method === 'POST') return jsonResponse({ id: 'org_new', name: 'Amy Builder' })
      if (url === 'https://api.workos.com/user_management/organization_memberships' && init?.method === 'POST') {
        createdMembership = JSON.parse(init.body as string)
        return jsonResponse({ id: 'om_new' })
      }
      throw new Error(`Unexpected ${url}`)
    })
    vi.stubGlobal('fetch', mockFetch)
    const fetchApp = makeApp(makeEnv())

    const res = await fetchApp(authReq('/api/orgs', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ name: 'Amy Builder', owner_sub: 'user_owner' }) }))
    expect(res.status).toBe(201)
    const body = (await res.json()) as any
    expect(body).toMatchObject({ id: 'org_new', name: 'Amy Builder', owner_sub: 'user_owner', created: true })
    expect(createdMembership).toMatchObject({ user_id: 'user_owner', organization_id: 'org_new', role_slug: 'owner' })
  })

  it('is idempotent: returns the existing org with 200 + created:false', async () => {
    mockFetch = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString()
      if (url === 'https://api.workos.com/api_keys/validations') return jsonResponse({ id: 'k', organization_id: ORG })
      if (url.includes('/organization_memberships') && url.includes('user_id='))
        return jsonResponse({ data: [{ id: 'om_x', user_id: 'user_owner', organization_id: 'org_existing', role: { slug: 'owner' }, status: 'active', created_at: 't', updated_at: 't' }] })
      if (url === 'https://api.workos.com/organizations/org_existing') return jsonResponse({ id: 'org_existing', name: 'Existing Account' })
      throw new Error(`Unexpected ${url}`)
    })
    vi.stubGlobal('fetch', mockFetch)
    const fetchApp = makeApp(makeEnv())

    const res = await fetchApp(authReq('/api/orgs', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ name: 'Amy Builder', owner_sub: 'user_owner' }) }))
    expect(res.status).toBe(200)
    const body = (await res.json()) as any
    expect(body).toMatchObject({ id: 'org_existing', owner_sub: 'user_owner', created: false })
  })

  it('400 when name is missing', async () => {
    mockFetch = workosMock([validationRoute])
    vi.stubGlobal('fetch', mockFetch)
    const fetchApp = makeApp(makeEnv())
    const res = await fetchApp(authReq('/api/orgs', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ owner_sub: 'user_owner' }) }))
    expect(res.status).toBe(400)
  })
})
