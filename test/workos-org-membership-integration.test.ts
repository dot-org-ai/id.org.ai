/**
 * Integration test for `/api/orgs/*` routes — the full middleware chain.
 *
 * The route-level tests in `workos-org-routes.test.ts` stub the
 * `authenticateRequest` middleware. This file uses the **real**
 * `authenticateRequest` from `worker/middleware/auth.ts`, the one that
 * `worker/index.ts:735` mounts in production for every `/api/*` request.
 *
 * The bug PR #7 fixed: the broker's `sk_*` API-key branch only consulted the
 * DO's `validateApiKey`, which never holds WorkOS-issued keys, so the
 * dashboard's `IDORGAI_ORG_TOKEN` 401d at the middleware and never reached
 * the org-membership route handlers. The fix adds a `validateWorkOSKey`
 * fallback in `broker-impl.ts`, wired through `worker/middleware/auth.ts`.
 *
 * These tests assert:
 *   1. A WorkOS sk_* key that DO-misses but WorkOS-validates passes the
 *      middleware and reaches the route handler.
 *   2. The response shape aligns with `saas.studio` `dtoToMember`.
 *   3. Same flow for PATCH / DELETE / POST routes.
 *   4. A WorkOS sk_* key that fails WorkOS validation still 401s.
 *   5. id.org.ai-issued credentials (oai_*, ses_*) keep working (regression).
 *   6. The "presented explicit credential but invalid" path still 401s.
 *
 * WorkOS upstream is mocked at the global `fetch`. The DO stub is a hand-
 * built minimal IdentityStub that returns `valid:false` for everything —
 * the broker's `sk_*` DO-miss → WorkOS fallback is exactly the path under
 * test.
 */

import { describe, it, expect, vi, afterEach } from 'vitest'
import { Hono } from 'hono'
import { authenticateRequest } from '../worker/middleware/auth'
import { workosRoutes } from '../worker/routes/workos'
import type { Env, Variables } from '../worker/types'
import type { IdentityStub } from '../src/server/do/Identity'

const ORG = 'org_acme'
const WORKOS_SK = 'sk_dashboard_server_token'

// ── Test helpers ────────────────────────────────────────────────────────────

function makeEnv(overrides: Partial<Env> = {}): Env {
  return {
    WORKOS_API_KEY: 'sk_platform_secret',
    WORKOS_CLIENT_ID: 'client_test',
    ...overrides,
  } as Env
}

/**
 * Build a minimal IdentityStub that always reports "not found". The broker
 * branches on `validateApiKey().valid === false` for `sk_*` keys → falls
 * through to `validateWorkOSKey` — exactly the path the dashboard hits.
 */
function emptyStub(): IdentityStub {
  return {
    validateApiKey: vi.fn(async () => ({ valid: false })),
    getSession: vi.fn(async () => ({ valid: false })),
    getIdentity: vi.fn(async () => null),
    getAgent: vi.fn(async () => null),
    touchAgent: vi.fn(async () => {}),
    checkRateLimit: vi.fn(async () => ({ allowed: true, remaining: 99, resetAt: Date.now() + 60000 })),
    oauthStorageOp: vi.fn(async () => ({ value: undefined })),
  } as unknown as IdentityStub
}

/**
 * Mount the routes under the REAL `authenticateRequest` middleware. The only
 * test seam is which `identityStub` is presented (the production middleware
 * upstream of `authenticateRequest` is `identityStubMiddleware`, which reads
 * the credential from KV; we set it explicitly here per request to keep the
 * test focused on the auth middleware itself).
 */
function makeApp(env: Env, stubProvider: (req: Request) => IdentityStub | undefined) {
  const app = new Hono<{ Bindings: Env; Variables: Variables }>()
  app.use('*', async (c, next) => {
    const stub = stubProvider(c.req.raw)
    if (stub) c.set('identityStub', stub)
    await next()
  })
  app.use('/api/*', authenticateRequest)
  app.route('', workosRoutes)
  return (req: Request) => app.fetch(req, env)
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function req(path: string, init: RequestInit = {}, token = WORKOS_SK): Request {
  return new Request(`https://id.org.ai${path}`, {
    ...init,
    headers: { authorization: `Bearer ${token}`, ...(init.headers ?? {}) },
  })
}

const workosKeyValidation = (overrides: Record<string, unknown> = {}) => ({
  match: (url: string) => url === 'https://api.workos.com/api_keys/validations',
  res: () =>
    jsonResponse({
      id: 'apik_dashboard',
      name: 'SaaS.Studio Dashboard',
      organization_id: ORG,
      permissions: ['read', 'write'],
      ...overrides,
    }),
})

function mockFetch(
  routes: Array<{ match: (url: string, init?: RequestInit) => boolean; res: () => Response }>,
) {
  const fn = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString()
    const r = routes.find((x) => x.match(url, init))
    if (!r) throw new Error(`Unexpected fetch: ${init?.method ?? 'GET'} ${url}`)
    return r.res()
  })
  vi.stubGlobal('fetch', fn)
  return fn
}

afterEach(() => vi.restoreAllMocks())

// ── Tests ───────────────────────────────────────────────────────────────────

describe('integration: real authenticateRequest middleware + /api/orgs/*', () => {
  describe('the bug fix: sk_* falls through DO miss to WorkOS validation', () => {
    it('GET /api/orgs/:id/members — sk_* token reaches the handler and returns the DTO', async () => {
      mockFetch([
        workosKeyValidation(),
        {
          match: (url) => url.includes('/user_management/organization_memberships') && url.includes('organization_id='),
          res: () =>
            jsonResponse({
              data: [
                {
                  id: 'om_1',
                  user_id: 'user_amy',
                  organization_id: ORG,
                  role: { slug: 'owner' },
                  status: 'active',
                  created_at: '2026-01-01T00:00:00Z',
                  updated_at: '2026-01-01T00:00:00Z',
                },
              ],
            }),
        },
        {
          match: (url) => url.includes('/user_management/invitations') && url.includes('organization_id='),
          res: () => jsonResponse({ data: [] }),
        },
        {
          match: (url) => url === 'https://api.workos.com/user_management/users/user_amy',
          res: () => jsonResponse({ id: 'user_amy', email: 'amy@do.industries', first_name: 'Amy', last_name: 'Builder' }),
        },
      ])

      const app = makeApp(makeEnv(), () => emptyStub())
      const res = await app(req(`/api/orgs/${ORG}/members`))

      expect(res.status).toBe(200)
      const body = (await res.json()) as { members: any[] }
      // dtoToMember-aligned fields: id, sub, name, display_name, email, role, status, joined_at
      expect(body.members).toHaveLength(1)
      expect(body.members[0]).toMatchObject({
        id: 'om_1',
        sub: 'user_amy',
        name: 'Amy Builder',
        display_name: 'Amy Builder',
        email: 'amy@do.industries',
        role: 'owner',
        status: 'active',
        joined_at: '2026-01-01T00:00:00Z',
      })
    })

    it('PATCH /api/orgs/:id/members/:membershipId — role-change reaches the handler', async () => {
      mockFetch([
        workosKeyValidation(),
        {
          match: (url, init) =>
            url === 'https://api.workos.com/user_management/organization_memberships/om_1' && init?.method === 'PUT',
          res: () =>
            jsonResponse({
              id: 'om_1',
              user_id: 'user_amy',
              organization_id: ORG,
              role: { slug: 'admin' },
              status: 'active',
              created_at: 't',
              updated_at: 't',
            }),
        },
      ])

      const app = makeApp(makeEnv(), () => emptyStub())
      const res = await app(
        req(`/api/orgs/${ORG}/members/om_1`, {
          method: 'PATCH',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ role: 'admin' }),
        }),
      )

      expect(res.status).toBe(200)
      const body = (await res.json()) as any
      expect(body).toMatchObject({ id: 'om_1', role: 'admin', status: 'active' })
    })

    it('DELETE /api/orgs/:id/members/:membershipId — remove member reaches the handler', async () => {
      mockFetch([
        workosKeyValidation(),
        {
          match: (url, init) =>
            url === 'https://api.workos.com/user_management/organization_memberships/om_42' && init?.method === 'DELETE',
          res: () => new Response(null, { status: 204 }),
        },
      ])

      const app = makeApp(makeEnv(), () => emptyStub())
      const res = await app(req(`/api/orgs/${ORG}/members/om_42`, { method: 'DELETE' }))

      expect(res.status).toBe(200)
      expect((await res.json()) as any).toEqual({ ok: true })
    })

    it('DELETE /api/orgs/:id/members/:invitationId — revoke invite reaches the handler', async () => {
      mockFetch([
        workosKeyValidation(),
        {
          match: (url, init) =>
            url === 'https://api.workos.com/user_management/invitations/invitation_9/revoke' && init?.method === 'POST',
          res: () => jsonResponse({ id: 'invitation_9', state: 'revoked' }),
        },
      ])

      const app = makeApp(makeEnv(), () => emptyStub())
      const res = await app(req(`/api/orgs/${ORG}/members/invitation_9`, { method: 'DELETE' }))

      expect(res.status).toBe(200)
    })

    it('POST /api/orgs — create-account reaches the handler with explicit owner_sub', async () => {
      mockFetch([
        workosKeyValidation(),
        // findOwnedOrg — none yet
        {
          match: (url) => url.includes('/user_management/organization_memberships') && url.includes('user_id='),
          res: () => jsonResponse({ data: [] }),
        },
        {
          match: (url, init) => url === 'https://api.workos.com/organizations' && init?.method === 'POST',
          res: () => jsonResponse({ id: 'org_new', name: 'Amy Builder' }),
        },
        {
          match: (url, init) =>
            url === 'https://api.workos.com/user_management/organization_memberships' && init?.method === 'POST',
          res: () => jsonResponse({ id: 'om_new' }),
        },
      ])

      const app = makeApp(makeEnv(), () => emptyStub())
      const res = await app(
        req('/api/orgs', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ name: 'Amy Builder', owner_sub: 'user_owner' }),
        }),
      )

      expect(res.status).toBe(201)
      const body = (await res.json()) as any
      expect(body).toMatchObject({ id: 'org_new', owner_sub: 'user_owner', created: true })
    })

    it('POST /api/orgs/:id/invites — invite reaches the handler', async () => {
      mockFetch([
        workosKeyValidation(),
        {
          match: (url, init) => url === 'https://api.workos.com/user_management/invitations' && init?.method === 'POST',
          res: () => jsonResponse({ id: 'invitation_new', state: 'pending' }),
        },
        {
          match: (url) => url.includes('/user_management/invitations') && url.includes('organization_id='),
          res: () =>
            jsonResponse({
              data: [
                {
                  id: 'invitation_new',
                  email: 'dev@x.com',
                  state: 'pending',
                  role: { slug: 'editor' },
                  created_at: '2026-05-01T00:00:00Z',
                },
              ],
            }),
        },
      ])

      const app = makeApp(makeEnv(), () => emptyStub())
      const res = await app(
        req(`/api/orgs/${ORG}/invites`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ email: 'dev@x.com', role: 'editor' }),
        }),
      )

      expect(res.status).toBe(201)
      const body = (await res.json()) as any
      expect(body).toMatchObject({ id: 'invitation_new', email: 'dev@x.com', role: 'editor', status: 'pending' })
    })
  })

  describe('regression: existing credential paths still work', () => {
    it('rejects a sk_* token that fails WorkOS validation (still 401)', async () => {
      mockFetch([
        {
          match: (url) => url === 'https://api.workos.com/api_keys/validations',
          res: () => jsonResponse({}, 401),
        },
      ])

      const app = makeApp(makeEnv(), () => emptyStub())
      const res = await app(req(`/api/orgs/${ORG}/members`))

      expect(res.status).toBe(401)
    })

    it('accepts a valid id.org.ai-issued oai_* key (DO path, unchanged)', async () => {
      mockFetch([
        // memberships + invites — no WorkOS validation call expected
        {
          match: (url) => url.includes('/user_management/organization_memberships') && url.includes('organization_id='),
          res: () => jsonResponse({ data: [] }),
        },
        {
          match: (url) => url.includes('/user_management/invitations') && url.includes('organization_id='),
          res: () => jsonResponse({ data: [] }),
        },
      ])

      const stub = {
        validateApiKey: vi.fn(async () => ({
          valid: true,
          identityId: 'human:test-user',
          scopes: ['read', 'write'],
          level: 2 as const,
        })),
        getSession: vi.fn(async () => ({ valid: false })),
        getIdentity: vi.fn(async (id: string) => ({
          id,
          type: 'human' as const,
          name: 'test-user',
          verified: true,
          level: 2 as const,
          claimStatus: 'claimed' as const,
        })),
        getAgent: vi.fn(async () => null),
        touchAgent: vi.fn(async () => {}),
        checkRateLimit: vi.fn(async () => ({ allowed: true, remaining: 99, resetAt: Date.now() + 60000 })),
        oauthStorageOp: vi.fn(async () => ({ value: undefined })),
      } as unknown as IdentityStub

      const app = makeApp(makeEnv(), () => stub)
      const res = await app(req(`/api/orgs/${ORG}/members`, {}, 'oai_test_user_key'))

      expect(res.status).toBe(200)
      // The WorkOS validation endpoint must NOT have been called — DO path served it.
      const fetchMock = (globalThis.fetch as unknown) as ReturnType<typeof vi.fn>
      const calls = fetchMock.mock.calls.map(([u]) => (typeof u === 'string' ? u : (u as URL).toString()))
      expect(calls.some((u) => u.includes('/api_keys/validations'))).toBe(false)
    })

    it('rejects an invalid oai_* key with 401 (presented-but-invalid path)', async () => {
      // No WorkOS sk_ fallback for oai_* — must 401.
      mockFetch([])

      const stub = {
        validateApiKey: vi.fn(async () => ({ valid: false })),
        getSession: vi.fn(async () => ({ valid: false })),
        getIdentity: vi.fn(async () => null),
        getAgent: vi.fn(async () => null),
        touchAgent: vi.fn(async () => {}),
        checkRateLimit: vi.fn(async () => ({ allowed: true, remaining: 99, resetAt: Date.now() + 60000 })),
      } as unknown as IdentityStub

      const app = makeApp(makeEnv(), () => stub)
      const res = await app(req(`/api/orgs/${ORG}/members`, {}, 'oai_bad_key'))

      expect(res.status).toBe(401)
    })

    it('rejects a request with no credentials (401)', async () => {
      mockFetch([])

      const app = makeApp(makeEnv(), () => undefined)
      const res = await app(new Request(`https://id.org.ai/api/orgs/${ORG}/members`))

      expect(res.status).toBe(401)
    })
  })

  describe('the dashboard round-trip would now work end-to-end', () => {
    // Smoke: this is the exact shape the saas.studio Members panel hits via
    // IDORGAI_API_BASE + IDORGAI_ORG_TOKEN. If this passes, setting the env
    // vars unlocks the panel.
    it('IDORGAI_ORG_TOKEN (sk_*) → /api/orgs/:id/members → member DTO', async () => {
      mockFetch([
        workosKeyValidation(),
        {
          match: (url) => url.includes('/organization_memberships') && url.includes('organization_id='),
          res: () =>
            jsonResponse({
              data: [
                { id: 'om_1', user_id: 'u_1', organization_id: ORG, role: { slug: 'owner' }, status: 'active', created_at: 't', updated_at: 't' },
                { id: 'om_2', user_id: 'u_2', organization_id: ORG, role: { slug: 'editor' }, status: 'active', created_at: 't', updated_at: 't' },
              ],
            }),
        },
        {
          match: (url) => url.includes('/invitations') && url.includes('organization_id='),
          res: () => jsonResponse({ data: [] }),
        },
        {
          match: (url) => url === 'https://api.workos.com/user_management/users/u_1',
          res: () => jsonResponse({ id: 'u_1', email: 'owner@x.com', first_name: 'Owner' }),
        },
        {
          match: (url) => url === 'https://api.workos.com/user_management/users/u_2',
          res: () => jsonResponse({ id: 'u_2', email: 'dev@x.com', first_name: 'Dev' }),
        },
      ])

      const app = makeApp(makeEnv(), () => emptyStub())
      const res = await app(req(`/api/orgs/${ORG}/members`))

      expect(res.status).toBe(200)
      const body = (await res.json()) as { members: any[] }
      expect(body.members).toHaveLength(2)
      // dtoToMember keys: id | sub, name | display_name, email | sub, role, status, joined_at.
      for (const m of body.members) {
        expect(m).toHaveProperty('id')
        expect(m).toHaveProperty('sub')
        expect(m).toHaveProperty('email')
        expect(m).toHaveProperty('role')
        expect(m).toHaveProperty('status', 'active')
      }
    })
  })
})
