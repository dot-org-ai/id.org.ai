/**
 * Authorization claims on opaque tokens (beads ui-lzpz.18).
 *
 * Opaque device-flow / CLI access tokens carry no payload. Before this change
 * GET /oauth/userinfo returned only { sub, name, email, email_verified,
 * org_id } while the session JWT (worker/routes/auth.ts) carried `roles`,
 * `permissions`, `org {id,name,domains}` and `platformRole`. A relying party
 * such as sdb's operator guard could therefore gate an opaque token only on
 * org membership or a subject allowlist.
 *
 * Two layers, matching the neighbouring route tests:
 *
 *   1. worker/routes/oauth.ts mounted directly with a mocked IdentityDO stub
 *      (same shape as oauth-routes-trusted-account.test.ts) — proves the
 *      userinfo route and provider.handleIntrospect surface the persisted
 *      snapshot and derive `platformRole` from PLATFORM_ORG_ID.
 *
 *   2. Real worker via SELF + real IdentityDO (same shape as
 *      auth-callback-device-flow-regression.test.ts) — proves /api/callback
 *      persists roles/permissions/org from the WorkOS auth result onto the
 *      identity record, and that a later opaque token reads them back.
 */
import { describe, it, expect, beforeEach, beforeAll, afterAll, vi } from 'vitest'
import { Hono } from 'hono'
import { SELF, fetchMock, env as workerEnv } from 'cloudflare:test'
import { oauthRoutes, toIdentityInfo } from '../worker/routes/oauth'
import type { Env, Variables } from '../worker/types'
import type { IdentityStub } from '../src/server/do/Identity'

// ─── Layer 1: mounted route with mocked stub ────────────────────────────────

type StoredIdentity = {
  id: string
  name?: string
  email?: string
  verified?: boolean
  level?: number
  organizationId?: string
  organizationName?: string
  organizationDomains?: string[]
  roles?: string[]
  permissions?: string[]
}

const PLATFORM_ORG = 'org_platform_test'

function createMockEnv(): { env: Env; oauthStore: Map<string, unknown>; identities: Map<string, StoredIdentity> } {
  const oauthStore = new Map<string, unknown>()
  const identities = new Map<string, StoredIdentity>([
    [
      'human:operator',
      {
        id: 'human:operator',
        name: 'Org Operator',
        email: 'operator@example.com',
        verified: true,
        level: 2,
        organizationId: PLATFORM_ORG,
        organizationName: 'Platform Org',
        organizationDomains: ['example.com'],
        roles: ['admin', 'operator'],
        permissions: ['sdb:operate', 'sdb:read'],
      },
    ],
    [
      'human:member',
      {
        id: 'human:member',
        name: 'Tenant Member',
        email: 'member@example.com',
        verified: true,
        level: 2,
        organizationId: 'org_tenant',
        organizationName: 'Tenant Org',
        roles: ['viewer'],
        permissions: ['sdb:read'],
      },
    ],
    ['human:legacy', { id: 'human:legacy', name: 'Legacy', email: 'legacy@example.com', verified: false, level: 1 }],
  ])

  const stub: Partial<IdentityStub> = {
    getIdentity: vi.fn(async (id: string) => (identities.get(id) ?? null) as never),
    ensureCliClient: vi.fn(async () => {}),
    ensureOAuthDoClient: vi.fn(async () => {}),
    ensureWebClients: vi.fn(async () => {}),
    oauthStorageOp: vi.fn(async (op: { op: string; key?: string; value?: unknown; options?: { prefix?: string } }) => {
      if (op.op === 'get' && op.key) return { value: oauthStore.get(op.key) }
      if (op.op === 'put' && op.key) {
        oauthStore.set(op.key, op.value)
        return { ok: true }
      }
      if (op.op === 'delete' && op.key) return { deleted: oauthStore.delete(op.key) }
      if (op.op === 'list') {
        const entries: Array<[string, unknown]> = []
        for (const [k, v] of oauthStore) {
          if (op.options?.prefix && !k.startsWith(op.options.prefix)) continue
          entries.push([k, v])
        }
        return { entries }
      }
      return {}
    }),
  }

  const env: Env = {
    IDENTITY: {
      idFromName: () => ({ toString: () => 'mock-id' } as unknown as DurableObjectId),
      get: () => stub as unknown as DurableObjectStub,
    } as unknown as DurableObjectNamespace,
    SESSIONS: {} as KVNamespace,
    AUTH_SECRET: 'test-secret',
    JWKS_SECRET: 'test-jwks-secret',
    PLATFORM_ORG_ID: PLATFORM_ORG,
  }
  return { env, oauthStore, identities }
}

function mountApp() {
  const app = new Hono<{ Bindings: Env; Variables: Variables }>()
  app.route('', oauthRoutes)
  return app
}

async function seedAccessToken(oauthStore: Map<string, unknown>, token: string, identityId: string, overrides: Record<string, unknown> = {}) {
  oauthStore.set(`access:${token}`, {
    token,
    clientId: 'rpc_do_cli',
    identityId,
    scopes: ['openid', 'profile', 'email', 'offline_access'],
    createdAt: Date.now(),
    expiresAt: Date.now() + 3600_000,
    ...overrides,
  })
}

describe('GET /oauth/userinfo — authorization claims for opaque tokens', () => {
  let env: Env
  let oauthStore: Map<string, unknown>

  beforeEach(() => {
    ;({ env, oauthStore } = createMockEnv())
  })

  it('returns roles, permissions, org {id,name,domains} and platformRole beside the standard OIDC claims', async () => {
    await seedAccessToken(oauthStore, 'at_operator', 'human:operator')
    const res = await mountApp().fetch(new Request('https://id.org.ai/oauth/userinfo', { headers: { authorization: 'Bearer at_operator' } }), env)
    expect(res.status).toBe(200)
    const d = (await res.json()) as Record<string, unknown>
    // Standard claims stay
    expect(d.sub).toBe('human:operator')
    expect(d.name).toBe('Org Operator')
    expect(d.email).toBe('operator@example.com')
    expect(d.email_verified).toBe(true)
    expect(d.org_id).toBe(PLATFORM_ORG)
    // Same claims as the session JWT
    expect(d.org).toEqual({ id: PLATFORM_ORG, name: 'Platform Org', domains: ['example.com'] })
    expect(d.roles).toEqual(['admin', 'operator'])
    expect(d.permissions).toEqual(['sdb:operate', 'sdb:read'])
    expect(d.platformRole).toBe('superadmin')
  })

  it('does not grant platformRole to a member of a non-platform org', async () => {
    await seedAccessToken(oauthStore, 'at_member', 'human:member')
    const res = await mountApp().fetch(new Request('https://id.org.ai/oauth/userinfo', { headers: { authorization: 'Bearer at_member' } }), env)
    const d = (await res.json()) as Record<string, unknown>
    expect(d.org).toEqual({ id: 'org_tenant', name: 'Tenant Org' })
    expect(d.roles).toEqual(['viewer'])
    expect(d.permissions).toEqual(['sdb:read'])
    expect(d).not.toHaveProperty('platformRole')
  })

  it('leaves a legacy identity (no login snapshot) exactly as before', async () => {
    await seedAccessToken(oauthStore, 'at_legacy', 'human:legacy')
    const res = await mountApp().fetch(new Request('https://id.org.ai/oauth/userinfo', { headers: { authorization: 'Bearer at_legacy' } }), env)
    const d = (await res.json()) as Record<string, unknown>
    expect(d).toEqual({ sub: 'human:legacy', name: 'Legacy', email: 'legacy@example.com', email_verified: false })
  })

  it('still rejects expired and unknown tokens', async () => {
    await seedAccessToken(oauthStore, 'at_expired', 'human:operator', { expiresAt: Date.now() - 1 })
    const expired = await mountApp().fetch(new Request('https://id.org.ai/oauth/userinfo', { headers: { authorization: 'Bearer at_expired' } }), env)
    expect(expired.status).toBe(401)
    const unknown = await mountApp().fetch(new Request('https://id.org.ai/oauth/userinfo', { headers: { authorization: 'Bearer at_nope' } }), env)
    expect(unknown.status).toBe(401)
  })
})

describe('POST /oauth/introspect — authorization claims for opaque tokens', () => {
  let env: Env
  let oauthStore: Map<string, unknown>

  beforeEach(() => {
    ;({ env, oauthStore } = createMockEnv())
  })

  function introspect(token: string) {
    return mountApp().fetch(
      new Request('https://id.org.ai/oauth/introspect', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token }),
      }),
      env,
    )
  }

  it('returns the same claims the session JWT carries, with platformRole derived from PLATFORM_ORG_ID', async () => {
    await seedAccessToken(oauthStore, 'at_operator', 'human:operator')
    const d = (await (await introspect('at_operator')).json()) as Record<string, unknown>
    expect(d.active).toBe(true)
    expect(d.client_id).toBe('rpc_do_cli')
    expect(d.sub).toBe('human:operator')
    expect(d.token_type).toBe('Bearer')
    expect(d.tier).toBe('L2')
    expect(d.org_id).toBe(PLATFORM_ORG)
    expect(d.org).toEqual({ id: PLATFORM_ORG, name: 'Platform Org', domains: ['example.com'] })
    expect(d.roles).toEqual(['admin', 'operator'])
    expect(d.permissions).toEqual(['sdb:operate', 'sdb:read'])
    expect(d.platformRole).toBe('superadmin')
  })

  it('does not grant platformRole outside the platform org', async () => {
    await seedAccessToken(oauthStore, 'at_member', 'human:member')
    const d = (await (await introspect('at_member')).json()) as Record<string, unknown>
    expect(d.active).toBe(true)
    expect(d.roles).toEqual(['viewer'])
    expect(d).not.toHaveProperty('platformRole')
  })

  it('active=false for an unknown token, with no claims', async () => {
    const d = (await (await introspect('at_nope')).json()) as Record<string, unknown>
    expect(d).toEqual({ active: false })
  })
})

describe('toIdentityInfo', () => {
  it('sets platformRole only when organizationId matches PLATFORM_ORG_ID', () => {
    const base = { id: 'x', name: 'x', organizationId: 'org_a', roles: ['admin'] }
    expect(toIdentityInfo({ PLATFORM_ORG_ID: 'org_a' }, base).platformRole).toBe('superadmin')
    expect(toIdentityInfo({ PLATFORM_ORG_ID: 'org_b' }, base).platformRole).toBeUndefined()
    expect(toIdentityInfo({}, base).platformRole).toBeUndefined()
    expect(toIdentityInfo({ PLATFORM_ORG_ID: 'org_a' }, { id: 'y', name: 'y' }).platformRole).toBeUndefined()
  })
})

// ─── Layer 2: real worker + real IdentityDO — login persists the snapshot ───

const BASE = 'https://id.org.ai'
const WORKOS_USER_ID = 'user_01CLAIMSTEST'
// PLATFORM_ORG_ID from worker/wrangler.jsonc vars — logging in under it must
// yield platformRole: 'superadmin' on the opaque-token surfaces too.
const WRANGLER_PLATFORM_ORG = (workerEnv as unknown as Env).PLATFORM_ORG_ID!

function b64url(s: string): string {
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

/** WorkOS access_token shape: roles/permissions/org_id live in the JWT payload. */
function fakeWorkOSAccessToken(payload: Record<string, unknown>): string {
  return `${b64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }))}.${b64url(JSON.stringify(payload))}.sig`
}

describe('/api/callback persists roles/permissions/org onto the identity; opaque tokens read them back', () => {
  beforeAll(() => {
    fetchMock.activate()
    fetchMock.disableNetConnect()

    fetchMock
      .get('https://api.workos.com')
      .intercept({ method: 'POST', path: '/user_management/authenticate' })
      .reply(
        200,
        JSON.stringify({
          access_token: fakeWorkOSAccessToken({
            sub: WORKOS_USER_ID,
            org_id: WRANGLER_PLATFORM_ORG,
            role: 'admin',
            roles: ['operator'],
            permissions: ['sdb:operate', 'sdb:read'],
          }),
          refresh_token: 'rt_test_refresh_token',
          user: { id: WORKOS_USER_ID, email: 'claims@example.com', first_name: 'Claims', last_name: 'Tester' },
          organization_id: WRANGLER_PLATFORM_ORG,
        }),
        { headers: { 'content-type': 'application/json' } },
      )
      .persist()

    // Profile lookup: null-fallback path.
    fetchMock
      .get('https://api.workos.com')
      .intercept({ path: /^\/user_management\/users\// })
      .reply(500, '')
      .persist()
    // Org info: the JWT's `org {name, domains}` is sourced from here.
    fetchMock
      .get('https://api.workos.com')
      .intercept({ path: new RegExp(`^/organizations/${WRANGLER_PLATFORM_ORG}`) })
      .reply(200, JSON.stringify({ id: WRANGLER_PLATFORM_ORG, name: 'Platform Org', domains: [{ domain: 'example.com', state: 'verified' }] }), {
        headers: { 'content-type': 'application/json' },
      })
      .persist()
  })

  afterAll(() => {
    fetchMock.deactivate()
  })

  it('login → identity record → /oauth/userinfo and /oauth/introspect carry the JWT claims', async () => {
    // Login round-trip (same shape as auth-callback-device-flow-regression).
    const loginRes = await SELF.fetch(`${BASE}/login?provider=GitHubOAuth&continue=${encodeURIComponent(`${BASE}/`)}`, { redirect: 'manual' })
    expect(loginRes.status).toBe(302)
    const state = new URL(loginRes.headers.get('location')!).searchParams.get('state')!
    const cbRes = await SELF.fetch(`${BASE}/api/callback?code=01CLAIMSCODE&state=${encodeURIComponent(state)}`, { redirect: 'manual' })
    expect(cbRes.status).toBe(302)

    // The identity record now holds the snapshot the JWT was signed from.
    const identityId = `human:${WORKOS_USER_ID}`
    const idEnv = workerEnv as unknown as Env
    const identityStub = idEnv.IDENTITY.get(idEnv.IDENTITY.idFromName(identityId)) as unknown as IdentityStub
    const identity = await identityStub.getIdentity(identityId)
    expect(identity).not.toBeNull()
    expect(identity!.organizationId).toBe(WRANGLER_PLATFORM_ORG)
    expect(identity!.organizationName).toBe('Platform Org')
    expect(identity!.organizationDomains).toEqual(['example.com'])
    // extractRolesFromToken: `role` is appended to `roles`
    expect(identity!.roles).toEqual(['operator', 'admin'])
    expect(identity!.permissions).toEqual(['sdb:operate', 'sdb:read'])

    // Mint an opaque access token in the oauth shard bound to that identity.
    const oauthStub = idEnv.IDENTITY.get(idEnv.IDENTITY.idFromName('oauth')) as unknown as IdentityStub
    await oauthStub.oauthStorageOp({
      op: 'put',
      key: 'access:at_claims_e2e',
      value: {
        token: 'at_claims_e2e',
        clientId: 'rpc_do_cli',
        identityId,
        scopes: ['openid', 'profile', 'email', 'offline_access'],
        createdAt: Date.now(),
        expiresAt: Date.now() + 3600_000,
      },
    })

    const ui = (await (await SELF.fetch(`${BASE}/oauth/userinfo`, { headers: { authorization: 'Bearer at_claims_e2e' } })).json()) as Record<string, unknown>
    expect(ui.sub).toBe(identityId)
    expect(ui.email).toBe('claims@example.com')
    expect(ui.org_id).toBe(WRANGLER_PLATFORM_ORG)
    expect(ui.org).toEqual({ id: WRANGLER_PLATFORM_ORG, name: 'Platform Org', domains: ['example.com'] })
    expect(ui.roles).toEqual(['operator', 'admin'])
    expect(ui.permissions).toEqual(['sdb:operate', 'sdb:read'])
    expect(ui.platformRole).toBe('superadmin')

    const ir = (await (
      await SELF.fetch(`${BASE}/oauth/introspect`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token: 'at_claims_e2e' }),
      })
    ).json()) as Record<string, unknown>
    expect(ir.active).toBe(true)
    expect(ir.sub).toBe(identityId)
    expect(ir.org).toEqual({ id: WRANGLER_PLATFORM_ORG, name: 'Platform Org', domains: ['example.com'] })
    expect(ir.roles).toEqual(['operator', 'admin'])
    expect(ir.permissions).toEqual(['sdb:operate', 'sdb:read'])
    expect(ir.platformRole).toBe('superadmin')
  })

  it('advertises the authorization claims in OpenID discovery', async () => {
    const d = (await (await SELF.fetch(`${BASE}/.well-known/openid-configuration`)).json()) as { claims_supported: string[] }
    for (const claim of ['sub', 'email', 'email_verified', 'org_id', 'org', 'roles', 'permissions', 'platformRole']) {
      expect(d.claims_supported).toContain(claim)
    }
  })
})
