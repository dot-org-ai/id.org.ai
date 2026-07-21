/**
 * POST /api/keys route hardening (ax-e6b.17.2) — the ISSUANCE surface.
 *
 * FINDING 1: minting requires explicit issuance authority (`keys:issue` /
 *            `admin`), not bare authentication; the caller's own identity is
 *            threaded into the mint as the narrowing ceiling.
 * FINDING 4: a structured `scope` on a WorkOS-backed tenant is rejected 400
 *            (scope-shaped keys are a native-key primitive).
 *
 * Drives the Hono sub-app directly via app.fetch, attaching identity/auth/stub
 * through a Variables-setting middleware — the miniature of the production
 * wiring where authenticateRequest runs first.
 */
import { describe, it, expect, vi } from 'vitest'
import { Hono } from 'hono'
import { apiKeyRoutes } from '../worker/routes/api-keys'
import type { Env, Variables } from '../worker/types'
import type { Identity, IdentityStub } from '../src/sdk/types'
import type { MCPAuthResult } from '../src/sdk/mcp/auth'
import type { Scope } from '../src/sdk/auth/scope'

function makeIdentity(overrides: Partial<Identity> = {}): Identity {
  return {
    id: 'usr_1',
    type: 'human',
    name: 'issuer',
    verified: true,
    level: 2,
    claimStatus: 'claimed',
    scopes: ['read', 'write', 'admin'],
    ...overrides,
  } as Identity
}

function makeAuth(overrides: Partial<MCPAuthResult> = {}): MCPAuthResult {
  return {
    authenticated: true,
    identityId: 'usr_1',
    level: 2,
    scopes: ['read', 'write', 'admin'],
    capabilities: [],
    ...overrides,
  } as MCPAuthResult
}

function makeStub(overrides: Partial<IdentityStub> = {}): IdentityStub {
  return {
    createApiKey: vi.fn(async (data: any) => ({
      id: 'key_1',
      key: 'hly_sk_generated',
      name: data.name,
      prefix: 'hly_sk_generat',
      scopes: data.scopes ?? ['read', 'write'],
      scope: data.scope,
      createdAt: new Date().toISOString(),
    })),
    listApiKeys: vi.fn(async () => []),
    revokeApiKey: vi.fn(async () => null),
    oauthStorageOp: vi.fn(async () => ({ value: null })),
    ...overrides,
  } as unknown as IdentityStub
}

function makeApp(deps: {
  identity?: Identity | null
  auth?: MCPAuthResult | null
  stub?: IdentityStub | null
  env?: Partial<Env>
}) {
  const app = new Hono<{ Bindings: Env; Variables: Variables }>()
  app.use('*', async (c, next) => {
    if (deps.identity !== null) c.set('identity', (deps.identity ?? makeIdentity()) as never)
    if (deps.auth !== null) c.set('auth', (deps.auth ?? makeAuth()) as never)
    if (deps.stub !== null) c.set('identityStub', (deps.stub ?? makeStub()) as never)
    await next()
  })
  app.route('', apiKeyRoutes)
  return app
}

function post(app: Hono<any>, body: unknown, env: Partial<Env> = {}) {
  // Minimal SESSIONS KV shim — the native-key path writes an apikey→identity
  // routing entry after minting.
  const sessions = { put: vi.fn(async () => {}), delete: vi.fn(async () => {}), get: vi.fn(async () => null) }
  return app.fetch(
    new Request('https://id.org.ai/api/keys', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }),
    { SESSIONS: sessions, ...env } as unknown as Env,
  )
}

describe('POST /api/keys — FINDING 1: issuance capability required', () => {
  it('403 when the caller lacks keys:issue / admin (bare authentication is not enough)', async () => {
    const app = makeApp({
      identity: makeIdentity({ scopes: ['read', 'write'] }),
      auth: makeAuth({ scopes: ['read', 'write'] }),
    })
    const res = await post(app, { name: 'k' })
    expect(res.status).toBe(403)
  })

  it('mints when the caller holds admin, threading the caller authority', async () => {
    const stub = makeStub()
    const app = makeApp({ stub })
    const res = await post(app, { name: 'k', scopes: ['read'] })
    expect(res.status).toBe(201)
    // The caller identity was threaded into the mint as the narrowing ceiling.
    const call = (stub.createApiKey as any).mock.calls[0][0]
    expect(call.caller).toBeDefined()
    expect(call.caller.flatScopes).toEqual(['read', 'write', 'admin'])
  })

  it('mints when the caller holds keys:issue', async () => {
    const app = makeApp({
      identity: makeIdentity({ scopes: ['read', 'keys:issue'] }),
      auth: makeAuth({ scopes: ['read', 'keys:issue'] }),
    })
    const res = await post(app, { name: 'k', scopes: ['read'] })
    expect(res.status).toBe(201)
  })
})

describe('POST /api/keys — FINDING 4: structured scope rejected on WorkOS tenants', () => {
  const structured: Scope = { grants: [{ verb: 'read', resource: 'listings/*' }] }

  it('400 when WORKOS_API_KEY is set and the body carries a structured scope', async () => {
    const app = makeApp({})
    const res = await post(app, { name: 'k', scope: structured }, { WORKOS_API_KEY: 'sk_test_workos' })
    expect(res.status).toBe(400)
    const body = (await res.json()) as Record<string, unknown>
    expect(String(body.error_description)).toContain('native-key primitive')
  })

  it('does not reject a flat-scope WorkOS key (no structured scope present)', async () => {
    // With no structured scope, the WorkOS path proceeds (createWorkOSApiKey is
    // exercised; here it will throw on the fake key → 500, NOT the 400 guard).
    const app = makeApp({})
    const res = await post(app, { name: 'k', scopes: ['read'] }, { WORKOS_API_KEY: 'sk_test_workos' })
    expect(res.status).not.toBe(400)
  })
})
