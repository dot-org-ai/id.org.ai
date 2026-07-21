/**
 * Vault tenant-isolation route tests (ax-e6b.17.4 — SECURITY).
 *
 * These tests exercise the REAL `authenticateRequest` middleware (the one
 * `worker/index.ts` mounts on `/vault/*` in production), NOT a hand-rolled
 * `app.use('*')` that stamps `c.get('auth')` directly. The harness mounts the
 * chain EXACTLY as prod does:
 *
 *     app.use('*', <set identityStub>)     // ← identityStubMiddleware in prod
 *     app.use('/vault/*', authenticateRequest)
 *     app.route('', workosRoutes)
 *
 * `authenticateRequest` is what resolves the caller's tenant and populates
 * `c.get('auth')`. If the production mount (`app.use('/vault/*', authenticateRequest)`
 * in worker/index.ts) were removed, `c.get('auth')` would be undefined for every
 * vault request and the OWNER happy-path below would 401 — so these tests fail
 * loudly if the vault is not actually behind the auth middleware.
 *
 * Per-tenant auth is minted the real way: an `oai_*` API key whose stub returns
 * an Identity carrying that tenant's `tenantId`, driven through the broker inside
 * `authenticateRequest`. Two distinct tenants, A and B, exercise isolation:
 *
 *   - A creates a secret and can list / get / reveal / resolve / delete it.
 *   - B CANNOT list, get, reveal, resolve, or delete A's secret — every path
 *     returns 404 and never A's plaintext.
 *   - An unauthenticated caller gets 401 (NOT 503, NOT 200).
 *   - Missing WORKOS_API_KEY yields 503 (config error), distinct from 401.
 *
 * The WorkOS Vault HTTP surface is faked in-memory so the routes drive real
 * fetch calls; the oai_* auth path makes no fetch (DO/stub only).
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { Hono } from 'hono'
import { authenticateRequest } from '../worker/middleware/auth'
import { workosRoutes } from '../worker/routes/workos'
import type { Env, Variables } from '../worker/types'
import type { IdentityStub } from '../src/server/do/Identity'

const TENANT_A = 'tenant_a'
const TENANT_B = 'tenant_b'

// ── In-memory fake of the WorkOS Vault HTTP surface ────────────────────────
type FakeSecret = {
  id: string
  name: string
  value: string
  description?: string
  environment: string
  created_at: string
  updated_at: string
}

const store = new Map<string, FakeSecret>()
let idCounter = 0

function stripValue(s: FakeSecret): Omit<FakeSecret, 'value'> {
  const { value: _v, ...rest } = s
  return rest
}

function jsonResp(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function fakeVaultFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const url = typeof input === 'string' ? input : input.toString()
  const method = (init?.method ?? 'GET').toUpperCase()
  const u = new URL(url)
  const path = u.pathname

  if (path === '/vault/v1/secrets' && method === 'GET') {
    const limit = Number(u.searchParams.get('limit') ?? '100')
    const after = u.searchParams.get('after') ?? undefined
    const all = [...store.values()]
    let start = 0
    if (after) {
      const idx = all.findIndex((s) => s.id === after)
      start = idx === -1 ? all.length : idx + 1
    }
    const page = all.slice(start, start + limit)
    const hasMore = start + limit < all.length
    const nextCursor = hasMore ? page[page.length - 1]?.id : undefined
    return Promise.resolve(jsonResp(200, { data: page.map(stripValue), list_metadata: { after: nextCursor } }))
  }

  if (path === '/vault/v1/secrets' && method === 'POST') {
    const body = JSON.parse(String(init!.body)) as { name: string; value: string; description?: string; environment?: string }
    const id = `secret_${++idCounter}`
    const now = new Date().toISOString()
    const secret: FakeSecret = {
      id,
      name: body.name,
      value: body.value,
      description: body.description,
      environment: body.environment ?? 'production',
      created_at: now,
      updated_at: now,
    }
    store.set(id, secret)
    return Promise.resolve(jsonResp(201, stripValue(secret)))
  }

  const matchById = path.match(/^\/vault\/v1\/secrets\/(secret_[^/]+)(?:\/(.+))?$/)
  if (matchById) {
    const [, id, suffix] = matchById
    const secret = store.get(id)
    if (!secret) return Promise.resolve(jsonResp(404, { error: 'not found' }))

    if (method === 'GET' && suffix === 'reveal') return Promise.resolve(jsonResp(200, secret))
    if (method === 'GET' && !suffix) return Promise.resolve(jsonResp(200, stripValue(secret)))
    if (method === 'PUT' && !suffix) {
      const body = JSON.parse(String(init!.body)) as { value?: string; description?: string }
      if (body.value !== undefined) secret.value = body.value
      if (body.description !== undefined) secret.description = body.description
      secret.updated_at = new Date().toISOString()
      return Promise.resolve(jsonResp(200, stripValue(secret)))
    }
    if (method === 'DELETE' && !suffix) {
      store.delete(id)
      return Promise.resolve(new Response(null, { status: 204 }))
    }
  }

  return Promise.resolve(jsonResp(404, { error: `not handled: ${method} ${path}` }))
}

// ── Real per-tenant auth via the broker ────────────────────────────────────
// Each tenant is fronted by an `oai_*` API key. The stub returns an Identity
// carrying that tenant's `tenantId`, which the broker inside authenticateRequest
// hydrates and MCPAuth.fromIdentity surfaces as `auth.tenantId` — exactly the
// field resolveVaultTenant reads. No fetch is involved in this path.
function keyForTenant(tenant: string): string {
  return `oai_${tenant}_key`
}

function stubForTenant(tenant: string): IdentityStub {
  return {
    validateApiKey: vi.fn(async () => ({ valid: true, identityId: `id_${tenant}`, level: 2 as const, scopes: ['read', 'write'] })),
    getSession: vi.fn(async () => ({ valid: false })),
    getIdentity: vi.fn(async (id: string) => ({
      id,
      type: 'agent' as const,
      name: `agent-${tenant}`,
      tenantId: tenant,
      verified: true,
      level: 2 as const,
      claimStatus: 'claimed' as const,
      scopes: ['read', 'write'],
    })),
    getAgent: vi.fn(async () => null),
    touchAgent: vi.fn(async () => {}),
    checkRateLimit: vi.fn(async () => ({ allowed: true, remaining: 99, resetAt: Date.now() + 60_000 })),
    oauthStorageOp: vi.fn(async () => ({ value: undefined })),
  } as unknown as IdentityStub
}

/**
 * Resolve the identityStub the way `identityStubMiddleware` does in prod:
 * from the presented credential. An unknown/absent credential yields no stub —
 * authenticateRequest then produces an anonymous result → the vault routes 401.
 */
function stubProvider(req: Request): IdentityStub | undefined {
  const auth = req.headers.get('authorization')
  if (!auth?.startsWith('Bearer ')) return undefined
  const key = auth.slice('Bearer '.length)
  if (key === keyForTenant(TENANT_A)) return stubForTenant(TENANT_A)
  if (key === keyForTenant(TENANT_B)) return stubForTenant(TENANT_B)
  return undefined
}

// ── App harness — mounts the REAL authenticateRequest exactly as prod ───────
function makeEnv(overrides: Partial<Env> = {}): Env {
  return { WORKOS_API_KEY: 'sk_platform_secret', WORKOS_CLIENT_ID: 'client_test', ...overrides } as Env
}

function makeApp(env: Env) {
  const app = new Hono<{ Bindings: Env; Variables: Variables }>()
  // Stand-in for identityStubMiddleware (reads the credential from KV in prod).
  app.use('*', async (c, next) => {
    const stub = stubProvider(c.req.raw)
    if (stub) c.set('identityStub', stub)
    await next()
  })
  // The production mount under test (worker/index.ts).
  app.use('/vault/*', authenticateRequest)
  app.route('', workosRoutes)
  return (req: Request) => app.fetch(req, env)
}

function req(tenant: string | null, path: string, init: RequestInit = {}): Request {
  const headers = new Headers(init.headers)
  if (tenant) headers.set('authorization', `Bearer ${keyForTenant(tenant)}`)
  return new Request(`https://id.org.ai${path}`, { ...init, headers })
}

function jbody(obj: unknown): RequestInit {
  return { headers: { 'content-type': 'application/json' }, body: JSON.stringify(obj) }
}

let fetchApp: (req: Request) => Promise<Response>

beforeEach(() => {
  store.clear()
  idCounter = 0
  vi.stubGlobal('fetch', vi.fn(fakeVaultFetch))
  fetchApp = makeApp(makeEnv())
})

afterEach(() => vi.restoreAllMocks())

async function createSecret(tenant: string, name: string, value: string): Promise<{ status: number; id: string }> {
  const res = await fetchApp(req(tenant, '/vault/secrets', { method: 'POST', ...jbody({ name, value }) }))
  const body = (await res.json().catch(() => ({}))) as { id?: string }
  return { status: res.status, id: body.id ?? '' }
}

// ============================================================================
// Auth gate — driven by the REAL authenticateRequest
// ============================================================================

describe('vault routes — auth is required via authenticateRequest (401, not 503, not 200)', () => {
  it('POST /vault/secrets rejects an unauthenticated caller with 401', async () => {
    const res = await fetchApp(req(null, '/vault/secrets', { method: 'POST', ...jbody({ name: 'K', value: 'v' }) }))
    expect(res.status).toBe(401)
    // Nothing was written.
    expect(store.size).toBe(0)
  })

  it('GET /vault/secrets rejects an unauthenticated caller with 401', async () => {
    const res = await fetchApp(req(null, '/vault/secrets'))
    expect(res.status).toBe(401)
  })

  it('POST /vault/resolve rejects an unauthenticated caller with 401', async () => {
    const res = await fetchApp(req(null, '/vault/resolve', { method: 'POST', ...jbody({ name: 'K' }) }))
    expect(res.status).toBe(401)
  })

  it('a presented-but-unknown credential 401s (broker → anonymous → 401)', async () => {
    const res = await fetchApp(
      new Request('https://id.org.ai/vault/secrets', { headers: { authorization: 'Bearer oai_unknown_key' } }),
    )
    expect(res.status).toBe(401)
  })

  it('still returns 503 (not 401) when WORKOS_API_KEY is missing, even authenticated', async () => {
    const app = makeApp(makeEnv({ WORKOS_API_KEY: undefined }))
    const res = await app(req(TENANT_A, '/vault/secrets'))
    expect(res.status).toBe(503)
  })
})

// ============================================================================
// Owner (tenant A) happy path — fails if authenticateRequest is not applied
// ============================================================================

describe('vault routes — owner can manage its own secrets', () => {
  it('A creates, lists, gets, reveals, resolves, and deletes its own secret', async () => {
    const created = await createSecret(TENANT_A, 'STRIPE_KEY', 'sk_a_value')
    expect(created.status).toBe(201)
    expect(created.id).toMatch(/^secret_/)

    // list
    const listRes = await fetchApp(req(TENANT_A, '/vault/secrets'))
    expect(listRes.status).toBe(200)
    const list = (await listRes.json()) as { data: Array<{ name: string }> }
    expect(list.data.map((s) => s.name)).toEqual(['STRIPE_KEY'])

    // get by id
    const getRes = await fetchApp(req(TENANT_A, `/vault/secrets/${created.id}`))
    expect(getRes.status).toBe(200)
    const meta = (await getRes.json()) as { name: string; value?: string }
    expect(meta.name).toBe('STRIPE_KEY')
    expect(meta.value).toBeUndefined()

    // reveal
    const revealRes = await fetchApp(req(TENANT_A, `/vault/secrets/${created.id}/reveal`))
    expect(revealRes.status).toBe(200)
    const revealed = (await revealRes.json()) as { value: string }
    expect(revealed.value).toBe('sk_a_value')

    // resolve within tenant
    const resolveRes = await fetchApp(req(TENANT_A, '/vault/resolve', { method: 'POST', ...jbody({ name: 'STRIPE_KEY' }) }))
    expect(resolveRes.status).toBe(200)
    expect((await resolveRes.json()) as { resolved: boolean }).toMatchObject({ resolved: true })

    // delete
    const delRes = await fetchApp(req(TENANT_A, `/vault/secrets/${created.id}`, { method: 'DELETE' }))
    expect(delRes.status).toBe(200)
    expect(store.size).toBe(0)
  })
})

// ============================================================================
// Cross-tenant isolation — B cannot touch A's secret
// ============================================================================

describe('vault routes — cross-tenant isolation (B cannot reach A)', () => {
  let aId = ''
  beforeEach(async () => {
    const created = await createSecret(TENANT_A, 'STRIPE_KEY', 'sk_a_value')
    aId = created.id
  })

  it("B does NOT see A's secret in its list", async () => {
    const res = await fetchApp(req(TENANT_B, '/vault/secrets'))
    expect(res.status).toBe(200)
    const body = (await res.json()) as { data: unknown[] }
    expect(body.data).toEqual([])
  })

  it("B cannot GET A's secret by id (404, no metadata)", async () => {
    const res = await fetchApp(req(TENANT_B, `/vault/secrets/${aId}`))
    expect(res.status).toBe(404)
    expect(JSON.stringify(await res.json())).not.toContain('STRIPE_KEY')
  })

  it("B cannot REVEAL A's secret (404, never the plaintext)", async () => {
    const res = await fetchApp(req(TENANT_B, `/vault/secrets/${aId}/reveal`))
    expect(res.status).toBe(404)
    expect(JSON.stringify(await res.json())).not.toContain('sk_a_value')
  })

  it("B cannot UPDATE A's secret (404) and A's value is untouched", async () => {
    const res = await fetchApp(req(TENANT_B, `/vault/secrets/${aId}`, { method: 'PUT', ...jbody({ value: 'hacked' }) }))
    expect(res.status).toBe(404)
    expect(store.get(aId)?.value).toBe('sk_a_value')
  })

  it("B cannot DELETE A's secret (404) and A's secret survives", async () => {
    const res = await fetchApp(req(TENANT_B, `/vault/secrets/${aId}`, { method: 'DELETE' }))
    expect(res.status).toBe(404)
    expect(store.has(aId)).toBe(true)
    expect(store.get(aId)?.value).toBe('sk_a_value')
  })

  it("B cannot RESOLVE A's secret name (404, resolved:false)", async () => {
    const res = await fetchApp(req(TENANT_B, '/vault/resolve', { method: 'POST', ...jbody({ name: 'STRIPE_KEY' }) }))
    expect(res.status).toBe(404)
    const body = (await res.json()) as { resolved: boolean }
    expect(body.resolved).toBe(false)
    expect(JSON.stringify(body)).not.toContain('sk_a_value')
  })

  it("batch resolve for B lists A's name as missing, never resolved", async () => {
    const res = await fetchApp(req(TENANT_B, '/vault/resolve', { method: 'POST', ...jbody({ names: ['STRIPE_KEY'] }) }))
    expect(res.status).toBe(200)
    const body = (await res.json()) as { resolved: string[]; missing: string[] }
    expect(body.resolved).toEqual([])
    expect(body.missing).toEqual(['STRIPE_KEY'])
  })

  it('same secret name across tenants does not collide — each resolves its own value', async () => {
    await createSecret(TENANT_B, 'STRIPE_KEY', 'sk_b_value')

    const aReveal = await fetchApp(req(TENANT_A, `/vault/secrets/${aId}/reveal`))
    expect(((await aReveal.json()) as { value: string }).value).toBe('sk_a_value')

    // B's own secret resolves to B's value only.
    const bList = await fetchApp(req(TENANT_B, '/vault/secrets'))
    const bSecrets = (await bList.json()) as { data: Array<{ id: string; name: string }> }
    expect(bSecrets.data.map((s) => s.name)).toEqual(['STRIPE_KEY'])
    const bId = bSecrets.data[0]!.id
    const bReveal = await fetchApp(req(TENANT_B, `/vault/secrets/${bId}/reveal`))
    expect(((await bReveal.json()) as { value: string }).value).toBe('sk_b_value')
  })
})
