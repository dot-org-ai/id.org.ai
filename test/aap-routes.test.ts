/**
 * AAP wire surface (id-9s0) — phase 1 endpoint tests.
 *
 * Imports the Hono sub-app directly, attaches a mock IdentityStub via
 * Variables, and drives requests through Hono's app.fetch.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest'
import { Hono } from 'hono'
import { aapRoutes } from '../worker/routes/aap'
import type { Env, Variables } from '../worker/types'
import type { Agent, IdentityStub, Identity } from '../src/sdk/types'
import type { MCPAuthResult } from '../src/sdk/mcp/auth'

function makeAgent(overrides: Partial<Agent> = {}): Agent {
  return {
    id: 'agent_abc',
    tenantId: 'tenant_xyz',
    name: 'crm-agent',
    publicKey: 'pubkey-aaa',
    status: 'active',
    mode: 'autonomous',
    capabilities: ['read', 'write'],
    createdAt: Date.now(),
    activatedAt: Date.now(),
    sessionTtlMs: 86400000,
    maxLifetimeMs: 2592000000,
    absoluteLifetimeMs: 31536000000,
    ...overrides,
  }
}

function makeAuth(overrides: Partial<MCPAuthResult> = {}): MCPAuthResult {
  return {
    authenticated: true,
    identityId: 'tenant_xyz',
    level: 1,
    scopes: ['read', 'write'],
    capabilities: [],
    ...overrides,
  }
}

function makeStub(overrides: Partial<IdentityStub> = {}): IdentityStub {
  return {
    getIdentity: vi.fn(async () => null),
    provisionAnonymous: vi.fn(async () => ({ identity: {} as Identity, sessionToken: '', claimToken: '' })),
    claim: vi.fn(async () => ({ success: true })),
    getSession: vi.fn(async () => ({ valid: false })),
    listSessions: vi.fn(async () => []),
    validateApiKey: vi.fn(async () => ({ valid: false })),
    createApiKey: vi.fn(async () => ({ id: '', key: '', name: '', prefix: '', scopes: [], createdAt: '' })),
    listApiKeys: vi.fn(async () => []),
    revokeApiKey: vi.fn(async () => null),
    checkRateLimit: vi.fn(async () => ({ allowed: true, remaining: 99, resetAt: Date.now() + 60000 })),
    verifyClaimToken: vi.fn(async () => ({ valid: false })),
    freezeIdentity: vi.fn(async () => ({ frozen: true, stats: { entities: 0, events: 0, sessions: 0 }, expiresAt: 0 })),
    mcpSearch: vi.fn(async () => ({ results: [], total: 0, limit: 20, offset: 0 })),
    mcpFetch: vi.fn(async () => ({})),
    mcpDo: vi.fn(async () => ({ success: true, entity: '', verb: '' })),
    ensureCliClient: vi.fn(async () => {}),
    ensureOAuthDoClient: vi.fn(async () => {}),
    ensureWebClients: vi.fn(async () => {}),
    oauthStorageOp: vi.fn(async () => ({})),
    registerAgent: vi.fn(async () => ({ success: false })),
    getAgent: vi.fn(async () => null),
    listAgents: vi.fn(async () => []),
    getAgentByPublicKey: vi.fn(async () => null),
    updateAgentStatus: vi.fn(async () => ({ success: false })),
    revokeAgent: vi.fn(async () => ({ success: false })),
    reactivateAgent: vi.fn(async () => ({ success: false })),
    touchAgent: vi.fn(async () => {}),
    auditEvent: vi.fn(async () => {}),
    queryAuditLog: vi.fn(async () => ({ events: [], hasMore: false })),
    storeWorkOSRefreshToken: vi.fn(async () => {}),
    refreshWorkOSToken: vi.fn(async () => ''),
    clearWorkOSRefreshToken: vi.fn(async () => {}),
    ...overrides,
  } as unknown as IdentityStub
}

function makeApp(deps: { auth?: MCPAuthResult | null; stub?: IdentityStub | null } = {}) {
  const app = new Hono<{ Bindings: Env; Variables: Variables }>()
  app.use('*', async (c, next) => {
    if (deps.auth !== null) c.set('auth', deps.auth ?? makeAuth())
    if (deps.stub !== null) c.set('identityStub', (deps.stub ?? makeStub()) as never)
    await next()
  })
  app.route('', aapRoutes)
  return app
}

// ──────────────────────────────────────────────────────────────────────
// Discovery
// ──────────────────────────────────────────────────────────────────────

describe('AAP /.well-known/agent-configuration', () => {
  it('returns AAP v1.0-draft discovery doc with id.org.ai endpoints', async () => {
    const app = makeApp({ auth: null, stub: null })
    const res = await app.fetch(new Request('https://id.org.ai/.well-known/agent-configuration'))
    expect(res.status).toBe(200)
    const body = (await res.json()) as Record<string, unknown>

    expect(body.version).toBe('1.0-draft')
    expect(body.provider_name).toBe('id.org.ai')
    expect(body.algorithms).toEqual(['Ed25519'])
    expect(body.modes).toEqual(['delegated', 'autonomous'])
    expect((body.endpoints as Record<string, unknown>).register).toBe('/agent/register')
    expect((body.endpoints as Record<string, unknown>).status).toBe('/agent/status')
    expect((body.endpoints as Record<string, unknown>).revoke).toBe('/agent/revoke')
    expect((body.endpoints as Record<string, unknown>).reactivate).toBe('/agent/reactivate')
    // Phase 2 endpoints declared as null
    expect((body.endpoints as Record<string, unknown>).execute).toBe(null)
    expect((body.endpoints as Record<string, unknown>).rotate_key).toBe(null)
    expect(Array.isArray(body.conformance_notes)).toBe(true)
  })
})

// ──────────────────────────────────────────────────────────────────────
// /agent/register
// ──────────────────────────────────────────────────────────────────────

describe('AAP POST /agent/register', () => {
  let stub: IdentityStub

  beforeEach(() => {
    stub = makeStub({
      registerAgent: vi.fn(async () => ({ success: true, agent: makeAgent() })),
    })
  })

  it('rejects unauthenticated requests', async () => {
    const app = makeApp({ auth: { authenticated: false, level: 0, scopes: [], capabilities: [] }, stub })
    const res = await app.fetch(
      new Request('https://id.org.ai/agent/register', {
        method: 'POST',
        body: JSON.stringify({ name: 'a', mode: 'autonomous', public_key: 'k' }),
      }),
    )
    expect(res.status).toBe(401)
  })

  it('rejects missing name', async () => {
    const app = makeApp({ stub })
    const res = await app.fetch(
      new Request('https://id.org.ai/agent/register', {
        method: 'POST',
        body: JSON.stringify({ mode: 'autonomous', public_key: 'k' }),
      }),
    )
    expect(res.status).toBe(400)
  })

  it('rejects invalid mode', async () => {
    const app = makeApp({ stub })
    const res = await app.fetch(
      new Request('https://id.org.ai/agent/register', {
        method: 'POST',
        body: JSON.stringify({ name: 'a', mode: 'sneaky', public_key: 'k' }),
      }),
    )
    expect(res.status).toBe(400)
  })

  it('rejects missing key material', async () => {
    const app = makeApp({ stub })
    const res = await app.fetch(
      new Request('https://id.org.ai/agent/register', {
        method: 'POST',
        body: JSON.stringify({ name: 'a', mode: 'autonomous' }),
      }),
    )
    expect(res.status).toBe(400)
  })

  it('returns AAP-shaped response on success', async () => {
    const app = makeApp({ stub })
    const res = await app.fetch(
      new Request('https://id.org.ai/agent/register', {
        method: 'POST',
        body: JSON.stringify({ name: 'crm-agent', mode: 'autonomous', public_key: 'pubkey-aaa', capabilities: ['read', 'write'] }),
      }),
    )
    expect(res.status).toBe(201)
    const body = (await res.json()) as Record<string, unknown>
    expect(body.agent_id).toBe('agent_abc')
    expect(body.host_id).toBe('tenant_xyz')
    expect(body.mode).toBe('autonomous')
    expect(body.status).toBe('active')
    expect(Array.isArray(body.agent_capability_grants)).toBe(true)
  })

  it('uses tenantId from auth context (agent caller scenario)', async () => {
    const stubSpy = makeStub({
      registerAgent: vi.fn(async () => ({ success: true, agent: makeAgent({ tenantId: 'tenant_from_auth' }) })),
    })
    const app = makeApp({
      auth: makeAuth({ identityId: 'agent_caller', tenantId: 'tenant_from_auth' }),
      stub: stubSpy,
    })
    await app.fetch(
      new Request('https://id.org.ai/agent/register', {
        method: 'POST',
        body: JSON.stringify({ name: 'sub', mode: 'autonomous', public_key: 'k' }),
      }),
    )
    expect(stubSpy.registerAgent).toHaveBeenCalledWith(
      expect.objectContaining({ tenantId: 'tenant_from_auth' }),
    )
  })
})

// ──────────────────────────────────────────────────────────────────────
// /agent/status
// ──────────────────────────────────────────────────────────────────────

describe('AAP GET /agent/status', () => {
  it('returns 400 when agent_id is missing', async () => {
    const app = makeApp()
    const res = await app.fetch(new Request('https://id.org.ai/agent/status'))
    expect(res.status).toBe(400)
  })

  it('returns 404 when agent does not exist', async () => {
    const stub = makeStub({ getAgent: vi.fn(async () => null) })
    const app = makeApp({ stub })
    const res = await app.fetch(new Request('https://id.org.ai/agent/status?agent_id=agent_missing'))
    expect(res.status).toBe(404)
  })

  it('returns 403 for cross-tenant access', async () => {
    const stub = makeStub({
      getAgent: vi.fn(async () => makeAgent({ tenantId: 'tenant_other' })),
    })
    const app = makeApp({ stub })
    const res = await app.fetch(new Request('https://id.org.ai/agent/status?agent_id=agent_abc'))
    expect(res.status).toBe(403)
  })

  it('returns AAP-shaped status on hit', async () => {
    const stub = makeStub({ getAgent: vi.fn(async () => makeAgent()) })
    const app = makeApp({ stub })
    const res = await app.fetch(new Request('https://id.org.ai/agent/status?agent_id=agent_abc'))
    expect(res.status).toBe(200)
    const body = (await res.json()) as Record<string, unknown>
    expect(body.agent_id).toBe('agent_abc')
    expect(body.host_id).toBe('tenant_xyz')
    expect(body.status).toBe('active')
    expect(body.mode).toBe('autonomous')
  })
})

// ──────────────────────────────────────────────────────────────────────
// /agent/revoke
// ──────────────────────────────────────────────────────────────────────

describe('AAP POST /agent/revoke', () => {
  it('returns 400 when agent_id is missing', async () => {
    const app = makeApp()
    const res = await app.fetch(
      new Request('https://id.org.ai/agent/revoke', { method: 'POST', body: JSON.stringify({}) }),
    )
    expect(res.status).toBe(400)
  })

  it('returns 403 for cross-tenant revoke', async () => {
    const stub = makeStub({
      getAgent: vi.fn(async () => makeAgent({ tenantId: 'tenant_other' })),
    })
    const app = makeApp({ stub })
    const res = await app.fetch(
      new Request('https://id.org.ai/agent/revoke', {
        method: 'POST',
        body: JSON.stringify({ agent_id: 'agent_abc' }),
      }),
    )
    expect(res.status).toBe(403)
  })

  it('revokes an agent in the same tenant', async () => {
    const revoked = makeAgent({ status: 'revoked', revokedAt: Date.now() })
    const stub = makeStub({
      getAgent: vi.fn(async () => makeAgent()),
      revokeAgent: vi.fn(async () => ({ success: true, agent: revoked })),
    })
    const app = makeApp({ stub })
    const res = await app.fetch(
      new Request('https://id.org.ai/agent/revoke', {
        method: 'POST',
        body: JSON.stringify({ agent_id: 'agent_abc', reason: 'testing' }),
      }),
    )
    expect(res.status).toBe(200)
    const body = (await res.json()) as Record<string, unknown>
    expect(body.agent_id).toBe('agent_abc')
    expect(body.status).toBe('revoked')
  })
})

// ──────────────────────────────────────────────────────────────────────
// /agent/reactivate
// ──────────────────────────────────────────────────────────────────────

describe('AAP POST /agent/reactivate', () => {
  it('reactivates an expired agent in the same tenant', async () => {
    const reactivated = makeAgent({ status: 'active' })
    const stub = makeStub({
      getAgent: vi.fn(async () => makeAgent({ status: 'expired' })),
      reactivateAgent: vi.fn(async () => ({ success: true, agent: reactivated })),
    })
    const app = makeApp({ stub })
    const res = await app.fetch(
      new Request('https://id.org.ai/agent/reactivate', {
        method: 'POST',
        body: JSON.stringify({ agent_id: 'agent_abc' }),
      }),
    )
    expect(res.status).toBe(200)
    const body = (await res.json()) as Record<string, unknown>
    expect(body.status).toBe('active')
  })

  it('returns 400 when reactivate fails (e.g., not expired)', async () => {
    const stub = makeStub({
      getAgent: vi.fn(async () => makeAgent({ status: 'active' })),
      reactivateAgent: vi.fn(async () => ({ success: false, error: 'not expired' })),
    })
    const app = makeApp({ stub })
    const res = await app.fetch(
      new Request('https://id.org.ai/agent/reactivate', {
        method: 'POST',
        body: JSON.stringify({ agent_id: 'agent_abc' }),
      }),
    )
    expect(res.status).toBe(400)
  })

  it('returns 403 for cross-tenant reactivate', async () => {
    const stub = makeStub({
      getAgent: vi.fn(async () => makeAgent({ tenantId: 'tenant_other', status: 'expired' })),
    })
    const app = makeApp({ stub })
    const res = await app.fetch(
      new Request('https://id.org.ai/agent/reactivate', {
        method: 'POST',
        body: JSON.stringify({ agent_id: 'agent_abc' }),
      }),
    )
    expect(res.status).toBe(403)
  })
})
