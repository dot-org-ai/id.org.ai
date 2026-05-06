/**
 * AuthBroker.gate() and AuthBroker.identify() — credential extraction +
 * gating. Phase 1's `auth-broker.test.ts` covers the synchronous `check()`
 * path.
 */
import { describe, it, expect, vi } from 'vitest'
import { AuthBrokerImpl } from '../src/sdk/auth/broker-impl'
import type { CapabilityLevel, Identity, IdentityStub } from '../src/sdk/types'

// ── Test helpers ────────────────────────────────────────────────────────────

function makeIdentity(overrides: Partial<Identity> = {}): Identity {
  return {
    id: 'id-1',
    type: 'agent',
    name: 'test',
    verified: false,
    level: 1,
    claimStatus: 'unclaimed',
    ...overrides,
  } as Identity
}

function createStub(overrides: Partial<IdentityStub> = {}): IdentityStub {
  return {
    getIdentity: vi.fn(async () => null),
    provisionAnonymous: vi.fn(async () => ({
      identity: makeIdentity({ id: '' }),
      sessionToken: '',
      claimToken: '',
    })),
    claim: vi.fn(async () => ({ success: true })),
    getSession: vi.fn(async () => ({ valid: false })),
    validateApiKey: vi.fn(async () => ({ valid: false })),
    createApiKey: vi.fn(async () => ({ id: '', key: '', name: '', prefix: '', scopes: [], createdAt: '' })),
    listApiKeys: vi.fn(async () => []),
    revokeApiKey: vi.fn(async () => null),
    checkRateLimit: vi.fn(async () => ({ allowed: true, remaining: 99, resetAt: Date.now() + 60000 })),
    verifyClaimToken: vi.fn(async () => ({ valid: false })),
    freezeIdentity: vi.fn(async () => ({ frozen: true, stats: { entities: 0, events: 0, sessions: 0 }, expiresAt: Date.now() + 30 * 86400000 })),
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
  } as IdentityStub
}

function makeRequest(opts: {
  apiKey?: string
  apiKeyHeader?: 'x-api-key' | 'authorization' | 'query'
  sessionToken?: string
  cookie?: string
  url?: string
} = {}): Request {
  const headers: Record<string, string> = {}
  let url = opts.url ?? 'https://id.org.ai/mcp'

  if (opts.apiKey) {
    const placement = opts.apiKeyHeader ?? 'x-api-key'
    if (placement === 'x-api-key') headers['x-api-key'] = opts.apiKey
    else if (placement === 'authorization') headers['authorization'] = `Bearer ${opts.apiKey}`
    else if (placement === 'query') {
      const u = new URL(url)
      u.searchParams.set('api_key', opts.apiKey)
      url = u.toString()
    }
  }
  if (opts.sessionToken) headers['authorization'] = `Bearer ${opts.sessionToken}`
  if (opts.cookie) headers['cookie'] = opts.cookie

  return new Request(url, { method: 'GET', headers })
}

// ── identify() ──────────────────────────────────────────────────────────────

describe('AuthBroker.identify — anonymous (no credentials)', () => {
  it('returns L0 anonymous identity when no credentials are presented', async () => {
    const stub = createStub()
    const broker = new AuthBrokerImpl({ stubFor: () => stub })

    const identity = await broker.identify(makeRequest())

    expect(identity.id).toBe('anon')
    expect(identity.level).toBe(0)
    expect(identity.type).toBe('agent')
    expect(stub.validateApiKey).not.toHaveBeenCalled()
    expect(stub.getSession).not.toHaveBeenCalled()
  })

  it('returns L0 anonymous identity when constructed without deps', async () => {
    const broker = new AuthBrokerImpl()
    const identity = await broker.identify(makeRequest())
    expect(identity.id).toBe('anon')
    expect(identity.level).toBe(0)
  })
})

describe('AuthBroker.identify — API key', () => {
  it('resolves identity from a valid X-API-Key header', async () => {
    const stub = createStub({
      validateApiKey: vi.fn(async () => ({
        valid: true,
        identityId: 'id-api-1',
        scopes: ['read', 'write'],
        level: 2 as CapabilityLevel,
      })),
      getIdentity: vi.fn(async (id: string) =>
        makeIdentity({ id, level: 2, type: 'agent', name: 'agent-1' }),
      ),
    })
    const broker = new AuthBrokerImpl({ stubFor: () => stub })

    const identity = await broker.identify(makeRequest({ apiKey: 'oai_valid' }))

    expect(identity.id).toBe('id-api-1')
    expect(identity.level).toBe(2)
    expect(identity.scopes).toEqual(['read', 'write'])
    expect(stub.validateApiKey).toHaveBeenCalledWith('oai_valid')
  })

  it('accepts API key via Authorization: Bearer', async () => {
    const stub = createStub({
      validateApiKey: vi.fn(async () => ({
        valid: true,
        identityId: 'id-api-2',
        scopes: ['read'],
        level: 2 as CapabilityLevel,
      })),
      getIdentity: vi.fn(async (id: string) => makeIdentity({ id, level: 2 })),
    })
    const broker = new AuthBrokerImpl({ stubFor: () => stub })

    const identity = await broker.identify(
      makeRequest({ apiKey: 'hly_sk_abc', apiKeyHeader: 'authorization' }),
    )
    expect(identity.id).toBe('id-api-2')
  })

  it('accepts API key via ?api_key= query param', async () => {
    const stub = createStub({
      validateApiKey: vi.fn(async () => ({
        valid: true,
        identityId: 'id-api-3',
        scopes: [],
        level: 2 as CapabilityLevel,
      })),
      getIdentity: vi.fn(async (id: string) => makeIdentity({ id, level: 2 })),
    })
    const broker = new AuthBrokerImpl({ stubFor: () => stub })

    const identity = await broker.identify(
      makeRequest({ apiKey: 'sk_xyz', apiKeyHeader: 'query' }),
    )
    expect(identity.id).toBe('id-api-3')
  })

  it('falls back to anonymous when the API key is invalid', async () => {
    const stub = createStub({ validateApiKey: vi.fn(async () => ({ valid: false })) })
    const broker = new AuthBrokerImpl({ stubFor: () => stub })

    const identity = await broker.identify(makeRequest({ apiKey: 'oai_bad' }))
    expect(identity.id).toBe('anon')
    expect(identity.level).toBe(0)
  })

  it('synthesises an identity when validateApiKey succeeds but getIdentity is empty', async () => {
    const stub = createStub({
      validateApiKey: vi.fn(async () => ({
        valid: true,
        identityId: 'id-orphan',
        scopes: ['read'],
        level: 2 as CapabilityLevel,
      })),
      getIdentity: vi.fn(async () => null),
    })
    const broker = new AuthBrokerImpl({ stubFor: () => stub })

    const identity = await broker.identify(makeRequest({ apiKey: 'oai_orphan' }))
    expect(identity.id).toBe('id-orphan')
    expect(identity.level).toBe(2)
    expect(identity.scopes).toEqual(['read'])
  })
})

describe('AuthBroker.identify — agent_* principal (id-ax7)', () => {
  // When validateApiKey returns an identityId starting with 'agent_', the
  // broker dispatches to getAgent() instead of getIdentity() and synthesises
  // an Identity{type:'agent'} with tenantId from the Agent row.

  function makeAgent(overrides: Record<string, unknown> = {}) {
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

  it('synthesises Identity{type:agent, tenantId} from the Agent row', async () => {
    const agent = makeAgent()
    const stub = createStub({
      validateApiKey: vi.fn(async () => ({
        valid: true,
        identityId: 'agent_abc',
        scopes: ['read', 'write'],
        level: 2 as CapabilityLevel,
      })),
      getAgent: vi.fn(async () => agent as never),
    })
    const broker = new AuthBrokerImpl({ stubFor: () => stub })

    const identity = await broker.identify(makeRequest({ apiKey: 'oai_agent' }))

    expect(identity.id).toBe('agent_abc')
    expect(identity.type).toBe('agent')
    expect(identity.tenantId).toBe('tenant_xyz')
    expect(identity.scopes).toEqual(['read', 'write'])
    expect(identity.claimStatus).toBe('claimed')
    expect(stub.getAgent).toHaveBeenCalledWith('agent_abc')
    expect(stub.getIdentity).not.toHaveBeenCalled()
  })

  it('touches the Agent (fire-and-forget) for sessionTtl tracking', async () => {
    const stub = createStub({
      validateApiKey: vi.fn(async () => ({
        valid: true,
        identityId: 'agent_abc',
        level: 2 as CapabilityLevel,
      })),
      getAgent: vi.fn(async () => makeAgent() as never),
    })
    const broker = new AuthBrokerImpl({ stubFor: () => stub })

    await broker.identify(makeRequest({ apiKey: 'oai_agent' }))

    expect(stub.touchAgent).toHaveBeenCalledWith('agent_abc')
  })

  it('falls back to anonymous when the Agent is missing', async () => {
    const stub = createStub({
      validateApiKey: vi.fn(async () => ({
        valid: true,
        identityId: 'agent_missing',
        level: 2 as CapabilityLevel,
      })),
      getAgent: vi.fn(async () => null),
    })
    const broker = new AuthBrokerImpl({ stubFor: () => stub })

    const identity = await broker.identify(makeRequest({ apiKey: 'oai_orphan' }))
    expect(identity.id).toBe('anon')
  })

  it('falls back to anonymous when the Agent is not active', async () => {
    const stub = createStub({
      validateApiKey: vi.fn(async () => ({
        valid: true,
        identityId: 'agent_pending',
        level: 2 as CapabilityLevel,
      })),
      getAgent: vi.fn(async () => makeAgent({ status: 'pending' }) as never),
    })
    const broker = new AuthBrokerImpl({ stubFor: () => stub })

    const identity = await broker.identify(makeRequest({ apiKey: 'oai_pending' }))
    expect(identity.id).toBe('anon')
  })

  it('uses agent.capabilities as scopes when the API key carries no scopes override', async () => {
    const stub = createStub({
      validateApiKey: vi.fn(async () => ({
        valid: true,
        identityId: 'agent_abc',
        level: 2 as CapabilityLevel,
      })),
      getAgent: vi.fn(async () => makeAgent({ capabilities: ['transfer_money', 'read_contacts'] }) as never),
    })
    const broker = new AuthBrokerImpl({ stubFor: () => stub })

    const identity = await broker.identify(makeRequest({ apiKey: 'oai_agent' }))
    expect(identity.scopes).toEqual(['transfer_money', 'read_contacts'])
  })

  it('does not call getIdentity when principal is agent_*', async () => {
    const stub = createStub({
      validateApiKey: vi.fn(async () => ({
        valid: true,
        identityId: 'agent_abc',
        level: 2 as CapabilityLevel,
      })),
      getAgent: vi.fn(async () => makeAgent() as never),
    })
    const broker = new AuthBrokerImpl({ stubFor: () => stub })

    await broker.identify(makeRequest({ apiKey: 'oai_agent' }))
    expect(stub.getIdentity).not.toHaveBeenCalled()
  })
})

describe('AuthBroker.identify — session token', () => {
  it('resolves identity from a valid ses_* session token', async () => {
    const stub = createStub({
      getSession: vi.fn(async () => ({
        valid: true,
        identityId: 'id-ses-1',
        level: 1 as CapabilityLevel,
        expiresAt: Date.now() + 86400000,
      })),
      getIdentity: vi.fn(async (id: string) =>
        makeIdentity({ id, level: 1, name: 'sandboxed' }),
      ),
    })
    const broker = new AuthBrokerImpl({ stubFor: () => stub })

    const identity = await broker.identify(makeRequest({ sessionToken: 'ses_abc' }))
    expect(identity.id).toBe('id-ses-1')
    expect(identity.level).toBe(1)
    expect(stub.getSession).toHaveBeenCalledWith('ses_abc')
  })

  it('falls back to anonymous when the session token is invalid', async () => {
    const stub = createStub({ getSession: vi.fn(async () => ({ valid: false })) })
    const broker = new AuthBrokerImpl({ stubFor: () => stub })

    const identity = await broker.identify(makeRequest({ sessionToken: 'ses_bad' }))
    expect(identity.id).toBe('anon')
  })
})

describe('AuthBroker.identify — JWT cookie', () => {
  it('resolves identity from a verified auth cookie', async () => {
    const stub = createStub({
      getIdentity: vi.fn(async (id: string) =>
        makeIdentity({ id, type: 'human', level: 2, name: 'martha' }),
      ),
    })
    const verifyJwt = vi.fn(async () => ({ identityId: 'human:user-1' }))
    const broker = new AuthBrokerImpl({ stubFor: () => stub, verifyJwt })

    const identity = await broker.identify(
      makeRequest({ cookie: 'auth=eyJabc.signature.payload; other=val' }),
    )

    expect(identity.id).toBe('human:user-1')
    expect(identity.type).toBe('human')
    expect(identity.level).toBe(2)
    expect(identity.scopes).toEqual(['openid', 'profile', 'email'])
    expect(verifyJwt).toHaveBeenCalledWith('eyJabc.signature.payload')
  })

  it('parses chunked auth cookies (auth.0, auth.1, …)', async () => {
    const stub = createStub({
      getIdentity: vi.fn(async (id: string) => makeIdentity({ id, type: 'human', level: 2 })),
    })
    const verifyJwt = vi.fn(async (jwt: string) => ({ identityId: `human:${jwt.slice(0, 4)}` }))
    const broker = new AuthBrokerImpl({ stubFor: () => stub, verifyJwt })

    const identity = await broker.identify(
      makeRequest({ cookie: 'auth.0=abcd; auth.1=efgh' }),
    )
    expect(identity.id).toBe('human:abcd')
    expect(verifyJwt).toHaveBeenCalledWith('abcdefgh')
  })

  it('falls back to anonymous when JWT verification fails', async () => {
    const stub = createStub()
    const verifyJwt = vi.fn(async () => null)
    const broker = new AuthBrokerImpl({ stubFor: () => stub, verifyJwt })

    const identity = await broker.identify(makeRequest({ cookie: 'auth=invalid' }))
    expect(identity.id).toBe('anon')
  })

  it('falls back to anonymous when verifyJwt is not provided', async () => {
    const stub = createStub()
    const broker = new AuthBrokerImpl({ stubFor: () => stub })

    const identity = await broker.identify(makeRequest({ cookie: 'auth=eyJanything' }))
    expect(identity.id).toBe('anon')
  })

  it('does not throw if verifyJwt itself throws', async () => {
    const stub = createStub()
    const verifyJwt = vi.fn(async () => {
      throw new Error('boom')
    })
    const broker = new AuthBrokerImpl({ stubFor: () => stub, verifyJwt })

    const identity = await broker.identify(makeRequest({ cookie: 'auth=eyJanything' }))
    expect(identity.id).toBe('anon')
  })
})

// ── gate() ──────────────────────────────────────────────────────────────────

describe('AuthBroker.gate — anonymous + L0 requirement', () => {
  it('passes when no credentials and no level required', async () => {
    const stub = createStub()
    const broker = new AuthBrokerImpl({ stubFor: () => stub })

    const decision = await broker.gate(makeRequest(), 0)
    expect(decision.ok).toBe(true)
    if (decision.ok) {
      expect(decision.identity.id).toBe('anon')
      expect(decision.identity.level).toBe(0)
    }
  })

  it('rejects with insufficient-level when no creds + L1 required', async () => {
    const stub = createStub()
    const broker = new AuthBrokerImpl({ stubFor: () => stub })

    const decision = await broker.gate(makeRequest(), 1)
    expect(decision.ok).toBe(false)
    if (!decision.ok) {
      expect(decision.reason).toBe('insufficient-level')
      expect(decision.response).toBeInstanceOf(Response)
      expect(decision.response!.status).toBe(403)
    }
  })
})

describe('AuthBroker.gate — invalid credentials', () => {
  it('returns 401 when an API key is presented but invalid', async () => {
    const stub = createStub({ validateApiKey: vi.fn(async () => ({ valid: false })) })
    const broker = new AuthBrokerImpl({ stubFor: () => stub })

    const decision = await broker.gate(makeRequest({ apiKey: 'oai_bad' }), 0)
    expect(decision.ok).toBe(false)
    if (!decision.ok) {
      expect(decision.reason).toBe('unauthenticated')
      expect(decision.response!.status).toBe(401)
    }
  })

  it('returns 401 when a session token is presented but invalid', async () => {
    const stub = createStub({ getSession: vi.fn(async () => ({ valid: false })) })
    const broker = new AuthBrokerImpl({ stubFor: () => stub })

    const decision = await broker.gate(makeRequest({ sessionToken: 'ses_bad' }), 0)
    expect(decision.ok).toBe(false)
    if (!decision.ok) {
      expect(decision.reason).toBe('unauthenticated')
      expect(decision.response!.status).toBe(401)
    }
  })

  it('returns 401 when a JWT cookie fails verification', async () => {
    const stub = createStub()
    const verifyJwt = vi.fn(async () => null)
    const broker = new AuthBrokerImpl({ stubFor: () => stub, verifyJwt })

    const decision = await broker.gate(makeRequest({ cookie: 'auth=bad' }), 0)
    expect(decision.ok).toBe(false)
    if (!decision.ok) {
      expect(decision.reason).toBe('unauthenticated')
      expect(decision.response!.status).toBe(401)
    }
  })
})

describe('AuthBroker.gate — successful credential paths', () => {
  it('passes for a valid API key meeting the level requirement', async () => {
    const stub = createStub({
      validateApiKey: vi.fn(async () => ({
        valid: true,
        identityId: 'id-7',
        scopes: ['read', 'write'],
        level: 2 as CapabilityLevel,
      })),
      getIdentity: vi.fn(async (id: string) => makeIdentity({ id, level: 2 })),
    })
    const broker = new AuthBrokerImpl({ stubFor: () => stub })

    const decision = await broker.gate(makeRequest({ apiKey: 'oai_good' }), 2)
    expect(decision.ok).toBe(true)
    if (decision.ok) expect(decision.identity.id).toBe('id-7')
  })

  it('passes for a valid session token meeting the level requirement', async () => {
    const stub = createStub({
      getSession: vi.fn(async () => ({
        valid: true,
        identityId: 'id-ses',
        level: 1 as CapabilityLevel,
        expiresAt: Date.now() + 86400000,
      })),
      getIdentity: vi.fn(async (id: string) => makeIdentity({ id, level: 1 })),
    })
    const broker = new AuthBrokerImpl({ stubFor: () => stub })

    const decision = await broker.gate(makeRequest({ sessionToken: 'ses_good' }), 1)
    expect(decision.ok).toBe(true)
  })

  it('passes for a valid JWT cookie meeting the level requirement', async () => {
    const stub = createStub({
      getIdentity: vi.fn(async (id: string) =>
        makeIdentity({ id, type: 'human', level: 2 }),
      ),
    })
    const verifyJwt = vi.fn(async () => ({ identityId: 'human:abc' }))
    const broker = new AuthBrokerImpl({ stubFor: () => stub, verifyJwt })

    const decision = await broker.gate(makeRequest({ cookie: 'auth=eyJok' }), 2)
    expect(decision.ok).toBe(true)
    if (decision.ok) expect(decision.identity.id).toBe('human:abc')
  })
})

describe('AuthBroker.gate — frozen identity', () => {
  it('blocks frozen identities with reason=frozen', async () => {
    const stub = createStub({
      validateApiKey: vi.fn(async () => ({
        valid: true,
        identityId: 'id-frozen',
        scopes: [],
        level: 3 as CapabilityLevel,
      })),
      getIdentity: vi.fn(async (id: string) =>
        makeIdentity({ id, level: 3, frozen: true, frozenAt: Date.now() }),
      ),
    })
    const broker = new AuthBrokerImpl({ stubFor: () => stub })

    const decision = await broker.gate(makeRequest({ apiKey: 'oai_frozen' }), 1)
    expect(decision.ok).toBe(false)
    if (!decision.ok) {
      expect(decision.reason).toBe('frozen')
      expect(decision.response!.status).toBe(403)
    }
  })
})

describe('AuthBroker.gate — typed requirements (insufficient-level / missing-scope)', () => {
  it('rejects insufficient-level with a 403 response', async () => {
    const stub = createStub({
      getSession: vi.fn(async () => ({
        valid: true,
        identityId: 'id-low',
        level: 1 as CapabilityLevel,
        expiresAt: Date.now() + 86400000,
      })),
      getIdentity: vi.fn(async (id: string) => makeIdentity({ id, level: 1 })),
    })
    const broker = new AuthBrokerImpl({ stubFor: () => stub })

    const decision = await broker.gate(makeRequest({ sessionToken: 'ses_low' }), { minLevel: 2 })
    expect(decision.ok).toBe(false)
    if (!decision.ok) {
      expect(decision.reason).toBe('insufficient-level')
      expect(decision.response!.status).toBe(403)
    }
  })

  it('rejects missing-scope with a 403 response', async () => {
    const stub = createStub({
      validateApiKey: vi.fn(async () => ({
        valid: true,
        identityId: 'id-readonly',
        scopes: ['read'],
        level: 2 as CapabilityLevel,
      })),
      getIdentity: vi.fn(async (id: string) => makeIdentity({ id, level: 2 })),
    })
    const broker = new AuthBrokerImpl({ stubFor: () => stub })

    const decision = await broker.gate(
      makeRequest({ apiKey: 'oai_readonly' }),
      { minLevel: 2, scopes: ['admin'] },
    )
    expect(decision.ok).toBe(false)
    if (!decision.ok) {
      expect(decision.reason).toBe('missing-scope')
      expect(decision.response!.status).toBe(403)
    }
  })

  it('rejects FGA-resource requirements as forbidden (must use async backend)', async () => {
    const stub = createStub({
      validateApiKey: vi.fn(async () => ({
        valid: true,
        identityId: 'id-x',
        scopes: ['read'],
        level: 2 as CapabilityLevel,
      })),
      getIdentity: vi.fn(async (id: string) => makeIdentity({ id, level: 2 })),
    })
    const broker = new AuthBrokerImpl({ stubFor: () => stub })

    const decision = await broker.gate(
      makeRequest({ apiKey: 'oai_x' }),
      { minLevel: 1, resource: { $id: 'https://x/1', $type: 'Tenant' } },
    )
    expect(decision.ok).toBe(false)
    if (!decision.ok) expect(decision.reason).toBe('forbidden')
  })
})

describe('AuthBroker.gate — response body shape', () => {
  it('returns an OAuth-style error JSON body', async () => {
    const stub = createStub()
    const broker = new AuthBrokerImpl({ stubFor: () => stub })

    const decision = await broker.gate(makeRequest(), 1)
    expect(decision.ok).toBe(false)
    if (!decision.ok && decision.response) {
      const body = (await decision.response.json()) as Record<string, string>
      expect(typeof body.error).toBe('string')
      expect(body.error_description).toBeDefined()
    }
  })
})
