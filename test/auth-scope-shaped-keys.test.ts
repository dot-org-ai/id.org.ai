/**
 * Scope-shaped keys (ax-e6b.17.2) — the SECURITY property.
 *
 * An API key may carry a structured `Scope`: a constrained may-do subset
 * (verb + resource, optionally a ceiling). AuthBroker.gate() evaluates the
 * caller's key Scope against a structured `need` via `scopeSatisfies`:
 * a request is allowed iff it sits inside the granted Scope, else 403.
 *
 * Keys are minted through the REAL mint path (ApiKeyServiceImpl.create — the
 * hly_sk_* generator + apikey/apikey-lookup store the DO delegates to), and
 * gate() is driven with REAL AuthRequirements. The flat-string scope path is
 * exercised alongside to prove it is untouched.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest'
import { AuditServiceImpl } from '../src/server/services/audit/service'
import { ApiKeyServiceImpl } from '../src/server/services/keys/api-keys'
import { AuthBrokerImpl } from '../src/sdk/auth/broker-impl'
import { scopeSatisfies, narrows, deriveChildScope, resourceMatches } from '../src/sdk/auth/scope'
import type { Scope } from '../src/sdk/auth/scope'
import type { StorageAdapter } from '../src/sdk/storage'
import type { CapabilityLevel, Identity, IdentityStub } from '../src/sdk/types'

// ── Storage + service harness (mirrors keys-service.test.ts) ─────────────────

function createTestStorage(data: Map<string, unknown> = new Map()): StorageAdapter {
  return {
    async get<T = unknown>(key: string): Promise<T | undefined> {
      return data.get(key) as T | undefined
    },
    async put(key: string, value: unknown): Promise<void> {
      data.set(key, value)
    },
    async delete(key: string): Promise<boolean> {
      return data.delete(key)
    },
    async list<T = unknown>(options?: { prefix?: string }): Promise<Map<string, T>> {
      const prefix = options?.prefix ?? ''
      const result = new Map<string, T>()
      for (const [k, v] of data) if (k.startsWith(prefix)) result.set(k, v as T)
      return result
    },
  }
}

// A broker whose credential lookup delegates to the REAL key service. This is
// the production wiring in miniature: gate() extracts the key, the DO's
// validateApiKey (here the service) resolves scope+level, check() evaluates.
function brokerBackedBy(svc: ApiKeyServiceImpl, level: CapabilityLevel = 2): AuthBrokerImpl {
  const stub = {
    validateApiKey: async (key: string) => {
      const r = await svc.validate(key)
      if (!r.success || !r.data.valid) return { valid: false as const }
      return r.data
    },
    getIdentity: vi.fn(async () => null),
    getAgent: vi.fn(async () => null),
    getSession: vi.fn(async () => ({ valid: false })),
  } as unknown as IdentityStub

  return new AuthBrokerImpl({ stubFor: () => stub })
}

function keyRequest(key: string): Request {
  return new Request('https://id.org.ai/mcp', { headers: { 'x-api-key': key } })
}

function noCredentialRequest(): Request {
  return new Request('https://id.org.ai/mcp')
}

async function mint(svc: ApiKeyServiceImpl, input: { name: string; scope?: Scope; scopes?: string[] }): Promise<string> {
  const r = await svc.create({ name: input.name, identityId: 'usr_1', scope: input.scope, scopes: input.scopes })
  if (!r.success) throw new Error(`mint failed: ${r.error.message}`)
  return r.data.key
}

// ============================================================================
// Scope module — pure predicates
// ============================================================================

describe('scope module — resourceMatches', () => {
  it('matches exact and trailing-glob patterns, rejects outside resources', () => {
    expect(resourceMatches('listings/123', 'listings/123')).toBe(true)
    expect(resourceMatches('listings/*', 'listings/123')).toBe(true)
    expect(resourceMatches('listings/*', 'listings/a/b')).toBe(true)
    expect(resourceMatches('*', 'anything')).toBe(true)
    expect(resourceMatches('listings/*', 'secrets/1')).toBe(false)
    expect(resourceMatches('listings/123', 'listings/124')).toBe(false)
  })
})

describe('scope module — scopeSatisfies', () => {
  const granted: Scope = { grants: [{ verb: 'read', resource: 'listings/*' }] }

  it('allows a request inside the grant', () => {
    expect(scopeSatisfies(granted, { verb: 'read', resource: 'listings/123' })).toBe(true)
  })

  it('denies a wrong verb', () => {
    expect(scopeSatisfies(granted, { verb: 'write', resource: 'listings/123' })).toBe(false)
  })

  it('denies a resource outside the pattern', () => {
    expect(scopeSatisfies(granted, { verb: 'read', resource: 'secrets/1' })).toBe(false)
  })

  it('honours a ceiling: within allowed, over denied', () => {
    const capped: Scope = { grants: [{ verb: 'spend', resource: 'orders/*', ceiling: { value: 100, unit: 'usd' } }] }
    expect(scopeSatisfies(capped, { verb: 'spend', resource: 'orders/9', amount: { value: 50, unit: 'usd' } })).toBe(true)
    expect(scopeSatisfies(capped, { verb: 'spend', resource: 'orders/9', amount: { value: 100, unit: 'usd' } })).toBe(true)
    expect(scopeSatisfies(capped, { verb: 'spend', resource: 'orders/9', amount: { value: 150, unit: 'usd' } })).toBe(false)
    // Mismatched unit is incomparable → fail closed.
    expect(scopeSatisfies(capped, { verb: 'spend', resource: 'orders/9', amount: { value: 1, unit: 'eur' } })).toBe(false)
  })
})

describe('scope module — narrows rejects any widening', () => {
  const parent: Scope = { grants: [{ verb: 'read', resource: 'listings/*', ceiling: { value: 100, unit: 'usd' } }] }
  const unboundedParent: Scope = { grants: [{ verb: 'read', resource: 'listings/*' }] }

  it('accepts a strict subset', () => {
    // A concrete resource under an unbounded parent narrows.
    expect(narrows({ grants: [{ verb: 'read', resource: 'listings/123' }] }, unboundedParent)).toBe(true)
    // Under a bounded parent, the child must carry a ceiling ≤ the parent's.
    expect(narrows({ grants: [{ verb: 'read', resource: 'listings/123', ceiling: { value: 100, unit: 'usd' } }] }, parent)).toBe(true)
    expect(narrows({ grants: [{ verb: 'read', resource: 'listings/*', ceiling: { value: 50, unit: 'usd' } }] }, parent)).toBe(true)
    expect(narrows({ grants: [] }, parent)).toBe(true)
  })

  it('rejects a widened verb', () => {
    expect(narrows({ grants: [{ verb: 'write', resource: 'listings/123' }] }, parent)).toBe(false)
    expect(narrows({ grants: [{ verb: '*', resource: 'listings/123' }] }, parent)).toBe(false)
  })

  it('rejects a widened resource', () => {
    expect(narrows({ grants: [{ verb: 'read', resource: 'secrets/1' }] }, parent)).toBe(false)
    expect(narrows({ grants: [{ verb: 'read', resource: '*' }] }, parent)).toBe(false)
  })

  it('rejects a widened ceiling (higher value, or unbounded under a bounded parent)', () => {
    expect(narrows({ grants: [{ verb: 'read', resource: 'listings/1', ceiling: { value: 200, unit: 'usd' } }] }, parent)).toBe(false)
    expect(narrows({ grants: [{ verb: 'read', resource: 'listings/1' }] }, parent)).toBe(false) // unbounded child widens
  })
})

describe('scope module — deriveChildScope (delegation must narrow downward)', () => {
  const parent: Scope = { grants: [{ verb: 'read', resource: 'listings/*', ceiling: { value: 100, unit: 'usd' } }] }

  it('returns a narrowed child', () => {
    const child = deriveChildScope(parent, { grants: [{ verb: 'read', resource: 'listings/123', ceiling: { value: 10, unit: 'usd' } }] })
    expect(child.grants).toHaveLength(1)
    expect(narrows(child, parent)).toBe(true)
  })

  it('throws when the proposed child widens the parent', () => {
    expect(() => deriveChildScope(parent, { grants: [{ verb: 'write', resource: 'listings/123' }] })).toThrow()
    expect(() => deriveChildScope(parent, { grants: [{ verb: 'read', resource: 'secrets/1' }] })).toThrow()
    expect(() => deriveChildScope(parent, { grants: [{ verb: 'read', resource: 'listings/1', ceiling: { value: 500, unit: 'usd' } }] })).toThrow()
  })
})

// ============================================================================
// End-to-end: real mint path → real gate()
// ============================================================================

describe('scope-shaped keys — gate() enforces the granted Scope', () => {
  let svc: ApiKeyServiceImpl
  let broker: AuthBrokerImpl

  beforeEach(() => {
    const storage = createTestStorage()
    const audit = new AuditServiceImpl({ storage })
    svc = new ApiKeyServiceImpl({ storage, audit, getIdentityLevel: async () => 2 as CapabilityLevel })
    broker = brokerBackedBy(svc)
  })

  it('PASSES gate for a request inside the key Scope', async () => {
    const key = await mint(svc, { name: 'reader', scope: { grants: [{ verb: 'read', resource: 'listings/*' }] } })
    const decision = await broker.gate(keyRequest(key), { need: { verb: 'read', resource: 'listings/123' } })
    expect(decision.ok).toBe(true)
    if (decision.ok) expect(decision.identity.scope).toBeDefined()
  })

  it('DENIES (403) a wrong verb — write on a read-only key', async () => {
    const key = await mint(svc, { name: 'reader', scope: { grants: [{ verb: 'read', resource: 'listings/*' }] } })
    const decision = await broker.gate(keyRequest(key), { need: { verb: 'write', resource: 'listings/123' } })
    expect(decision.ok).toBe(false)
    if (!decision.ok) {
      expect(decision.reason).toBe('missing-scope')
      expect(decision.response?.status).toBe(403)
    }
  })

  it('DENIES (403) a resource outside the granted pattern', async () => {
    const key = await mint(svc, { name: 'reader', scope: { grants: [{ verb: 'read', resource: 'listings/*' }] } })
    const decision = await broker.gate(keyRequest(key), { need: { verb: 'read', resource: 'secrets/1' } })
    expect(decision.ok).toBe(false)
    if (!decision.ok) expect(decision.response?.status).toBe(403)
  })

  it('a ceiling-bearing key allows within the ceiling and denies over it', async () => {
    const key = await mint(svc, {
      name: 'spender',
      scope: { grants: [{ verb: 'spend', resource: 'orders/*', ceiling: { value: 100, unit: 'usd' } }] },
    })
    const within = await broker.gate(keyRequest(key), { need: { verb: 'spend', resource: 'orders/9', amount: { value: 50, unit: 'usd' } } })
    expect(within.ok).toBe(true)

    const over = await broker.gate(keyRequest(key), { need: { verb: 'spend', resource: 'orders/9', amount: { value: 150, unit: 'usd' } } })
    expect(over.ok).toBe(false)
    if (!over.ok) expect(over.response?.status).toBe(403)
  })

  it('an unauthenticated / no-scope caller is denied a scoped requirement (403)', async () => {
    const decision = await broker.gate(noCredentialRequest(), { need: { verb: 'read', resource: 'listings/123' } })
    expect(decision.ok).toBe(false)
    if (!decision.ok) expect(decision.response?.status).toBe(403)
  })

  it('a flat-scope key (no structured Scope) is denied a structured need', async () => {
    // A key with only flat scopes carries no may-do subset — a structured need
    // must fail closed rather than fall through to allow.
    const key = await mint(svc, { name: 'flat', scopes: ['read', 'write'] })
    const decision = await broker.gate(keyRequest(key), { need: { verb: 'read', resource: 'listings/123' } })
    expect(decision.ok).toBe(false)
    if (!decision.ok) expect(decision.response?.status).toBe(403)
  })
})

// ============================================================================
// Backward compatibility: the flat-string scope path is untouched
// ============================================================================

describe('flat-string scope path stays intact', () => {
  const broker = new AuthBrokerImpl()

  function id(overrides: Partial<Identity> = {}): Identity {
    return { id: 'id-1', type: 'agent', name: 't', verified: false, level: 1, claimStatus: 'unclaimed', ...overrides } as Identity
  }

  it('scopes:[a,b] all-of still passes when present and fails when missing', () => {
    expect(broker.check(id({ scopes: ['a', 'b'] }), { scopes: ['a', 'b'] }).ok).toBe(true)
    expect(broker.check(id({ scopes: ['a'] }), { scopes: ['a', 'b'] }).ok).toBe(false)
  })

  it('anyScopes any-of still works', () => {
    expect(broker.check(id({ scopes: ['b'] }), { anyScopes: ['a', 'b'] }).ok).toBe(true)
    expect(broker.check(id({ scopes: ['c'] }), { anyScopes: ['a', 'b'] }).ok).toBe(false)
  })

  it('bare-number level gate is unchanged', () => {
    expect(broker.check(id({ level: 2 }), 1).ok).toBe(true)
    expect(broker.check(id({ level: 0 }), 1).ok).toBe(false)
  })

  it('a flat requirement and a structured need coexist in one requirement', () => {
    // Both must pass: caller holds the flat scope AND the request is in-Scope.
    const identity = id({ scopes: ['read'], scope: { grants: [{ verb: 'read', resource: 'listings/*' }] } })
    expect(broker.check(identity, { scopes: ['read'], need: { verb: 'read', resource: 'listings/1' } }).ok).toBe(true)
    // Flat scope satisfied but structured need outside → deny.
    expect(broker.check(identity, { scopes: ['read'], need: { verb: 'read', resource: 'secrets/1' } }).ok).toBe(false)
  })
})
