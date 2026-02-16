/**
 * MCPAuth Unit Tests
 *
 * Tests the three-tier authentication strategy:
 *   L0: No auth — anonymous, read-only, 30 req/min
 *   L1: Session token (ses_*) — sandboxed, read+write, 100 req/min
 *   L2+: API key (oai_*) — full scopes, 1000+ req/min
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { MCPAuth } from '../src/mcp/auth'
import type { IdentityStub, CapabilityLevel } from '../src/do/Identity'

// ── Mock Identity Stub ──────────────────────────────────────────────────

function createMockIdentityStub(overrides: Partial<IdentityStub> = {}): IdentityStub {
  return {
    getIdentity: vi.fn(async () => null),
    provisionAnonymous: vi.fn(async () => ({
      identity: { id: '', type: 'agent' as const, name: '', verified: false, level: 1 as const, claimStatus: 'unclaimed' as const },
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
    freezeIdentity: vi.fn(async () => ({ frozen: true, stats: { entities: 0, events: 0, sessions: 0 }, expiresAt: Date.now() + 30 * 24 * 60 * 60 * 1000 })),
    mcpSearch: vi.fn(async () => ({ results: [], total: 0, limit: 20, offset: 0 })),
    mcpFetch: vi.fn(async () => ({})),
    mcpDo: vi.fn(async () => ({ success: true, entity: '', verb: '' })),
    oauthStorageOp: vi.fn(async () => ({})),
    writeAuditEvent: vi.fn(async () => {}),
    queryAuditLog: vi.fn(async () => ({ events: [], hasMore: false })),
    ...overrides,
  }
}

function makeRequest(options: { apiKey?: string; sessionToken?: string; url?: string } = {}): Request {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }

  if (options.apiKey) {
    headers['X-API-Key'] = options.apiKey
  }

  if (options.sessionToken) {
    headers['Authorization'] = `Bearer ${options.sessionToken}`
  }

  return new Request(options.url ?? 'https://id.org.ai/mcp', {
    method: 'GET',
    headers,
  })
}

// ── Tests ───────────────────────────────────────────────────────────────

describe('MCPAuth', () => {
  describe('L0: Anonymous authentication', () => {
    it('returns L0 result when no credentials are provided', async () => {
      const stub = createMockIdentityStub()
      const mcpAuth = new MCPAuth(stub)
      const request = makeRequest()

      const result = await mcpAuth.authenticate(request)

      expect(result.authenticated).toBe(false)
      expect(result.level).toBe(0)
      expect(result.scopes).toContain('read')
      expect(result.scopes).toContain('search')
      expect(result.scopes).toContain('fetch')
      expect(result.scopes).toContain('explore')
      expect(result.scopes).not.toContain('write')
      expect(result.scopes).not.toContain('do')
      expect(result.capabilities).toEqual(['explore', 'search', 'fetch'])
    })

    it('includes upgrade hint to L1', async () => {
      const stub = createMockIdentityStub()
      const mcpAuth = new MCPAuth(stub)
      const request = makeRequest()

      const result = await mcpAuth.authenticate(request)

      expect(result.upgrade).toBeDefined()
      expect(result.upgrade!.nextLevel).toBe(1)
      expect(result.upgrade!.action).toBe('provision')
      expect(result.upgrade!.url).toBe('https://id.org.ai/api/provision')
    })

    it('provides rate limit info for anonymous users', async () => {
      const stub = createMockIdentityStub()
      const mcpAuth = new MCPAuth(stub)
      const request = makeRequest()

      const result = await mcpAuth.authenticate(request)

      expect(result.rateLimit).toBeDefined()
      expect(result.rateLimit!.allowed).toBe(true)
      expect(result.rateLimit!.limit).toBe(30)
    })
  })

  describe('L1: Session token authentication', () => {
    it('authenticates valid session token', async () => {
      const stub = createMockIdentityStub({
        getSession: vi.fn(async () => ({
          valid: true,
          identityId: 'id-123',
          level: 1 as CapabilityLevel,
          expiresAt: Date.now() + 86400000,
        })),
        checkRateLimit: vi.fn(async () => ({
          allowed: true,
          remaining: 99,
          resetAt: Date.now() + 60000,
        })),
      })
      const mcpAuth = new MCPAuth(stub)
      const request = makeRequest({ sessionToken: 'ses_abc123' })

      const result = await mcpAuth.authenticate(request)

      expect(result.authenticated).toBe(true)
      expect(result.level).toBe(1)
      expect(result.identityId).toBe('id-123')
      expect(result.scopes).toContain('write')
      expect(result.scopes).toContain('do')
      expect(result.scopes).toContain('try')
      expect(result.capabilities).toContain('do')
      expect(result.capabilities).toContain('try')
    })

    it('includes upgrade hint to L2 (claim)', async () => {
      const stub = createMockIdentityStub({
        getSession: vi.fn(async () => ({
          valid: true,
          identityId: 'id-123',
          level: 1 as CapabilityLevel,
          expiresAt: Date.now() + 86400000,
        })),
        checkRateLimit: vi.fn(async () => ({
          allowed: true,
          remaining: 99,
          resetAt: Date.now() + 60000,
        })),
      })
      const mcpAuth = new MCPAuth(stub)
      const request = makeRequest({ sessionToken: 'ses_abc123' })

      const result = await mcpAuth.authenticate(request)

      expect(result.upgrade).toBeDefined()
      expect(result.upgrade!.nextLevel).toBe(2)
      expect(result.upgrade!.action).toBe('claim')
    })

    it('falls back to L0 for invalid session token', async () => {
      const stub = createMockIdentityStub({
        getSession: vi.fn(async () => ({ valid: false })),
      })
      const mcpAuth = new MCPAuth(stub)
      const request = makeRequest({ sessionToken: 'ses_invalid' })

      const result = await mcpAuth.authenticate(request)

      expect(result.authenticated).toBe(false)
      expect(result.level).toBe(0)
      expect(result.error).toBe('Invalid or expired session token')
    })

    it('reports rate limit exceeded for L1', async () => {
      const stub = createMockIdentityStub({
        getSession: vi.fn(async () => ({
          valid: true,
          identityId: 'id-123',
          level: 1 as CapabilityLevel,
          expiresAt: Date.now() + 86400000,
        })),
        checkRateLimit: vi.fn(async () => ({
          allowed: false,
          remaining: 0,
          resetAt: Date.now() + 30000,
        })),
      })
      const mcpAuth = new MCPAuth(stub)
      const request = makeRequest({ sessionToken: 'ses_abc123' })

      const result = await mcpAuth.authenticate(request)

      expect(result.authenticated).toBe(true)
      expect(result.rateLimit!.allowed).toBe(false)
      expect(result.error).toBe('Rate limit exceeded')
    })
  })

  describe('L2+: API key authentication', () => {
    it('authenticates valid API key via X-API-Key header', async () => {
      const stub = createMockIdentityStub({
        validateApiKey: vi.fn(async (key: string) => {
          if (key === 'oai_validkey123') {
            return {
              valid: true,
              identityId: 'id-456',
              scopes: ['read', 'write'],
              level: 2 as CapabilityLevel,
            }
          }
          return { valid: false }
        }),
        checkRateLimit: vi.fn(async () => ({
          allowed: true,
          remaining: 999,
          resetAt: Date.now() + 60000,
        })),
      })
      const mcpAuth = new MCPAuth(stub)
      const request = makeRequest({ apiKey: 'oai_validkey123' })

      const result = await mcpAuth.authenticate(request)

      expect(result.authenticated).toBe(true)
      expect(result.level).toBe(2)
      expect(result.identityId).toBe('id-456')
    })

    it('authenticates valid API key via Bearer header', async () => {
      const stub = createMockIdentityStub({
        validateApiKey: vi.fn(async () => ({
          valid: true,
          identityId: 'id-789',
          level: 3 as CapabilityLevel,
        })),
        checkRateLimit: vi.fn(async () => ({
          allowed: true,
          remaining: Infinity,
          resetAt: 0,
        })),
      })
      const mcpAuth = new MCPAuth(stub)
      const request = new Request('https://id.org.ai/mcp', {
        headers: { 'Authorization': 'Bearer oai_bearerkey456' },
      })

      const result = await mcpAuth.authenticate(request)

      expect(result.authenticated).toBe(true)
      expect(result.level).toBeGreaterThanOrEqual(2)
    })

    it('falls back to L0 for invalid API key', async () => {
      const stub = createMockIdentityStub({
        validateApiKey: vi.fn(async () => ({ valid: false })),
      })
      const mcpAuth = new MCPAuth(stub)
      const request = makeRequest({ apiKey: 'oai_invalidkey' })

      const result = await mcpAuth.authenticate(request)

      expect(result.authenticated).toBe(false)
      expect(result.level).toBe(0)
      expect(result.error).toBe('Invalid API key')
    })

    it('includes upgrade hint to L3 for L2 users', async () => {
      const stub = createMockIdentityStub({
        validateApiKey: vi.fn(async () => ({
          valid: true,
          identityId: 'id-456',
          level: 2 as CapabilityLevel,
        })),
        checkRateLimit: vi.fn(async () => ({
          allowed: true,
          remaining: 999,
          resetAt: Date.now() + 60000,
        })),
      })
      const mcpAuth = new MCPAuth(stub)
      const request = makeRequest({ apiKey: 'oai_validkey' })

      const result = await mcpAuth.authenticate(request)

      expect(result.upgrade).toBeDefined()
      expect(result.upgrade!.nextLevel).toBe(3)
      expect(result.upgrade!.action).toBe('subscribe')
    })

    it('API key takes priority over session token', async () => {
      const stub = createMockIdentityStub({
        validateApiKey: vi.fn(async () => ({
          valid: true,
          identityId: 'id-apikey',
          level: 2 as CapabilityLevel,
        })),
        checkRateLimit: vi.fn(async () => ({
          allowed: true,
          remaining: 999,
          resetAt: Date.now() + 60000,
        })),
      })
      const mcpAuth = new MCPAuth(stub)
      // Both API key and session token provided — API key should win
      const request = new Request('https://id.org.ai/mcp', {
        headers: {
          'X-API-Key': 'oai_apikey',
          'Authorization': 'Bearer ses_sessiontoken',
        },
      })

      const result = await mcpAuth.authenticate(request)

      expect(result.identityId).toBe('id-apikey')
      expect(result.level).toBe(2)
    })
  })

  describe('buildMeta', () => {
    it('builds meta with auth level and capabilities', () => {
      const stub = createMockIdentityStub()
      const mcpAuth = new MCPAuth(stub)

      const meta = mcpAuth.buildMeta({
        authenticated: true,
        identityId: 'id-123',
        level: 1,
        scopes: ['read', 'write'],
        capabilities: ['explore', 'search', 'fetch', 'try', 'do'],
      })

      expect(meta.auth).toBeDefined()
      const auth = meta.auth as Record<string, unknown>
      expect(auth.level).toBe(1)
      expect(auth.authenticated).toBe(true)
      expect(auth.identityId).toBe('id-123')
    })

    it('includes rate limit info when present', () => {
      const stub = createMockIdentityStub()
      const mcpAuth = new MCPAuth(stub)

      const meta = mcpAuth.buildMeta({
        authenticated: false,
        level: 0,
        scopes: ['read'],
        capabilities: ['explore'],
        rateLimit: {
          allowed: true,
          remaining: 29,
          resetAt: Date.now() + 60000,
          limit: 30,
        },
      })

      expect(meta.rateLimit).toBeDefined()
      const rateLimit = meta.rateLimit as Record<string, unknown>
      expect(rateLimit.limit).toBe(30)
      expect(rateLimit.remaining).toBe(29)
    })

    it('includes upgrade hint when present', () => {
      const stub = createMockIdentityStub()
      const mcpAuth = new MCPAuth(stub)

      const meta = mcpAuth.buildMeta({
        authenticated: false,
        level: 0,
        scopes: ['read'],
        capabilities: ['explore'],
        upgrade: {
          nextLevel: 1,
          action: 'provision',
          description: 'POST to provision',
          url: 'https://id.org.ai/api/provision',
        },
      })

      expect(meta.upgrade).toBeDefined()
    })

    it('includes error when present', () => {
      const stub = createMockIdentityStub()
      const mcpAuth = new MCPAuth(stub)

      const meta = mcpAuth.buildMeta({
        authenticated: false,
        level: 0,
        scopes: ['read'],
        capabilities: ['explore'],
        error: 'Rate limit exceeded',
      })

      expect(meta.error).toBe('Rate limit exceeded')
    })
  })

  describe('Token extraction', () => {
    it('extracts API key from X-API-Key header', async () => {
      const stub = createMockIdentityStub({
        validateApiKey: vi.fn(async () => ({
          valid: true,
          identityId: 'id-1',
          level: 2 as CapabilityLevel,
        })),
        checkRateLimit: vi.fn(async () => ({
          allowed: true,
          remaining: 999,
          resetAt: Date.now() + 60000,
        })),
      })
      const mcpAuth = new MCPAuth(stub)
      const request = new Request('https://id.org.ai/mcp', {
        headers: { 'X-API-Key': 'oai_from_header' },
      })

      const result = await mcpAuth.authenticate(request)
      expect(result.authenticated).toBe(true)
    })

    it('extracts API key from query parameter', async () => {
      const stub = createMockIdentityStub({
        validateApiKey: vi.fn(async () => ({
          valid: true,
          identityId: 'id-1',
          level: 2 as CapabilityLevel,
        })),
        checkRateLimit: vi.fn(async () => ({
          allowed: true,
          remaining: 999,
          resetAt: Date.now() + 60000,
        })),
      })
      const mcpAuth = new MCPAuth(stub)
      const request = new Request('https://id.org.ai/mcp?api_key=oai_from_query')

      const result = await mcpAuth.authenticate(request)
      expect(result.authenticated).toBe(true)
    })

    it('ignores non-oai Bearer tokens for API key extraction', async () => {
      const stub = createMockIdentityStub()
      const mcpAuth = new MCPAuth(stub)
      const request = new Request('https://id.org.ai/mcp', {
        headers: { 'Authorization': 'Bearer some_random_token' },
      })

      const result = await mcpAuth.authenticate(request)
      // Should fall through to L0 since "some_random_token" is not ses_* or oai_*
      expect(result.authenticated).toBe(false)
      expect(result.level).toBe(0)
    })

    it('extracts session token from Bearer ses_* header', async () => {
      const stub = createMockIdentityStub({
        getSession: vi.fn(async () => ({
          valid: true,
          identityId: 'id-ses',
          level: 1 as CapabilityLevel,
        })),
        checkRateLimit: vi.fn(async () => ({
          allowed: true,
          remaining: 99,
          resetAt: Date.now() + 60000,
        })),
      })
      const mcpAuth = new MCPAuth(stub)
      const request = new Request('https://id.org.ai/mcp', {
        headers: { 'Authorization': 'Bearer ses_session123' },
      })

      const result = await mcpAuth.authenticate(request)
      expect(result.authenticated).toBe(true)
      expect(result.level).toBe(1)
    })
  })
})
