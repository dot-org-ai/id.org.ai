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

// ── Mock Identity Stub ──────────────────────────────────────────────────

function createMockStub(handlers: Record<string, (url: string, request: Request) => Promise<Response> | Response> = {}) {
  return {
    fetch: vi.fn(async (input: string | Request): Promise<Response> => {
      const request = typeof input === 'string' ? new Request(input) : input
      const url = new URL(request.url)
      const path = url.pathname

      for (const [pattern, handler] of Object.entries(handlers)) {
        if (path.startsWith(pattern)) {
          return handler(path, request)
        }
      }

      return new Response(JSON.stringify({ error: 'not_found' }), { status: 404 })
    }),
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
      const stub = createMockStub()
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
      const stub = createMockStub()
      const mcpAuth = new MCPAuth(stub)
      const request = makeRequest()

      const result = await mcpAuth.authenticate(request)

      expect(result.upgrade).toBeDefined()
      expect(result.upgrade!.nextLevel).toBe(1)
      expect(result.upgrade!.action).toBe('provision')
      expect(result.upgrade!.url).toBe('https://id.org.ai/api/provision')
    })

    it('provides rate limit info for anonymous users', async () => {
      const stub = createMockStub()
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
      const stub = createMockStub({
        '/api/session/': () => Response.json({
          valid: true,
          identityId: 'id-123',
          level: 1,
          expiresAt: Date.now() + 86400000,
        }),
        '/api/rate-limit/': () => Response.json({
          allowed: true,
          remaining: 99,
          resetAt: Date.now() + 60000,
          level: 1,
        }),
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
      const stub = createMockStub({
        '/api/session/': () => Response.json({
          valid: true,
          identityId: 'id-123',
          level: 1,
          expiresAt: Date.now() + 86400000,
        }),
        '/api/rate-limit/': () => Response.json({
          allowed: true,
          remaining: 99,
          resetAt: Date.now() + 60000,
          level: 1,
        }),
      })
      const mcpAuth = new MCPAuth(stub)
      const request = makeRequest({ sessionToken: 'ses_abc123' })

      const result = await mcpAuth.authenticate(request)

      expect(result.upgrade).toBeDefined()
      expect(result.upgrade!.nextLevel).toBe(2)
      expect(result.upgrade!.action).toBe('claim')
    })

    it('falls back to L0 for invalid session token', async () => {
      const stub = createMockStub({
        '/api/session/': () => Response.json({ valid: false }),
      })
      const mcpAuth = new MCPAuth(stub)
      const request = makeRequest({ sessionToken: 'ses_invalid' })

      const result = await mcpAuth.authenticate(request)

      expect(result.authenticated).toBe(false)
      expect(result.level).toBe(0)
      expect(result.error).toBe('Invalid or expired session token')
    })

    it('reports rate limit exceeded for L1', async () => {
      const stub = createMockStub({
        '/api/session/': () => Response.json({
          valid: true,
          identityId: 'id-123',
          level: 1,
          expiresAt: Date.now() + 86400000,
        }),
        '/api/rate-limit/': () => Response.json({
          allowed: false,
          remaining: 0,
          resetAt: Date.now() + 30000,
          level: 1,
        }),
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
      const stub = createMockStub({
        '/api/validate-key': async (_path, req) => {
          const body = await req.json() as { key: string }
          if (body.key === 'oai_validkey123') {
            return Response.json({
              valid: true,
              identityId: 'id-456',
              scopes: ['read', 'write'],
              level: 2,
            })
          }
          return Response.json({ valid: false })
        },
        '/api/rate-limit/': () => Response.json({
          allowed: true,
          remaining: 999,
          resetAt: Date.now() + 60000,
          level: 2,
        }),
      })
      const mcpAuth = new MCPAuth(stub)
      const request = makeRequest({ apiKey: 'oai_validkey123' })

      const result = await mcpAuth.authenticate(request)

      expect(result.authenticated).toBe(true)
      expect(result.level).toBe(2)
      expect(result.identityId).toBe('id-456')
    })

    it('authenticates valid API key via Bearer header', async () => {
      const stub = createMockStub({
        '/api/validate-key': async () => Response.json({
          valid: true,
          identityId: 'id-789',
          level: 3,
        }),
        '/api/rate-limit/': () => Response.json({
          allowed: true,
          remaining: Infinity,
          resetAt: 0,
          level: 3,
        }),
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
      const stub = createMockStub({
        '/api/validate-key': async () => Response.json({ valid: false }),
      })
      const mcpAuth = new MCPAuth(stub)
      const request = makeRequest({ apiKey: 'oai_invalidkey' })

      const result = await mcpAuth.authenticate(request)

      expect(result.authenticated).toBe(false)
      expect(result.level).toBe(0)
      expect(result.error).toBe('Invalid API key')
    })

    it('includes upgrade hint to L3 for L2 users', async () => {
      const stub = createMockStub({
        '/api/validate-key': async () => Response.json({
          valid: true,
          identityId: 'id-456',
          level: 2,
        }),
        '/api/rate-limit/': () => Response.json({
          allowed: true,
          remaining: 999,
          resetAt: Date.now() + 60000,
          level: 2,
        }),
      })
      const mcpAuth = new MCPAuth(stub)
      const request = makeRequest({ apiKey: 'oai_validkey' })

      const result = await mcpAuth.authenticate(request)

      expect(result.upgrade).toBeDefined()
      expect(result.upgrade!.nextLevel).toBe(3)
      expect(result.upgrade!.action).toBe('subscribe')
    })

    it('API key takes priority over session token', async () => {
      const stub = createMockStub({
        '/api/validate-key': async () => Response.json({
          valid: true,
          identityId: 'id-apikey',
          level: 2,
        }),
        '/api/rate-limit/': () => Response.json({
          allowed: true,
          remaining: 999,
          resetAt: Date.now() + 60000,
          level: 2,
        }),
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
      const stub = createMockStub()
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
      const stub = createMockStub()
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
      const stub = createMockStub()
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
      const stub = createMockStub()
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
      const stub = createMockStub({
        '/api/validate-key': async () => Response.json({
          valid: true,
          identityId: 'id-1',
          level: 2,
        }),
        '/api/rate-limit/': () => Response.json({
          allowed: true,
          remaining: 999,
          resetAt: Date.now() + 60000,
          level: 2,
        }),
      })
      const mcpAuth = new MCPAuth(stub)
      const request = new Request('https://id.org.ai/mcp', {
        headers: { 'X-API-Key': 'oai_from_header' },
      })

      const result = await mcpAuth.authenticate(request)
      expect(result.authenticated).toBe(true)
    })

    it('extracts API key from query parameter', async () => {
      const stub = createMockStub({
        '/api/validate-key': async () => Response.json({
          valid: true,
          identityId: 'id-1',
          level: 2,
        }),
        '/api/rate-limit/': () => Response.json({
          allowed: true,
          remaining: 999,
          resetAt: Date.now() + 60000,
          level: 2,
        }),
      })
      const mcpAuth = new MCPAuth(stub)
      const request = new Request('https://id.org.ai/mcp?api_key=oai_from_query')

      const result = await mcpAuth.authenticate(request)
      expect(result.authenticated).toBe(true)
    })

    it('ignores non-oai Bearer tokens for API key extraction', async () => {
      const stub = createMockStub()
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
      const stub = createMockStub({
        '/api/session/': () => Response.json({
          valid: true,
          identityId: 'id-ses',
          level: 1,
        }),
        '/api/rate-limit/': () => Response.json({
          allowed: true,
          remaining: 99,
          resetAt: Date.now() + 60000,
          level: 1,
        }),
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
