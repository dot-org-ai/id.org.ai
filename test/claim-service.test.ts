/**
 * ClaimService and verifyClaim Unit Tests
 *
 * Tests anonymous provisioning, freeze, status, and claim token verification.
 */

import { describe, it, expect, vi } from 'vitest'
import { ClaimService } from '../src/claim/provision'
import { verifyClaim } from '../src/claim/verify'

// ── Mock Identity Stub ──────────────────────────────────────────────────

function createMockStub(handlers: Record<string, (path: string, request: Request) => Promise<Response> | Response> = {}) {
  return {
    fetch: vi.fn(async (input: string | Request): Promise<Response> => {
      const request = typeof input === 'string' ? new Request(input) : input
      const url = new URL(request.url)
      const path = url.pathname

      for (const [pattern, handler] of Object.entries(handlers)) {
        if (path === pattern || path.startsWith(pattern)) {
          return handler(path, request)
        }
      }

      return new Response(JSON.stringify({ error: 'not_found' }), { status: 404 })
    }),
  }
}

// ── ClaimService Tests ──────────────────────────────────────────────────

describe('ClaimService', () => {
  describe('provision', () => {
    it('provisions an anonymous tenant and returns session + claim tokens', async () => {
      const stub = createMockStub({
        '/api/provision': () => Response.json({
          identity: { id: 'uuid-123', name: 'anon_abc', level: 1 },
          sessionToken: 'ses_token123',
          claimToken: 'clm_claim456',
        }),
      })

      const service = new ClaimService(stub)
      const result = await service.provision()

      expect(result.tenantId).toBe('anon_abc')
      expect(result.identityId).toBe('uuid-123')
      expect(result.sessionToken).toBe('ses_token123')
      expect(result.claimToken).toBe('clm_claim456')
      expect(result.level).toBe(1)
    })

    it('includes correct limits for L1 tenant', async () => {
      const stub = createMockStub({
        '/api/provision': () => Response.json({
          identity: { id: 'id-1', name: 'anon_1', level: 1 },
          sessionToken: 'ses_1',
          claimToken: 'clm_1',
        }),
      })

      const service = new ClaimService(stub)
      const result = await service.provision()

      expect(result.limits.maxEntities).toBe(1000)
      expect(result.limits.ttlHours).toBe(24)
      expect(result.limits.maxRequestsPerMinute).toBe(100)
    })

    it('includes upgrade hint to L2 (claim)', async () => {
      const stub = createMockStub({
        '/api/provision': () => Response.json({
          identity: { id: 'id-1', name: 'anon_1', level: 1 },
          sessionToken: 'ses_1',
          claimToken: 'clm_1',
        }),
      })

      const service = new ClaimService(stub)
      const result = await service.provision()

      expect(result.upgrade.nextLevel).toBe(2)
      expect(result.upgrade.action).toBe('claim')
      expect(result.upgrade.url).toContain('clm_1')
    })

    it('throws on provision failure', async () => {
      const stub = createMockStub({
        '/api/provision': () => new Response('Internal Server Error', { status: 500 }),
      })

      const service = new ClaimService(stub)

      await expect(service.provision()).rejects.toThrow('Provision failed')
    })
  })

  describe('freeze', () => {
    it('freezes an identity and returns stats', async () => {
      const stub = createMockStub({
        '/api/freeze/': () => Response.json({
          frozen: true,
          stats: { entities: 42, events: 128, sessions: 2 },
          expiresAt: Date.now() + 30 * 24 * 60 * 60 * 1000,
        }),
      })

      const service = new ClaimService(stub)
      const result = await service.freeze('id-123')

      expect(result.frozen).toBe(true)
      expect(result.identityId).toBe('id-123')
      expect(result.stats.entities).toBe(42)
      expect(result.stats.events).toBe(128)
      expect(result.stats.sessions).toBe(2)
    })

    it('includes claim URL in freeze result', async () => {
      const stub = createMockStub({
        '/api/freeze/': () => Response.json({
          frozen: true,
          stats: { entities: 0, events: 0, sessions: 0 },
          expiresAt: Date.now() + 30 * 24 * 60 * 60 * 1000,
        }),
      })

      const service = new ClaimService(stub)
      const result = await service.freeze('id-123')

      expect(result.claimUrl).toContain('id-123')
    })

    it('generates appropriate message based on entity count', async () => {
      const stub = createMockStub({
        '/api/freeze/': () => Response.json({
          frozen: true,
          stats: { entities: 10, events: 50, sessions: 1 },
          expiresAt: Date.now() + 30 * 24 * 60 * 60 * 1000,
        }),
      })

      const service = new ClaimService(stub)
      const result = await service.freeze('id-123')

      expect(result.message).toContain('10 entities')
      expect(result.message).toContain('50 events')
    })

    it('generates simpler message when no entities exist', async () => {
      const stub = createMockStub({
        '/api/freeze/': () => Response.json({
          frozen: true,
          stats: { entities: 0, events: 0, sessions: 0 },
          expiresAt: Date.now() + 30 * 24 * 60 * 60 * 1000,
        }),
      })

      const service = new ClaimService(stub)
      const result = await service.freeze('id-empty')

      expect(result.message).toContain('frozen')
      expect(result.message).not.toContain('entities')
    })

    it('throws on freeze failure', async () => {
      const stub = createMockStub({
        '/api/freeze/': () => new Response('Not Found', { status: 404 }),
      })

      const service = new ClaimService(stub)

      await expect(service.freeze('id-missing')).rejects.toThrow('Freeze failed')
    })
  })

  describe('getStatus', () => {
    it('returns tenant status for valid claim token', async () => {
      const stub = createMockStub({
        '/api/verify-claim': () => Response.json({
          valid: true,
          identityId: 'id-status',
          status: 'unclaimed',
          level: 1,
          stats: {
            entities: 5,
            events: 10,
            createdAt: Date.now() - 86400000,
          },
        }),
      })

      const service = new ClaimService(stub)
      const result = await service.getStatus('clm_statustoken')

      expect(result.identityId).toBe('id-status')
      expect(result.level).toBe(1)
      expect(result.claimStatus).toBe('unclaimed')
      expect(result.frozen).toBe(false)
    })

    it('includes upgrade path for L1 users', async () => {
      const stub = createMockStub({
        '/api/verify-claim': () => Response.json({
          valid: true,
          identityId: 'id-l1',
          status: 'unclaimed',
          level: 1,
        }),
      })

      const service = new ClaimService(stub)
      const result = await service.getStatus('clm_token')

      expect(result.upgrade).toBeDefined()
      expect(result.upgrade!.nextLevel).toBe(2)
      expect(result.upgrade!.action).toBe('claim')
    })

    it('throws for invalid claim token', async () => {
      const stub = createMockStub({
        '/api/verify-claim': () => Response.json({ valid: false }),
      })

      const service = new ClaimService(stub)

      await expect(service.getStatus('clm_invalid')).rejects.toThrow('Invalid or expired claim token')
    })
  })
})

// ── verifyClaim Tests ───────────────────────────────────────────────────

describe('verifyClaim', () => {
  it('rejects tokens that do not start with clm_', async () => {
    const stub = createMockStub()
    const result = await verifyClaim('invalid_token', stub)
    expect(result.valid).toBe(false)
  })

  it('rejects empty tokens', async () => {
    const stub = createMockStub()
    const result = await verifyClaim('', stub)
    expect(result.valid).toBe(false)
  })

  it('rejects tokens shorter than 20 characters', async () => {
    const stub = createMockStub()
    const result = await verifyClaim('clm_short', stub)
    expect(result.valid).toBe(false)
  })

  it('returns valid status for a good claim token', async () => {
    const createdAt = Date.now() - 3600000
    const stub = createMockStub({
      '/api/verify-claim': () => Response.json({
        valid: true,
        identityId: 'id-verified',
        status: 'unclaimed',
        level: 1,
        stats: {
          entities: 3,
          events: 7,
          createdAt,
        },
      }),
    })

    const result = await verifyClaim('clm_validtoken1234567890', stub)

    expect(result.valid).toBe(true)
    expect(result.identityId).toBe('id-verified')
    expect(result.status).toBe('unclaimed')
    expect(result.level).toBe(1)
    expect(result.stats).toBeDefined()
    expect(result.stats!.entities).toBe(3)
    expect(result.stats!.events).toBe(7)
  })

  it('includes upgrade path for unclaimed L1 token', async () => {
    const stub = createMockStub({
      '/api/verify-claim': () => Response.json({
        valid: true,
        identityId: 'id-1',
        status: 'unclaimed',
        level: 1,
        stats: { entities: 0, events: 0, createdAt: Date.now() },
      }),
    })

    const result = await verifyClaim('clm_upgradetoken12345678', stub)

    expect(result.upgrade).toBeDefined()
    expect(result.upgrade!.nextLevel).toBe(2)
    expect(result.upgrade!.action).toBe('claim')
  })

  it('includes L3 upgrade for L2 token', async () => {
    const stub = createMockStub({
      '/api/verify-claim': () => Response.json({
        valid: true,
        identityId: 'id-2',
        status: 'unclaimed',
        level: 2,
        stats: { entities: 0, events: 0, createdAt: Date.now() },
      }),
    })

    const result = await verifyClaim('clm_l2token123456789012', stub)

    expect(result.upgrade).toBeDefined()
    expect(result.upgrade!.nextLevel).toBe(3)
    expect(result.upgrade!.action).toBe('subscribe')
  })

  it('does not include upgrade for claimed tokens', async () => {
    const stub = createMockStub({
      '/api/verify-claim': () => Response.json({
        valid: true,
        identityId: 'id-claimed',
        status: 'claimed',
        level: 2,
        stats: { entities: 100, events: 500, createdAt: Date.now() - 86400000 },
      }),
    })

    const result = await verifyClaim('clm_claimedtoken1234567', stub)

    expect(result.valid).toBe(true)
    expect(result.status).toBe('claimed')
    expect(result.upgrade).toBeUndefined()
  })

  it('returns invalid for non-ok response from DO', async () => {
    const stub = createMockStub({
      '/api/verify-claim': () => new Response('Server Error', { status: 500 }),
    })

    const result = await verifyClaim('clm_servererror123456789', stub)
    expect(result.valid).toBe(false)
  })

  it('converts timestamps to ISO strings', async () => {
    const createdAt = 1706745600000 // 2024-02-01T00:00:00.000Z
    const expiresAt = 1709337600000 // 2024-03-02T00:00:00.000Z
    const stub = createMockStub({
      '/api/verify-claim': () => Response.json({
        valid: true,
        identityId: 'id-ts',
        status: 'unclaimed',
        level: 1,
        stats: { entities: 0, events: 0, createdAt, expiresAt },
      }),
    })

    const result = await verifyClaim('clm_timestamptoken1234567', stub)

    expect(result.stats!.createdAt).toMatch(/^\d{4}-\d{2}-\d{2}T/)
    expect(result.stats!.expiresAt).toMatch(/^\d{4}-\d{2}-\d{2}T/)
  })
})
