/**
 * Audit Log Unit Tests
 *
 * Tests event recording, querying, pagination, filtering, counting,
 * and the cleanup of expired tokens.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { AuditLog, AUDIT_EVENTS } from '../src/audit'
import type { CSRFToken } from '../src/csrf'
import { CSRFProtection, generateCSRFToken } from '../src/csrf'

// ── Mock DurableObjectStorage ─────────────────────────────────────────────

function createMockStorage(): DurableObjectStorage {
  const store = new Map<string, unknown>()

  return {
    get: vi.fn(async (key: string) => store.get(key)),
    put: vi.fn(async (key: string | Record<string, unknown>, value?: unknown) => {
      if (typeof key === 'string') {
        store.set(key, value)
      } else {
        // Batch put
        for (const [k, v] of Object.entries(key)) {
          store.set(k, v)
        }
      }
    }),
    delete: vi.fn(async (key: string | string[]) => {
      if (Array.isArray(key)) {
        let count = 0
        for (const k of key) {
          if (store.has(k)) {
            store.delete(k)
            count++
          }
        }
        return count
      }
      const had = store.has(key)
      store.delete(key)
      return had
    }),
    list: vi.fn(async (options?: { prefix?: string; limit?: number; reverse?: boolean; start?: string }) => {
      const entries = new Map<string, unknown>()
      const prefix = options?.prefix ?? ''
      const limit = options?.limit ?? Infinity

      // Collect matching entries
      const matchingEntries: Array<[string, unknown]> = []
      for (const [key, value] of store) {
        if (key.startsWith(prefix)) {
          if (options?.start && key <= options.start) continue
          matchingEntries.push([key, value])
        }
      }

      // Sort keys (lexicographic)
      matchingEntries.sort((a, b) => {
        if (options?.reverse) return b[0].localeCompare(a[0])
        return a[0].localeCompare(b[0])
      })

      // Apply limit
      for (let i = 0; i < Math.min(matchingEntries.length, limit); i++) {
        entries.set(matchingEntries[i][0], matchingEntries[i][1])
      }

      return entries
    }),
    // Minimal stubs for other methods
    deleteAll: vi.fn(),
    getAlarm: vi.fn(),
    setAlarm: vi.fn(),
    deleteAlarm: vi.fn(),
    sync: vi.fn(),
    transaction: vi.fn(),
    transactionSync: vi.fn(),
    getCurrentBookmark: vi.fn(),
    getBookmarkForTime: vi.fn(),
    onNextSessionRestoreBookmark: vi.fn(),
    sql: {} as any,
  } as unknown as DurableObjectStorage
}

// ── Audit Log Tests ───────────────────────────────────────────────────────

describe('AuditLog', () => {
  let storage: DurableObjectStorage
  let auditLog: AuditLog

  beforeEach(() => {
    storage = createMockStorage()
    auditLog = new AuditLog(storage)
  })

  describe('log', () => {
    it('records an audit event with auto-generated timestamp', async () => {
      const event = await auditLog.log({
        event: AUDIT_EVENTS.IDENTITY_CREATED,
        actor: 'user-123',
        target: 'identity-456',
      })

      expect(event.event).toBe('identity.created')
      expect(event.actor).toBe('user-123')
      expect(event.target).toBe('identity-456')
      expect(event.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T/)
      expect(event.key).toMatch(/^audit:/)
    })

    it('uses provided timestamp when given', async () => {
      const timestamp = '2025-01-15T12:00:00.000Z'
      const event = await auditLog.log({
        event: AUDIT_EVENTS.CLAIM_COMPLETED,
        timestamp,
      })

      expect(event.timestamp).toBe(timestamp)
      expect(event.key).toContain(timestamp)
    })

    it('includes metadata in stored event', async () => {
      const event = await auditLog.log({
        event: AUDIT_EVENTS.AUTH_FAILED,
        metadata: { reason: 'invalid_key', attempts: 3 },
      })

      expect(event.metadata).toEqual({ reason: 'invalid_key', attempts: 3 })
    })

    it('includes ip and userAgent when provided', async () => {
      const event = await auditLog.log({
        event: AUDIT_EVENTS.RATE_LIMIT_EXCEEDED,
        ip: '1.2.3.4',
        userAgent: 'TestAgent/1.0',
      })

      expect(event.ip).toBe('1.2.3.4')
      expect(event.userAgent).toBe('TestAgent/1.0')
    })

    it('stores event in DO storage with correct key format', async () => {
      const event = await auditLog.log({
        event: AUDIT_EVENTS.KEY_REGISTERED,
      })

      // Key format: audit:{timestamp}:{event}:{randomSuffix}
      const keyParts = event.key.split(':')
      expect(keyParts[0]).toBe('audit')
      // Second part is the timestamp
      expect(keyParts[1]).toMatch(/^\d{4}-\d{2}-\d{2}T/)
      // Third part (and potentially more colons in timestamp) contains the event name
      expect(event.key).toContain('key.registered')

      // Verify it was actually stored
      expect(storage.put).toHaveBeenCalled()
    })

    it('generates unique keys for events at the same timestamp', async () => {
      const events = await Promise.all([
        auditLog.log({ event: 'test.event', timestamp: '2025-01-01T00:00:00.000Z' }),
        auditLog.log({ event: 'test.event', timestamp: '2025-01-01T00:00:00.000Z' }),
        auditLog.log({ event: 'test.event', timestamp: '2025-01-01T00:00:00.000Z' }),
      ])

      const keys = new Set(events.map((e) => e.key))
      expect(keys.size).toBe(3)
    })
  })

  describe('logFromRequest', () => {
    it('extracts IP from cf-connecting-ip header', async () => {
      const request = new Request('https://example.com', {
        headers: {
          'cf-connecting-ip': '10.0.0.1',
          'user-agent': 'Mozilla/5.0',
        },
      })

      const event = await auditLog.logFromRequest(request, {
        event: AUDIT_EVENTS.AUTH_SESSION_CREATED,
      })

      expect(event.ip).toBe('10.0.0.1')
      expect(event.userAgent).toBe('Mozilla/5.0')
    })

    it('falls back to x-forwarded-for when cf-connecting-ip is missing', async () => {
      const request = new Request('https://example.com', {
        headers: {
          'x-forwarded-for': '192.168.1.1, 10.0.0.1',
        },
      })

      const event = await auditLog.logFromRequest(request, {
        event: AUDIT_EVENTS.AUTH_SESSION_CREATED,
      })

      expect(event.ip).toBe('192.168.1.1')
    })

    it('handles missing IP headers gracefully', async () => {
      const request = new Request('https://example.com')

      const event = await auditLog.logFromRequest(request, {
        event: AUDIT_EVENTS.AUTH_SESSION_CREATED,
      })

      expect(event.ip).toBeUndefined()
      expect(event.userAgent).toBeUndefined()
    })
  })

  describe('query', () => {
    beforeEach(async () => {
      // Seed events with known timestamps
      await auditLog.log({ event: 'auth.failed', actor: 'user-a', timestamp: '2025-01-01T01:00:00.000Z' })
      await auditLog.log({ event: 'auth.session.created', actor: 'user-a', timestamp: '2025-01-01T02:00:00.000Z' })
      await auditLog.log({ event: 'identity.created', actor: 'system', timestamp: '2025-01-01T03:00:00.000Z' })
      await auditLog.log({ event: 'claim.completed', actor: 'user-b', timestamp: '2025-01-01T04:00:00.000Z' })
      await auditLog.log({ event: 'auth.failed', actor: 'user-c', timestamp: '2025-01-01T05:00:00.000Z' })
    })

    it('returns all events when no filters are applied', async () => {
      const result = await auditLog.query()
      expect(result.events.length).toBe(5)
      expect(result.total).toBe(5)
      expect(result.hasMore).toBe(false)
    })

    it('respects the limit parameter', async () => {
      const result = await auditLog.query({ limit: 2 })
      expect(result.events.length).toBe(2)
      expect(result.total).toBe(2)
      expect(result.hasMore).toBe(true)
    })

    it('filters by eventPrefix', async () => {
      const result = await auditLog.query({ eventPrefix: 'auth.' })
      expect(result.events.length).toBe(3)
      for (const event of result.events) {
        expect(event.event).toMatch(/^auth\./)
      }
    })

    it('filters by actor', async () => {
      const result = await auditLog.query({ actor: 'user-a' })
      expect(result.events.length).toBe(2)
      for (const event of result.events) {
        expect(event.actor).toBe('user-a')
      }
    })

    it('filters by after timestamp', async () => {
      const result = await auditLog.query({ after: '2025-01-01T03:00:00.000Z' })
      for (const event of result.events) {
        expect(event.timestamp > '2025-01-01T03:00:00.000Z').toBe(true)
      }
    })

    it('filters by before timestamp', async () => {
      const result = await auditLog.query({ before: '2025-01-01T03:00:00.000Z' })
      for (const event of result.events) {
        expect(event.timestamp < '2025-01-01T03:00:00.000Z').toBe(true)
      }
    })

    it('enforces max limit of 200', async () => {
      const result = await auditLog.query({ limit: 500 })
      // The limit is clamped to 200, but we only have 5 events
      expect(result.events.length).toBe(5)
    })

    it('enforces min limit of 1', async () => {
      const result = await auditLog.query({ limit: 0 })
      expect(result.events.length).toBe(1)
    })

    it('includes cursor for pagination when hasMore is true', async () => {
      const page1 = await auditLog.query({ limit: 2 })
      expect(page1.hasMore).toBe(true)
      expect(page1.cursor).toBeDefined()
    })

    it('does not include cursor when hasMore is false', async () => {
      const result = await auditLog.query({ limit: 50 })
      expect(result.hasMore).toBe(false)
      expect(result.cursor).toBeUndefined()
    })
  })

  describe('count', () => {
    beforeEach(async () => {
      await auditLog.log({ event: 'auth.failed', timestamp: '2025-01-01T01:00:00.000Z' })
      await auditLog.log({ event: 'auth.failed', timestamp: '2025-01-01T02:00:00.000Z' })
      await auditLog.log({ event: 'identity.created', timestamp: '2025-01-01T03:00:00.000Z' })
    })

    it('counts all events with no filter', async () => {
      const count = await auditLog.count()
      expect(count).toBe(3)
    })

    it('counts events by eventPrefix', async () => {
      const count = await auditLog.count({ eventPrefix: 'auth.' })
      expect(count).toBe(2)
    })

    it('counts events after a timestamp', async () => {
      const count = await auditLog.count({ after: '2025-01-01T01:30:00.000Z' })
      expect(count).toBe(2)
    })

    it('returns 0 for no matching events', async () => {
      const count = await auditLog.count({ eventPrefix: 'nonexistent.' })
      expect(count).toBe(0)
    })
  })
})

// ── Audit Event Constants ─────────────────────────────────────────────────

describe('AUDIT_EVENTS', () => {
  it('has all expected event constants', () => {
    expect(AUDIT_EVENTS.IDENTITY_CREATED).toBe('identity.created')
    expect(AUDIT_EVENTS.IDENTITY_FROZEN).toBe('identity.frozen')
    expect(AUDIT_EVENTS.CLAIM_INITIATED).toBe('claim.initiated')
    expect(AUDIT_EVENTS.CLAIM_COMPLETED).toBe('claim.completed')
    expect(AUDIT_EVENTS.CLAIM_FAILED).toBe('claim.failed')
    expect(AUDIT_EVENTS.CLAIM_VERIFIED).toBe('claim.verified')
    expect(AUDIT_EVENTS.AUTH_SESSION_CREATED).toBe('auth.session.created')
    expect(AUDIT_EVENTS.AUTH_SESSION_EXPIRED).toBe('auth.session.expired')
    expect(AUDIT_EVENTS.AUTH_FAILED).toBe('auth.failed')
    expect(AUDIT_EVENTS.AUTH_API_KEY_VALIDATED).toBe('auth.apikey.validated')
    expect(AUDIT_EVENTS.AUTH_API_KEY_INVALID).toBe('auth.apikey.invalid')
    expect(AUDIT_EVENTS.KEY_REGISTERED).toBe('key.registered')
    expect(AUDIT_EVENTS.KEY_REVOKED).toBe('key.revoked')
    expect(AUDIT_EVENTS.KEY_SIGNATURE_VERIFIED).toBe('key.signature.verified')
    expect(AUDIT_EVENTS.KEY_SIGNATURE_FAILED).toBe('key.signature.failed')
    expect(AUDIT_EVENTS.RATE_LIMIT_EXCEEDED).toBe('rate_limit.exceeded')
    expect(AUDIT_EVENTS.CSRF_VALIDATION_FAILED).toBe('csrf.validation.failed')
    expect(AUDIT_EVENTS.OAUTH_CLIENT_REGISTERED).toBe('oauth.client.registered')
    expect(AUDIT_EVENTS.OAUTH_CODE_ISSUED).toBe('oauth.code.issued')
    expect(AUDIT_EVENTS.OAUTH_TOKEN_ISSUED).toBe('oauth.token.issued')
    expect(AUDIT_EVENTS.OAUTH_TOKEN_REVOKED).toBe('oauth.token.revoked')
  })

  it('uses dot-separated namespacing', () => {
    for (const [, value] of Object.entries(AUDIT_EVENTS)) {
      // All event names should contain at least one dot or underscore
      expect(value).toMatch(/[._]/)
    }
  })
})

// ── CSRFProtection Class ──────────────────────────────────────────────────

describe('CSRFProtection', () => {
  let storage: DurableObjectStorage
  let csrf: CSRFProtection

  beforeEach(() => {
    storage = createMockStorage()
    csrf = new CSRFProtection(storage)
  })

  describe('generate', () => {
    it('returns a hex token string', async () => {
      const token = await csrf.generate()
      expect(token).toMatch(/^[0-9a-f]{64}$/)
    })

    it('stores the token in DO storage', async () => {
      const token = await csrf.generate()
      expect(storage.put).toHaveBeenCalledWith(`csrf:${token}`, expect.objectContaining({
        token,
        createdAt: expect.any(Number),
        expiresAt: expect.any(Number),
      }))
    })

    it('sets expiration ~30 minutes from now', async () => {
      const before = Date.now()
      const token = await csrf.generate()
      const after = Date.now()

      const stored = await storage.get(`csrf:${token}`) as CSRFToken
      expect(stored).toBeDefined()
      // Expiration should be within 30 minutes (+/- a few ms for execution time)
      const thirtyMinutes = 30 * 60 * 1000
      expect(stored.expiresAt).toBeGreaterThanOrEqual(before + thirtyMinutes)
      expect(stored.expiresAt).toBeLessThanOrEqual(after + thirtyMinutes)
    })
  })

  describe('validate', () => {
    it('returns valid when cookie and form tokens match and exist in storage', async () => {
      const token = await csrf.generate()
      const result = await csrf.validate(token, token)
      expect(result.valid).toBe(true)
    })

    it('returns invalid when cookie token is null', async () => {
      const token = await csrf.generate()
      const result = await csrf.validate(null, token)
      expect(result.valid).toBe(false)
      expect(result.error).toContain('Missing')
    })

    it('returns invalid when form token is null', async () => {
      const token = await csrf.generate()
      const result = await csrf.validate(token, null)
      expect(result.valid).toBe(false)
      expect(result.error).toContain('Missing')
    })

    it('returns invalid when tokens do not match', async () => {
      const token = await csrf.generate()
      const result = await csrf.validate(token, 'different_token_value_00000000000000000000000000000000')
      expect(result.valid).toBe(false)
      expect(result.error).toContain('mismatch')
    })

    it('returns invalid for unknown tokens', async () => {
      const fakeToken = '0'.repeat(64)
      const result = await csrf.validate(fakeToken, fakeToken)
      expect(result.valid).toBe(false)
      expect(result.error).toContain('Unknown')
    })

    it('consumes the token after successful validation (one-time use)', async () => {
      const token = await csrf.generate()

      // First validation should succeed
      const result1 = await csrf.validate(token, token)
      expect(result1.valid).toBe(true)

      // Second validation should fail (token consumed)
      const result2 = await csrf.validate(token, token)
      expect(result2.valid).toBe(false)
      expect(result2.error).toContain('Unknown')
    })

    it('returns invalid for expired tokens', async () => {
      const token = await csrf.generate()

      // Manually expire the token by overwriting with past expiration
      await storage.put(`csrf:${token}`, {
        token,
        createdAt: Date.now() - 60 * 60 * 1000,
        expiresAt: Date.now() - 1000, // expired 1 second ago
      })

      const result = await csrf.validate(token, token)
      expect(result.valid).toBe(false)
      expect(result.error).toContain('expired')
    })

    it('deletes expired tokens during validation', async () => {
      const token = await csrf.generate()

      // Expire the token
      await storage.put(`csrf:${token}`, {
        token,
        createdAt: Date.now() - 60 * 60 * 1000,
        expiresAt: Date.now() - 1000,
      })

      await csrf.validate(token, token)
      const stored = await storage.get(`csrf:${token}`)
      expect(stored).toBeUndefined()
    })
  })

  describe('cleanup', () => {
    it('removes expired tokens', async () => {
      // Create an expired token manually
      await storage.put('csrf:expired1', {
        token: 'expired1',
        createdAt: Date.now() - 60 * 60 * 1000,
        expiresAt: Date.now() - 1000,
      })

      // Create a valid token
      await csrf.generate()

      const cleaned = await csrf.cleanup()
      expect(cleaned).toBe(1)
    })

    it('leaves valid tokens untouched', async () => {
      const token = await csrf.generate()
      const cleaned = await csrf.cleanup()
      expect(cleaned).toBe(0)

      // Token should still be valid
      const result = await csrf.validate(token, token)
      expect(result.valid).toBe(true)
    })

    it('returns 0 when no expired tokens exist', async () => {
      const cleaned = await csrf.cleanup()
      expect(cleaned).toBe(0)
    })
  })
})
