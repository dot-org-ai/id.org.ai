// test/session-service.test.ts
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { SessionServiceImpl } from '../src/services/auth/service'
import type { SessionData, CapabilityLevel } from '../src/services/auth/types'
import type { IdentityReader } from '../src/services/identity/types'

// ── Mock Storage ────────────────────────────────────────────────────────

function createMockStorage() {
  const store = new Map<string, unknown>()

  const storage = {
    get: vi.fn(async (key: string) => store.get(key)),
    put: vi.fn(async (key: string | Record<string, unknown>, value?: unknown) => {
      if (typeof key === 'string') {
        store.set(key, value)
      } else {
        for (const [k, v] of Object.entries(key)) {
          store.set(k, v)
        }
      }
    }),
    delete: vi.fn(async (key: string | string[]) => {
      if (Array.isArray(key)) {
        let count = 0
        for (const k of key) {
          if (store.has(k)) { store.delete(k); count++ }
        }
        return count
      }
      const had = store.has(key)
      store.delete(key)
      return had
    }),
    list: vi.fn(async (options?: { prefix?: string }) => {
      const entries = new Map<string, unknown>()
      for (const [k, v] of store) {
        if (!options?.prefix || k.startsWith(options.prefix)) {
          entries.set(k, v)
        }
      }
      return entries
    }),
    deleteAll: vi.fn(),
    getAlarm: vi.fn(),
    setAlarm: vi.fn(),
  } as unknown as DurableObjectStorage

  return { storage, store }
}

// ── Mock IdentityReader (only need get() for frozen check) ──────────────

function createMockIdentityReader(overrides: { frozen?: boolean; exists?: boolean } = {}): IdentityReader {
  return {
    get: vi.fn(async (id: string) => {
      if (overrides.exists === false) {
        return { success: false, error: { _tag: 'NotFoundError', entity: 'Identity', id } }
      }
      return {
        success: true,
        data: {
          id,
          type: 'human' as const,
          name: 'Test User',
          email: 'test@example.com',
          verified: true,
          level: 2 as CapabilityLevel,
          claimStatus: 'claimed' as const,
          frozen: overrides.frozen ?? false,
          createdAt: 1700000000000,
          updatedAt: 1700000001000,
        },
      }
    }),
    exists: vi.fn(async () => true),
  } as unknown as IdentityReader
}

// ============================================================================
// Tests
// ============================================================================

describe('SessionServiceImpl', () => {
  let storage: DurableObjectStorage
  let store: Map<string, unknown>
  let identityReader: IdentityReader
  let service: SessionServiceImpl

  beforeEach(() => {
    const mock = createMockStorage()
    storage = mock.storage
    store = mock.store
    identityReader = createMockIdentityReader()
    service = new SessionServiceImpl({ storage, identityReader })
  })

  // ── get() ──────────────────────────────────────────────────────────────

  describe('get()', () => {
    it('returns valid: false for non-ses_ tokens', async () => {
      const result = await service.get('oai_abc123')
      expect(result.valid).toBe(false)
    })

    it('returns valid: false for unknown token', async () => {
      const result = await service.get('ses_unknown')
      expect(result.valid).toBe(false)
    })

    it('returns valid: true for existing non-expired session', async () => {
      store.set('session:ses_abc', {
        identityId: 'usr_1',
        level: 2,
        createdAt: Date.now() - 1000,
        expiresAt: Date.now() + 86400000,
      })

      const result = await service.get('ses_abc')
      expect(result.valid).toBe(true)
      expect(result.identityId).toBe('usr_1')
      expect(result.level).toBe(2)
    })

    it('returns valid: false and cleans up expired session', async () => {
      store.set('session:ses_expired', {
        identityId: 'usr_1',
        level: 1,
        createdAt: Date.now() - 100000,
        expiresAt: Date.now() - 1000,
      })

      const result = await service.get('ses_expired')
      expect(result.valid).toBe(false)
      expect(store.has('session:ses_expired')).toBe(false)
    })

    it('returns valid: false when identity is frozen', async () => {
      identityReader = createMockIdentityReader({ frozen: true })
      service = new SessionServiceImpl({ storage, identityReader })

      store.set('session:ses_frozen', {
        identityId: 'usr_frozen',
        level: 2,
        createdAt: Date.now() - 1000,
        expiresAt: Date.now() + 86400000,
      })

      const result = await service.get('ses_frozen')
      expect(result.valid).toBe(false)
    })

    it('returns valid: false when identity does not exist', async () => {
      identityReader = createMockIdentityReader({ exists: false })
      service = new SessionServiceImpl({ storage, identityReader })

      store.set('session:ses_orphan', {
        identityId: 'usr_gone',
        level: 1,
        createdAt: Date.now() - 1000,
        expiresAt: Date.now() + 86400000,
      })

      const result = await service.get('ses_orphan')
      expect(result.valid).toBe(false)
    })
  })

  // ── list() ─────────────────────────────────────────────────────────────

  describe('list()', () => {
    it('returns empty array when no sessions exist', async () => {
      const result = await service.list('usr_1')
      expect(result).toEqual([])
    })

    it('returns only non-expired sessions for the given identity', async () => {
      const now = Date.now()
      store.set('session:ses_a', { identityId: 'usr_1', level: 2, createdAt: now - 1000, expiresAt: now + 86400000 })
      store.set('session:ses_b', { identityId: 'usr_1', level: 2, createdAt: now - 2000, expiresAt: now - 1000 }) // expired
      store.set('session:ses_c', { identityId: 'usr_2', level: 1, createdAt: now - 1000, expiresAt: now + 86400000 }) // different identity

      const result = await service.list('usr_1')
      expect(result).toHaveLength(1)
      expect(result[0].token).toBe('ses_a')
    })
  })

  // ── findForIdentity() ──────────────────────────────────────────────────

  describe('findForIdentity()', () => {
    it('returns null when no sessions exist', async () => {
      const result = await service.findForIdentity('usr_1')
      expect(result).toBeNull()
    })

    it('returns the first matching non-expired session', async () => {
      const now = Date.now()
      store.set('session:ses_x', { identityId: 'usr_1', level: 2, createdAt: now, expiresAt: now + 86400000 })

      const result = await service.findForIdentity('usr_1')
      expect(result).not.toBeNull()
      expect(result!.identityId).toBe('usr_1')
    })

    it('skips expired sessions', async () => {
      const now = Date.now()
      store.set('session:ses_old', { identityId: 'usr_1', level: 2, createdAt: now - 100000, expiresAt: now - 1000 })

      const result = await service.findForIdentity('usr_1')
      expect(result).toBeNull()
    })
  })

  // ── create() ───────────────────────────────────────────────────────────

  describe('create()', () => {
    it('creates a session with ses_ prefix', async () => {
      const result = await service.create('usr_1', 2)
      expect(result.success).toBe(true)
      if (result.success) {
        expect(result.data.token).toMatch(/^ses_/)
        expect(result.data.identityId).toBe('usr_1')
        expect(result.data.level).toBe(2)
        expect(result.data.expiresAt).toBeGreaterThan(Date.now())
      }
    })

    it('stores session data in storage', async () => {
      const result = await service.create('usr_1', 1)
      expect(result.success).toBe(true)
      if (result.success) {
        const stored = store.get(`session:${result.data.token}`)
        expect(stored).toBeDefined()
      }
    })

    it('uses custom TTL when provided', async () => {
      const result = await service.create('usr_1', 1, 3600000) // 1 hour
      expect(result.success).toBe(true)
      if (result.success) {
        const expectedExpiry = Date.now() + 3600000
        expect(result.data.expiresAt).toBeGreaterThan(expectedExpiry - 1000)
        expect(result.data.expiresAt).toBeLessThan(expectedExpiry + 1000)
      }
    })
  })

  // ── delete() ───────────────────────────────────────────────────────────

  describe('delete()', () => {
    it('deletes an existing session', async () => {
      store.set('session:ses_del', { identityId: 'usr_1', level: 2, createdAt: Date.now(), expiresAt: Date.now() + 86400000 })

      const result = await service.delete('ses_del')
      expect(result.success).toBe(true)
      if (result.success) expect(result.data.deleted).toBe(true)
      expect(store.has('session:ses_del')).toBe(false)
    })

    it('returns deleted: false for non-existent session', async () => {
      const result = await service.delete('ses_nope')
      expect(result.success).toBe(true)
      if (result.success) expect(result.data.deleted).toBe(false)
    })
  })

  // ── deleteAllForIdentity() ─────────────────────────────────────────────

  describe('deleteAllForIdentity()', () => {
    it('deletes all sessions for an identity', async () => {
      const now = Date.now()
      store.set('session:ses_1', { identityId: 'usr_1', level: 2, createdAt: now, expiresAt: now + 86400000 })
      store.set('session:ses_2', { identityId: 'usr_1', level: 2, createdAt: now, expiresAt: now + 86400000 })
      store.set('session:ses_3', { identityId: 'usr_2', level: 1, createdAt: now, expiresAt: now + 86400000 })

      const count = await service.deleteAllForIdentity('usr_1')
      expect(count).toBe(2)
      expect(store.has('session:ses_1')).toBe(false)
      expect(store.has('session:ses_2')).toBe(false)
      expect(store.has('session:ses_3')).toBe(true)
    })

    it('returns 0 when no sessions exist', async () => {
      const count = await service.deleteAllForIdentity('usr_none')
      expect(count).toBe(0)
    })
  })
})
