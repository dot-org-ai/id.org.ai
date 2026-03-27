/**
 * AuditService Unit Tests
 *
 * Tests the AuditService interface wrapping AuditLog with Result types.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { AuditServiceImpl } from '../src/services/audit/service'
import { AUDIT_EVENTS } from '../src/audit'
import { isOk, isErr } from '../src/foundation/result'

// ── Mock DurableObjectStorage ─────────────────────────────────────────────

function createMockStorage(): DurableObjectStorage {
  const store = new Map<string, unknown>()

  return {
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

      const matchingEntries: Array<[string, unknown]> = []
      for (const [key, value] of store) {
        if (key.startsWith(prefix)) {
          if (options?.start && key <= options.start) continue
          matchingEntries.push([key, value])
        }
      }

      matchingEntries.sort((a, b) => {
        if (options?.reverse) return b[0].localeCompare(a[0])
        return a[0].localeCompare(b[0])
      })

      for (let i = 0; i < Math.min(matchingEntries.length, limit); i++) {
        entries.set(matchingEntries[i][0], matchingEntries[i][1])
      }

      return entries
    }),
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

// ── AuditService Tests ────────────────────────────────────────────────────

describe('AuditServiceImpl', () => {
  let storage: DurableObjectStorage
  let service: AuditServiceImpl

  beforeEach(() => {
    storage = createMockStorage()
    service = new AuditServiceImpl({ storage })
  })

  describe('log()', () => {
    it('records an event and returns Ok with StoredAuditEvent', async () => {
      const result = await service.log({
        event: AUDIT_EVENTS.IDENTITY_CREATED,
        actor: 'user-123',
        target: 'identity-456',
      })

      expect(isOk(result)).toBe(true)
      if (!isOk(result)) return

      expect(result.data.event).toBe('identity.created')
      expect(result.data.actor).toBe('user-123')
      expect(result.data.target).toBe('identity-456')
      expect(result.data.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T/)
      expect(result.data.key).toMatch(/^audit:/)
    })

    it('returns Err with ValidationError when event is empty string', async () => {
      const result = await service.log({ event: '' })

      expect(isErr(result)).toBe(true)
      if (!isErr(result)) return

      expect(result.error._tag).toBe('ValidationError')
      expect(result.error.field).toBe('event')
    })

    it('returns Err with ValidationError when event is whitespace-only', async () => {
      const result = await service.log({ event: '   ' })

      expect(isErr(result)).toBe(true)
      if (!isErr(result)) return

      expect(result.error._tag).toBe('ValidationError')
      expect(result.error.field).toBe('event')
    })

    it('uses provided timestamp when given', async () => {
      const timestamp = '2025-01-15T12:00:00.000Z'
      const result = await service.log({ event: AUDIT_EVENTS.AUTH_FAILED, timestamp })

      expect(isOk(result)).toBe(true)
      if (!isOk(result)) return

      expect(result.data.timestamp).toBe(timestamp)
    })
  })

  describe('query()', () => {
    beforeEach(async () => {
      await service.log({ event: 'auth.failed', actor: 'user-a', timestamp: '2025-01-01T01:00:00.000Z' })
      await service.log({ event: 'auth.session.created', actor: 'user-a', timestamp: '2025-01-01T02:00:00.000Z' })
      await service.log({ event: 'identity.created', actor: 'system', timestamp: '2025-01-01T03:00:00.000Z' })
    })

    it('returns paginated events directly (not wrapped in Result)', async () => {
      const result = await service.query({})

      expect(result).toHaveProperty('events')
      expect(result).toHaveProperty('total')
      expect(result).toHaveProperty('hasMore')
      expect(result.events.length).toBe(3)
    })

    it('filters by eventPrefix', async () => {
      const result = await service.query({ eventPrefix: 'auth.' })

      expect(result.events.length).toBe(2)
      for (const event of result.events) {
        expect(event.event).toMatch(/^auth\./)
      }
    })

    it('respects limit', async () => {
      const result = await service.query({ limit: 1 })

      expect(result.events.length).toBe(1)
      expect(result.hasMore).toBe(true)
    })
  })

  describe('logFireAndForget()', () => {
    it('logs without throwing', async () => {
      await expect(
        service.logFireAndForget({ event: AUDIT_EVENTS.KEY_REGISTERED, actor: 'agent-1' }),
      ).resolves.toBeUndefined()
    })

    it('swallows storage errors silently', async () => {
      const failStorage = createMockStorage()
      ;(failStorage.put as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('storage failure'))

      const failService = new AuditServiceImpl({ storage: failStorage })

      await expect(failService.logFireAndForget({ event: AUDIT_EVENTS.AUTH_FAILED })).resolves.toBeUndefined()
    })
  })
})
