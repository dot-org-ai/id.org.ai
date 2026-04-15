/**
 * AuditService Unit Tests
 *
 * Tests the AuditService interface wrapping AuditLog with Result types.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { AuditServiceImpl } from '../src/server/services/audit/service'
import { AUDIT_EVENTS } from '../src/sdk/audit'
import { isOk, isErr } from '../src/sdk/foundation/result'
import { MemoryStorageAdapter } from '../src/sdk/storage'
import type { StorageAdapter } from '../src/sdk/storage'

// ── AuditService Tests ────────────────────────────────────────────────────

describe('AuditServiceImpl', () => {
  let storage: StorageAdapter
  let service: AuditServiceImpl

  beforeEach(() => {
    storage = new MemoryStorageAdapter()
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
      const failStorage: StorageAdapter = {
        async get() { return undefined },
        async put() { throw new Error('storage failure') },
        async delete() { return false },
        async list() { return new Map() },
      }

      const failService = new AuditServiceImpl({ storage: failStorage })

      await expect(failService.logFireAndForget({ event: AUDIT_EVENTS.AUTH_FAILED })).resolves.toBeUndefined()
    })
  })
})
