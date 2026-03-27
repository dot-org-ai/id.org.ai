import { describe, it, expect, beforeEach } from 'vitest'
import { IdentityServiceImpl } from '../src/services/identity/service'
import { AuditServiceImpl } from '../src/services/audit/service'
import type { Identity } from '../src/services/identity/types'

// ============================================================================
// Mock Storage
// ============================================================================

function createMockStorage(data: Map<string, unknown> = new Map()): DurableObjectStorage {
  const backing = data
  return {
    async get(key: string | string[]) {
      if (Array.isArray(key)) {
        const result = new Map()
        for (const k of key) result.set(k, backing.get(k))
        return result
      }
      return backing.get(key)
    },
    async put(key: string | Record<string, unknown>, value?: unknown) {
      if (typeof key === 'string') {
        backing.set(key, value)
      } else {
        for (const [k, v] of Object.entries(key)) backing.set(k, v)
      }
    },
    async delete(key: string | string[]) {
      if (Array.isArray(key)) {
        let count = 0
        for (const k of key) if (backing.delete(k)) count++
        return count
      }
      return backing.delete(key)
    },
    async list(options?: { prefix?: string; limit?: number; cursor?: string }) {
      const prefix = options?.prefix ?? ''
      const result = new Map()
      for (const [k, v] of backing) {
        if (k.startsWith(prefix)) result.set(k, v)
      }
      return result
    },
  } as unknown as DurableObjectStorage
}

// ============================================================================
// Fixtures
// ============================================================================

const sampleRaw = {
  id: 'usr_abc123',
  type: 'human' as const,
  name: 'Alice Example',
  email: 'alice@example.com',
  verified: true,
  level: 2,
  claimStatus: 'claimed' as const,
  frozen: false,
  createdAt: 1700000000000,
  updatedAt: 1700000001000,
}

// ============================================================================
// Tests
// ============================================================================

describe('IdentityServiceImpl', () => {
  let storage: DurableObjectStorage
  let backingMap: Map<string, unknown>
  let service: IdentityServiceImpl

  beforeEach(() => {
    backingMap = new Map()
    storage = createMockStorage(backingMap)
    const audit = new AuditServiceImpl({ storage })
    service = new IdentityServiceImpl({ storage, audit })
  })

  // --------------------------------------------------------------------------
  // get()
  // --------------------------------------------------------------------------

  describe('get()', () => {
    it('returns NotFoundError for missing identity', async () => {
      const result = await service.get('usr_missing')
      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error._tag).toBe('NotFoundError')
        expect(result.error.entity).toBe('Identity')
        expect(result.error.id).toBe('usr_missing')
      }
    })

    it('returns identity when it exists', async () => {
      backingMap.set('identity:usr_abc123', sampleRaw)

      const result = await service.get('usr_abc123')
      expect(result.success).toBe(true)
      if (result.success) {
        const identity: Identity = result.data
        expect(identity.id).toBe('usr_abc123')
        expect(identity.type).toBe('human')
        expect(identity.name).toBe('Alice Example')
        expect(identity.email).toBe('alice@example.com')
        expect(identity.verified).toBe(true)
        expect(identity.level).toBe(2)
        expect(identity.claimStatus).toBe('claimed')
        expect(identity.frozen).toBe(false)
        expect(identity.createdAt).toBe(1700000000000)
        expect(identity.updatedAt).toBe(1700000001000)
      }
    })

    it('applies defaults for optional fields when absent', async () => {
      const minimal = { id: 'usr_min', type: 'agent' as const, name: 'Bot' }
      backingMap.set('identity:usr_min', minimal)

      const result = await service.get('usr_min')
      expect(result.success).toBe(true)
      if (result.success) {
        expect(result.data.verified).toBe(false)
        expect(result.data.level).toBe(0)
        expect(result.data.claimStatus).toBe('unclaimed')
        expect(result.data.frozen).toBe(false)
        expect(typeof result.data.createdAt).toBe('number')
        expect(typeof result.data.updatedAt).toBe('number')
      }
    })
  })

  // --------------------------------------------------------------------------
  // exists()
  // --------------------------------------------------------------------------

  describe('exists()', () => {
    it('returns false for missing identity', async () => {
      const found = await service.exists('usr_missing')
      expect(found).toBe(false)
    })

    it('returns true for existing identity', async () => {
      backingMap.set('identity:usr_abc123', sampleRaw)
      const found = await service.exists('usr_abc123')
      expect(found).toBe(true)
    })
  })
})
