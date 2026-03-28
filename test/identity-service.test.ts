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

  // --------------------------------------------------------------------------
  // createHuman()
  // --------------------------------------------------------------------------

  describe('createHuman()', () => {
    it('creates a human identity at level 2 / claimed', async () => {
      const result = await service.createHuman({ name: 'Bob Smith', email: 'bob@example.com' })
      expect(result.success).toBe(true)
      if (result.success) {
        const identity = result.data
        expect(identity.type).toBe('human')
        expect(identity.name).toBe('Bob Smith')
        expect(identity.email).toBe('bob@example.com')
        expect(identity.verified).toBe(true)
        expect(identity.level).toBe(2)
        expect(identity.claimStatus).toBe('claimed')
        expect(identity.frozen).toBe(false)
        expect(typeof identity.id).toBe('string')
        expect(identity.id.length).toBeGreaterThan(0)
        expect(typeof identity.createdAt).toBe('number')
      }
    })

    it('stores the identity in storage and creates email index', async () => {
      const result = await service.createHuman({ name: 'Carol', email: 'carol@example.com' })
      expect(result.success).toBe(true)
      if (result.success) {
        const id = result.data.id
        expect(backingMap.has(`identity:${id}`)).toBe(true)
        expect(backingMap.get('idx:email:carol@example.com')).toBe(id)
      }
    })

    it('stores handle index when handle is provided', async () => {
      const result = await service.createHuman({ name: 'Dave', email: 'dave@example.com', handle: 'dave' })
      expect(result.success).toBe(true)
      if (result.success) {
        const id = result.data.id
        expect(backingMap.get('idx:handle:dave')).toBe(id)
        expect(result.data.handle).toBe('dave')
      }
    })

    it('returns ValidationError for empty name', async () => {
      const result = await service.createHuman({ name: '', email: 'test@example.com' })
      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error._tag).toBe('ValidationError')
      }
    })

    it('returns ValidationError for empty email', async () => {
      const result = await service.createHuman({ name: 'Test', email: '' })
      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error._tag).toBe('ValidationError')
      }
    })

    it('returns ConflictError for duplicate email', async () => {
      await service.createHuman({ name: 'First', email: 'dup@example.com' })
      const result = await service.createHuman({ name: 'Second', email: 'dup@example.com' })
      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error._tag).toBe('ConflictError')
      }
    })

    it('returns ConflictError for duplicate handle', async () => {
      await service.createHuman({ name: 'First', email: 'first@example.com', handle: 'shared' })
      const result = await service.createHuman({ name: 'Second', email: 'second@example.com', handle: 'shared' })
      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error._tag).toBe('ConflictError')
      }
    })

    it('email uniqueness check is case-insensitive', async () => {
      await service.createHuman({ name: 'First', email: 'Case@Example.com' })
      const result = await service.createHuman({ name: 'Second', email: 'case@example.com' })
      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error._tag).toBe('ConflictError')
      }
    })
  })

  // --------------------------------------------------------------------------
  // provisionAgent()
  // --------------------------------------------------------------------------

  describe('provisionAgent()', () => {
    it('creates an agent at level 0 / unclaimed with a clm_ token', async () => {
      const result = await service.provisionAgent({})
      expect(result.success).toBe(true)
      if (result.success) {
        const { identity, claimToken } = result.data
        expect(identity.type).toBe('agent')
        expect(identity.verified).toBe(false)
        expect(identity.level).toBe(0)
        expect(identity.claimStatus).toBe('unclaimed')
        expect(claimToken).toMatch(/^clm_/)
        expect(typeof identity.id).toBe('string')
      }
    })

    it('uses provided name when given', async () => {
      const result = await service.provisionAgent({ name: 'my-agent' })
      expect(result.success).toBe(true)
      if (result.success) {
        expect(result.data.identity.name).toBe('my-agent')
      }
    })

    it('generates anon_ name when no name provided', async () => {
      const result = await service.provisionAgent({})
      expect(result.success).toBe(true)
      if (result.success) {
        expect(result.data.identity.name).toMatch(/^anon_/)
      }
    })

    it('stores the identity in storage', async () => {
      const result = await service.provisionAgent({})
      expect(result.success).toBe(true)
      if (result.success) {
        const id = result.data.identity.id
        expect(backingMap.has(`identity:${id}`)).toBe(true)
      }
    })

    it('generates unique IDs for each provisioned agent', async () => {
      const r1 = await service.provisionAgent({})
      const r2 = await service.provisionAgent({})
      expect(r1.success && r2.success).toBe(true)
      if (r1.success && r2.success) {
        expect(r1.data.identity.id).not.toBe(r2.data.identity.id)
        expect(r1.data.claimToken).not.toBe(r2.data.claimToken)
      }
    })
  })

  // --------------------------------------------------------------------------
  // createService()
  // --------------------------------------------------------------------------

  describe('createService()', () => {
    it('creates a service identity at level 3 / claimed', async () => {
      const result = await service.createService({ name: 'payments-service', handle: 'payments' })
      expect(result.success).toBe(true)
      if (result.success) {
        const identity = result.data
        expect(identity.type).toBe('service')
        expect(identity.name).toBe('payments-service')
        expect(identity.handle).toBe('payments')
        expect(identity.verified).toBe(true)
        expect(identity.level).toBe(3)
        expect(identity.claimStatus).toBe('claimed')
      }
    })

    it('stores handle index', async () => {
      const result = await service.createService({ name: 'my-svc', handle: 'my-svc' })
      expect(result.success).toBe(true)
      if (result.success) {
        const id = result.data.id
        expect(backingMap.get('idx:handle:my-svc')).toBe(id)
      }
    })

    it('returns ValidationError for empty name', async () => {
      const result = await service.createService({ name: '', handle: 'svc' })
      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error._tag).toBe('ValidationError')
      }
    })

    it('returns ValidationError for empty handle', async () => {
      const result = await service.createService({ name: 'svc', handle: '' })
      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error._tag).toBe('ValidationError')
      }
    })

    it('returns ConflictError for duplicate handle', async () => {
      await service.createService({ name: 'First', handle: 'shared-handle' })
      const result = await service.createService({ name: 'Second', handle: 'shared-handle' })
      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error._tag).toBe('ConflictError')
      }
    })
  })
})
