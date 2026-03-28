import { describe, it, expect, beforeEach } from 'vitest'
import { AuditServiceImpl } from '../src/services/audit/service'

// ============================================================================
// Mock Storage (same pattern as identity-service.test.ts)
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
    async list(options?: { prefix?: string; limit?: number }) {
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
// Rate Limit Tests
// ============================================================================

describe('RateLimitServiceImpl', () => {
  let storage: DurableObjectStorage
  let backingMap: Map<string, unknown>

  beforeEach(() => {
    backingMap = new Map()
    storage = createMockStorage(backingMap)
  })

  it('should be importable', async () => {
    const { RateLimitServiceImpl } = await import('../src/services/keys/rate-limit')
    expect(RateLimitServiceImpl).toBeDefined()
  })

  it('L3 always returns allowed with Infinity remaining', async () => {
    const { RateLimitServiceImpl } = await import('../src/services/keys/rate-limit')
    const svc = new RateLimitServiceImpl({ storage })
    const result = await svc.check('usr_1', 3)
    expect(result.allowed).toBe(true)
    expect(result.remaining).toBe(Infinity)
    expect(result.resetAt).toBe(0)
  })

  it('L0 allows first request and tracks remaining', async () => {
    const { RateLimitServiceImpl } = await import('../src/services/keys/rate-limit')
    const svc = new RateLimitServiceImpl({ storage })
    const result = await svc.check('usr_1', 0)
    expect(result.allowed).toBe(true)
    expect(result.remaining).toBe(29) // 30 - 1
    expect(result.resetAt).toBeGreaterThan(Date.now() - 1000)
  })

  it('denies after max requests exceeded', async () => {
    const { RateLimitServiceImpl } = await import('../src/services/keys/rate-limit')
    const svc = new RateLimitServiceImpl({ storage })
    // Fill up the window
    for (let i = 0; i < 30; i++) {
      await svc.check('usr_1', 0)
    }
    const result = await svc.check('usr_1', 0)
    expect(result.allowed).toBe(false)
    expect(result.remaining).toBe(0)
  })

  it('resets after window expires', async () => {
    const { RateLimitServiceImpl } = await import('../src/services/keys/rate-limit')
    const svc = new RateLimitServiceImpl({ storage })
    // Pre-seed an expired window
    backingMap.set('rateLimit:usr_1', {
      identityId: 'usr_1',
      windowStart: Date.now() - 120_000, // 2 minutes ago (window is 1 min)
      requestCount: 30,
    })
    const result = await svc.check('usr_1', 0)
    expect(result.allowed).toBe(true)
    expect(result.remaining).toBe(29)
  })
})

describe('ApiKeyServiceImpl', () => {
  let storage: DurableObjectStorage
  let backingMap: Map<string, unknown>
  let audit: AuditServiceImpl

  beforeEach(() => {
    backingMap = new Map()
    storage = createMockStorage(backingMap)
    audit = new AuditServiceImpl({ storage })
  })

  describe('create()', () => {
    it('creates an API key with hly_sk_ prefix', async () => {
      const { ApiKeyServiceImpl } = await import('../src/services/keys/api-keys')
      const svc = new ApiKeyServiceImpl({ storage, audit })
      const result = await svc.create({ name: 'Test Key', identityId: 'usr_1' })
      expect(result.success).toBe(true)
      if (result.success) {
        expect(result.data.key).toMatch(/^hly_sk_/)
        expect(result.data.name).toBe('Test Key')
        expect(result.data.scopes).toEqual(['read', 'write'])
        expect(result.data.prefix).toBe(result.data.key.slice(0, 15))
      }
    })

    it('returns ValidationError for empty name', async () => {
      const { ApiKeyServiceImpl } = await import('../src/services/keys/api-keys')
      const svc = new ApiKeyServiceImpl({ storage, audit })
      const result = await svc.create({ name: '', identityId: 'usr_1' })
      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error._tag).toBe('ValidationError')
        expect(result.error.field).toBe('name')
      }
    })

    it('returns ValidationError for invalid scope', async () => {
      const { ApiKeyServiceImpl } = await import('../src/services/keys/api-keys')
      const svc = new ApiKeyServiceImpl({ storage, audit })
      const result = await svc.create({ name: 'Key', identityId: 'usr_1', scopes: ['nope'] })
      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error._tag).toBe('ValidationError')
        expect(result.error.field).toBe('scopes')
      }
    })

    it('returns ValidationError for past expiresAt', async () => {
      const { ApiKeyServiceImpl } = await import('../src/services/keys/api-keys')
      const svc = new ApiKeyServiceImpl({ storage, audit })
      const result = await svc.create({
        name: 'Key',
        identityId: 'usr_1',
        expiresAt: '2020-01-01T00:00:00Z',
      })
      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error._tag).toBe('ValidationError')
        expect(result.error.field).toBe('expiresAt')
      }
    })
  })

  describe('list()', () => {
    it('returns empty array when no keys exist', async () => {
      const { ApiKeyServiceImpl } = await import('../src/services/keys/api-keys')
      const svc = new ApiKeyServiceImpl({ storage, audit })
      const keys = await svc.list('usr_1')
      expect(keys).toEqual([])
    })

    it('returns only keys for the given identity', async () => {
      const { ApiKeyServiceImpl } = await import('../src/services/keys/api-keys')
      const svc = new ApiKeyServiceImpl({ storage, audit })
      await svc.create({ name: 'Key 1', identityId: 'usr_1' })
      await svc.create({ name: 'Key 2', identityId: 'usr_2' })
      const keys = await svc.list('usr_1')
      expect(keys).toHaveLength(1)
      expect(keys[0].name).toBe('Key 1')
      expect((keys[0] as any).key).toBeUndefined()
    })
  })

  describe('revoke()', () => {
    it('revokes an existing key', async () => {
      const { ApiKeyServiceImpl } = await import('../src/services/keys/api-keys')
      const svc = new ApiKeyServiceImpl({ storage, audit })
      const created = await svc.create({ name: 'Key', identityId: 'usr_1' })
      if (!created.success) throw new Error('create failed')

      const result = await svc.revoke(created.data.id, 'usr_1')
      expect(result.success).toBe(true)
      if (result.success) {
        expect(result.data.status).toBe('revoked')
        expect(result.data.revokedAt).toBeDefined()
      }
    })

    it('returns NotFoundError for non-existent key', async () => {
      const { ApiKeyServiceImpl } = await import('../src/services/keys/api-keys')
      const svc = new ApiKeyServiceImpl({ storage, audit })
      const result = await svc.revoke('nope', 'usr_1')
      expect(result.success).toBe(false)
      if (!result.success) expect(result.error._tag).toBe('NotFoundError')
    })

    it('returns KeyError for already-revoked key', async () => {
      const { ApiKeyServiceImpl } = await import('../src/services/keys/api-keys')
      const svc = new ApiKeyServiceImpl({ storage, audit })
      const created = await svc.create({ name: 'Key', identityId: 'usr_1' })
      if (!created.success) throw new Error('create failed')

      await svc.revoke(created.data.id, 'usr_1')
      const result = await svc.revoke(created.data.id, 'usr_1')
      expect(result.success).toBe(false)
      if (!result.success) expect(result.error._tag).toBe('KeyError')
    })

    it('prevents validation after revocation', async () => {
      const { ApiKeyServiceImpl } = await import('../src/services/keys/api-keys')
      const svc = new ApiKeyServiceImpl({
        storage,
        audit,
        getIdentityLevel: async () => 2 as const,
      })
      const created = await svc.create({ name: 'Key', identityId: 'usr_1' })
      if (!created.success) throw new Error('create failed')

      await svc.revoke(created.data.id, 'usr_1')
      const result = await svc.validate(created.data.key)
      expect(result.success).toBe(true)
      if (result.success) expect(result.data.valid).toBe(false)
    })
  })

  describe('validate()', () => {
    it('validates a live key and returns identity context', async () => {
      const { ApiKeyServiceImpl } = await import('../src/services/keys/api-keys')
      const svc = new ApiKeyServiceImpl({
        storage,
        audit,
        getIdentityLevel: async () => 2 as const,
      })
      const created = await svc.create({ name: 'Key', identityId: 'usr_1' })
      if (!created.success) throw new Error('create failed')

      const result = await svc.validate(created.data.key)
      expect(result.success).toBe(true)
      if (result.success) {
        expect(result.data.valid).toBe(true)
        expect(result.data.identityId).toBe('usr_1')
        expect(result.data.scopes).toEqual(['read', 'write'])
        expect(result.data.level).toBe(2)
      }
    })

    it('returns valid=false for unknown key', async () => {
      const { ApiKeyServiceImpl } = await import('../src/services/keys/api-keys')
      const svc = new ApiKeyServiceImpl({ storage, audit })
      const result = await svc.validate('hly_sk_nonexistent')
      expect(result.success).toBe(true)
      if (result.success) expect(result.data.valid).toBe(false)
    })

    it('returns valid=false for expired key', async () => {
      const { ApiKeyServiceImpl } = await import('../src/services/keys/api-keys')
      const svc = new ApiKeyServiceImpl({
        storage,
        audit,
        getIdentityLevel: async () => 2 as const,
      })
      const created = await svc.create({ name: 'Key', identityId: 'usr_1' })
      if (!created.success) throw new Error('create failed')
      const record = await storage.get<any>(`apikey:${created.data.id}`)
      await storage.put(`apikey:${created.data.id}`, { ...record, expiresAt: '2020-01-01T00:00:00Z' })

      const result = await svc.validate(created.data.key)
      expect(result.success).toBe(true)
      if (result.success) expect(result.data.valid).toBe(false)
    })
  })
})
