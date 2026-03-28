import { describe, it, expect, beforeEach } from 'vitest'

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
