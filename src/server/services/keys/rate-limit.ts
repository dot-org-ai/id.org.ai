import type { StorageAdapter } from '../../../sdk/storage'
import type { RateLimitService, CapabilityLevel, RateLimitEntry, RateLimitResult, RateLimitConfig } from './types'

// ============================================================================
// Rate Limit Configuration
// ============================================================================

export const RATE_LIMITS: Record<CapabilityLevel, RateLimitConfig> = {
  0: { maxRequests: 30, windowMs: 60_000 },
  1: { maxRequests: 100, windowMs: 60_000 },
  2: { maxRequests: 1000, windowMs: 60_000 },
  3: { maxRequests: Infinity, windowMs: 60_000 },
}

// ============================================================================
// Implementation
// ============================================================================

export class RateLimitServiceImpl implements RateLimitService {
  private storage: StorageAdapter

  constructor({ storage }: { storage: StorageAdapter }) {
    this.storage = storage
  }

  async check(identityId: string, level: CapabilityLevel): Promise<RateLimitResult> {
    const config = RATE_LIMITS[level]
    if (config.maxRequests === Infinity) {
      return { allowed: true, remaining: Infinity, resetAt: 0 }
    }

    const key = `rateLimit:${identityId}`
    const now = Date.now()
    const entry = await this.storage.get<RateLimitEntry>(key)

    if (!entry || now - entry.windowStart > config.windowMs) {
      await this.storage.put(key, {
        identityId,
        windowStart: now,
        requestCount: 1,
      } satisfies RateLimitEntry)
      return {
        allowed: true,
        remaining: config.maxRequests - 1,
        resetAt: now + config.windowMs,
      }
    }

    const remaining = config.maxRequests - entry.requestCount - 1
    const resetAt = entry.windowStart + config.windowMs

    if (entry.requestCount >= config.maxRequests) {
      return { allowed: false, remaining: 0, resetAt }
    }

    await this.storage.put(key, {
      ...entry,
      requestCount: entry.requestCount + 1,
    })

    return { allowed: true, remaining: Math.max(0, remaining), resetAt }
  }
}
