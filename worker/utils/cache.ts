import type { AuthUser } from '../types'

// ── Token Cache Helpers ─────────────────────────────────────────────────
// Uses Cloudflare Cache API to cache verified tokens for 5 minutes.
// Avoids repeated KV lookups and JWT verification on hot paths.

const TOKEN_CACHE_TTL = 5 * 60 // 5 minutes
const CACHE_URL_PREFIX = 'https://id.org.ai/_cache/token/'

// ── Negative Cache (invalid tokens) ─────────────────────────────────────
// Caches failed verification results for 60 seconds to prevent repeated
// KV lookups and JWT verification for known-bad tokens.

const NEGATIVE_CACHE_TTL = 60 // 60 seconds
const NEGATIVE_CACHE_URL_PREFIX = 'https://id.org.ai/_cache/neg/'

async function hashToken(token: string): Promise<string> {
  const data = new TextEncoder().encode(token)
  const hashBuffer = await crypto.subtle.digest('SHA-256', data)
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

export async function getCachedUser(token: string): Promise<AuthUser | null> {
  try {
    const hash = await hashToken(token)
    const cacheKey = new Request(`${CACHE_URL_PREFIX}${hash}`)
    const cached = await caches.default.match(cacheKey)
    if (!cached) return null
    const data = (await cached.json()) as { user: AuthUser; expiresAt: number }
    if (data.expiresAt < Date.now()) return null
    return data.user
  } catch {
    return null
  }
}

export async function cacheUser(token: string, user: AuthUser): Promise<void> {
  try {
    const hash = await hashToken(token)
    const cacheKey = new Request(`${CACHE_URL_PREFIX}${hash}`)
    const data = { user, expiresAt: Date.now() + TOKEN_CACHE_TTL * 1000 }
    const response = new Response(JSON.stringify(data), {
      headers: { 'Cache-Control': `max-age=${TOKEN_CACHE_TTL}` },
    })
    await caches.default.put(cacheKey, response)
  } catch {
    // Cache failures are non-fatal
  }
}

export async function invalidateCachedToken(token: string): Promise<boolean> {
  try {
    const hash = await hashToken(token)
    const cacheKey = new Request(`${CACHE_URL_PREFIX}${hash}`)
    return caches.default.delete(cacheKey)
  } catch {
    return false
  }
}

export async function isNegativelyCached(token: string): Promise<boolean> {
  try {
    const hash = await hashToken(token)
    const cacheKey = new Request(`${NEGATIVE_CACHE_URL_PREFIX}${hash}`)
    const cached = await caches.default.match(cacheKey)
    return !!cached
  } catch {
    return false
  }
}

export async function cacheNegativeResult(token: string): Promise<void> {
  try {
    const hash = await hashToken(token)
    const cacheKey = new Request(`${NEGATIVE_CACHE_URL_PREFIX}${hash}`)
    const response = new Response('invalid', {
      headers: { 'Cache-Control': `max-age=${NEGATIVE_CACHE_TTL}` },
    })
    await caches.default.put(cacheKey, response)
  } catch {
    // Cache failures are non-fatal
  }
}
