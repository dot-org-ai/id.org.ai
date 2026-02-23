/**
 * Auth Worker - Lightweight JWT/API key verification
 *
 * This worker is designed to be fast and lightweight.
 * It only uses jose for JWT verification - no heavy SDK dependencies.
 *
 * Features:
 * - JWT verification with JWKS (WorkOS)
 * - API key verification with hashing and caching
 * - Cookie-based session validation
 * - Cache API for token caching (5 min TTL)
 *
 * @module auth-worker
 */

import { Hono } from 'hono'
import { cors } from 'hono/cors'
import * as jose from 'jose'

// ═══════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════

/**
 * RPC interface for id.org.ai's AuthService (WorkerEntrypoint).
 * Bound via service binding with entrypoint: "AuthService".
 */
interface AuthServiceRPC {
  verifyToken(token: string): Promise<VerifyResult>
  getUser(token: string): Promise<AuthUser | null>
  authenticate(authorization?: string | null, cookie?: string | null): Promise<{ ok: true; user: AuthUser } | { ok: false; status: number; error: string }>
}

interface Env {
  WORKOS_CLIENT_ID: string
  WORKOS_API_KEY?: string
  ADMIN_TOKEN?: string
  ALLOWED_ORIGINS?: string
  // RPC binding to id.org.ai AuthService for session/API key verification
  OAUTH?: AuthServiceRPC
}

/**
 * Authenticated user from JWT or API key
 *
 * This is compatible with the canonical AuthUser in oauth.do/src/types.ts.
 * All fields are optional except id for maximum compatibility.
 */
interface AuthUser {
  /** Unique user identifier */
  id: string
  /** User's email address */
  email?: string
  /** User's display name */
  name?: string
  /** User's profile image URL */
  image?: string
  /** Organization/tenant ID (canonical name) */
  organizationId?: string
  /**
   * Organization/tenant ID (alias for backwards compatibility)
   * @deprecated Use organizationId instead
   */
  org?: string
  /** User roles for RBAC */
  roles?: string[]
  /** User permissions for fine-grained access */
  permissions?: string[]
  /** Additional user metadata */
  metadata?: Record<string, unknown>
}

interface VerifyResult {
  valid: boolean
  user?: AuthUser
  error?: string
  cached?: boolean
}

// ═══════════════════════════════════════════════════════════════════════════
// Runtime Guards
// ═══════════════════════════════════════════════════════════════════════════

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

function isVerifyResult(data: unknown): data is VerifyResult {
  if (!isObject(data)) return false
  if (typeof data.valid !== 'boolean') return false
  if (data.error !== undefined && typeof data.error !== 'string') return false
  if (data.cached !== undefined && typeof data.cached !== 'boolean') return false
  if (data.user !== undefined) {
    if (!isObject(data.user)) return false
    if (typeof (data.user as Record<string, unknown>).id !== 'string') return false
  }
  return true
}

// ═══════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════

const TOKEN_CACHE_TTL = 5 * 60 // 5 minutes for valid tokens
const NEGATIVE_CACHE_TTL = 60 // 60 seconds for invalid tokens
const CACHE_URL_PREFIX = 'https://auth.oauth.do/_cache/'

// JWKS cache (module-level)
let jwksCache: jose.JWTVerifyGetKey | null = null
let jwksCacheExpiry = 0
const JWKS_CACHE_TTL = 60 * 60 * 1000 // 1 hour

// ═══════════════════════════════════════════════════════════════════════════
// Utilities
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Extract roles from JWT payload, handling both WorkOS 'role' (singular)
 * and 'roles' (array) claims
 */
function extractRoles(payload: jose.JWTPayload): string[] | undefined {
  const roles = payload.roles as string[] | undefined
  const role = payload.role as string | undefined
  if (roles && role && !roles.includes(role)) {
    return [...roles, role]
  }
  return roles ?? (role ? [role] : undefined)
}

async function hashToken(token: string): Promise<string> {
  const data = new TextEncoder().encode(token)
  const hashBuffer = await crypto.subtle.digest('SHA-256', data)
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

async function getCachedResult(token: string): Promise<VerifyResult | null> {
  try {
    const cache = caches.default
    const hash = await hashToken(token)
    const cacheKey = new Request(`${CACHE_URL_PREFIX}${hash}`)
    const cached = await cache.match(cacheKey)

    if (!cached) return null

    const data = (await cached.json()) as { result: VerifyResult; expiresAt: number }
    if (data.expiresAt < Date.now()) return null

    return { ...data.result, cached: true }
  } catch {
    return null
  }
}

async function cacheResult(token: string, result: VerifyResult): Promise<void> {
  try {
    const cache = caches.default
    const hash = await hashToken(token)
    const cacheKey = new Request(`${CACHE_URL_PREFIX}${hash}`)
    // Use shorter TTL for invalid tokens to allow retry sooner
    const ttl = result.valid ? TOKEN_CACHE_TTL : NEGATIVE_CACHE_TTL
    const data = { result, expiresAt: Date.now() + ttl * 1000 }
    const response = new Response(JSON.stringify(data), {
      headers: { 'Cache-Control': `max-age=${ttl}` },
    })
    await cache.put(cacheKey, response)
  } catch {
    // Non-fatal
  }
}

// id.org.ai JWKS cache (for tokens signed by the identity provider)
let idOrgAiJwksCache: jose.JWTVerifyGetKey | null = null
let idOrgAiJwksCacheExpiry = 0

async function getIdOrgAiJwks(): Promise<jose.JWTVerifyGetKey> {
  const now = Date.now()
  if (idOrgAiJwksCache && idOrgAiJwksCacheExpiry > now) {
    return idOrgAiJwksCache
  }

  // auth.headless.ly is the same worker as id.org.ai — DNS for id.org.ai
  // currently points to Vercel, so we use auth.headless.ly (workers.do zone)
  const jwksUri = 'https://auth.headless.ly/.well-known/jwks.json'
  idOrgAiJwksCache = jose.createRemoteJWKSet(new URL(jwksUri))
  idOrgAiJwksCacheExpiry = now + JWKS_CACHE_TTL
  return idOrgAiJwksCache
}

// oauth.do JWKS cache (for tokens issued by oauth.do)
let oauthJwksCache: jose.JWTVerifyGetKey | null = null
let oauthJwksCacheExpiry = 0

async function getOAuthJwks(): Promise<jose.JWTVerifyGetKey> {
  const now = Date.now()
  if (oauthJwksCache && oauthJwksCacheExpiry > now) {
    return oauthJwksCache
  }

  const jwksUri = 'https://oauth.do/.well-known/jwks.json'
  oauthJwksCache = jose.createRemoteJWKSet(new URL(jwksUri))
  oauthJwksCacheExpiry = now + JWKS_CACHE_TTL
  return oauthJwksCache
}

// WorkOS JWKS cache (for tokens issued directly by WorkOS)
async function getWorkosJwks(clientId: string): Promise<jose.JWTVerifyGetKey> {
  const now = Date.now()
  if (jwksCache && jwksCacheExpiry > now) {
    return jwksCache
  }

  const jwksUri = `https://api.workos.com/sso/jwks/${clientId}`
  jwksCache = jose.createRemoteJWKSet(new URL(jwksUri))
  jwksCacheExpiry = now + JWKS_CACHE_TTL
  return jwksCache
}

// ═══════════════════════════════════════════════════════════════════════════
// Verification Functions
// ═══════════════════════════════════════════════════════════════════════════

async function verifyJWT(token: string, env: Env): Promise<VerifyResult> {
  // Verification order: id.org.ai → oauth.do → WorkOS
  // id.org.ai is the primary issuer (login flow JWTs), oauth.do is legacy,
  // WorkOS covers tokens issued directly by WorkOS (device flow, etc.)

  const errors: string[] = []

  // 1. Try id.org.ai JWKS (primary — tokens from login flow, iss: 'https://id.org.ai')
  try {
    const idJwks = await getIdOrgAiJwks()
    const { payload } = await jose.jwtVerify(token, idJwks)
    return { valid: true, user: jwtPayloadToUser(payload) }
  } catch (err) {
    errors.push(`id.org.ai: ${err instanceof Error ? err.message : 'failed'}`)
  }

  // 2. Try oauth.do JWKS (legacy tokens, iss: 'https://oauth.do')
  try {
    const oauthJwks = await getOAuthJwks()
    const { payload } = await jose.jwtVerify(token, oauthJwks)
    return { valid: true, user: jwtPayloadToUser(payload) }
  } catch (err) {
    errors.push(`oauth.do: ${err instanceof Error ? err.message : 'failed'}`)
  }

  // 3. Try WorkOS JWKS (tokens issued directly by WorkOS)
  try {
    const workosJwks = await getWorkosJwks(env.WORKOS_CLIENT_ID)
    const { payload } = await jose.jwtVerify(token, workosJwks)
    return { valid: true, user: jwtPayloadToUser(payload) }
  } catch (err) {
    errors.push(`WorkOS: ${err instanceof Error ? err.message : 'failed'}`)
  }

  return { valid: false, error: `JWT verification failed (${errors.join(', ')})` }
}

function jwtPayloadToUser(payload: jose.JWTPayload): AuthUser {
  // Support both new nested org format (id.org.ai) and legacy flat org_id (WorkOS, oauth.do)
  const org = payload.org as { id?: string; name?: string; domains?: string[] } | undefined
  const orgId = org?.id || (payload.org_id as string | undefined)
  return {
    id: payload.sub || '',
    email: payload.email as string | undefined,
    name: payload.name as string | undefined,
    image: payload.picture as string | undefined,
    organizationId: orgId,
    org: orgId,
    roles: extractRoles(payload),
    permissions: payload.permissions as string[] | undefined,
  }
}

/**
 * Constant-time string comparison to prevent timing attacks.
 * Uses crypto.subtle.timingSafeEqual if available (Cloudflare Workers),
 * otherwise falls back to a manual constant-time implementation.
 */
function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  // Use native timingSafeEqual if available (Cloudflare Workers non-standard extension)
  // @ts-expect-error - timingSafeEqual is not in standard WebCrypto types
  if (typeof crypto?.subtle?.timingSafeEqual === 'function') {
    // @ts-expect-error - timingSafeEqual is not in standard WebCrypto types
    return crypto.subtle.timingSafeEqual(a, b)
  }

  // Fallback: manual constant-time comparison
  // This should only be used in test environments
  if (a.length !== b.length) return false
  let result = 0
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i]
  }
  return result === 0
}

async function verifyAdminToken(token: string, env: Env): Promise<VerifyResult> {
  if (!env.ADMIN_TOKEN) return { valid: false, error: 'Admin token not configured' }

  // Constant-time comparison to prevent timing attacks
  const tokenBytes = new TextEncoder().encode(token)
  const adminBytes = new TextEncoder().encode(env.ADMIN_TOKEN)

  // To avoid leaking length information, we compare against itself when lengths differ
  // This ensures the comparison takes the same time regardless of length mismatch
  const lengthsMatch = tokenBytes.length === adminBytes.length
  const compareBytes = lengthsMatch ? adminBytes : tokenBytes

  // timingSafeEqual requires equal-length buffers, so we compare:
  // - tokenBytes vs adminBytes when lengths match (actual comparison)
  // - tokenBytes vs tokenBytes when lengths differ (always true, but we'll return false)
  const isEqual = timingSafeEqual(tokenBytes, compareBytes)

  if (lengthsMatch && isEqual) {
    return {
      valid: true,
      user: {
        id: 'admin',
        email: 'admin@oauth.do',
        roles: ['admin'],
        permissions: ['*'],
      },
    }
  }

  return { valid: false, error: 'Invalid admin token' }
}

// sk_* API key verification — delegated to id.org.ai AuthService
// (id.org.ai handles WorkOS API key validation internally)

// ═══════════════════════════════════════════════════════════════════════════
// Main Verification
// ═══════════════════════════════════════════════════════════════════════════

async function verifyToken(token: string, env: Env): Promise<VerifyResult> {
  // Check cache first
  const cached = await getCachedResult(token)
  if (cached) return cached

  let result: VerifyResult

  // Try different verification methods based on token format
  if (token.startsWith('ses_') || token.startsWith('oai_') || token.startsWith('hly_sk_') || token.startsWith('sk_')) {
    // Session tokens, custom API keys, and WorkOS API keys — delegate to id.org.ai AuthService
    result = await delegateToOAuth(token, env)
  } else if (token.includes('.')) {
    // JWTs contain dots (header.payload.signature)
    result = await verifyJWT(token, env)
  } else if (env.ADMIN_TOKEN) {
    // For other tokens, try admin token verification if configured
    result = await verifyAdminToken(token, env)
  } else {
    result = { valid: false, error: 'Invalid token format' }
  }

  // Cache results (valid tokens: 5 min, invalid tokens: 60 sec)
  await cacheResult(token, result)

  return result
}

/**
 * Delegate token verification to id.org.ai's AuthService via RPC.
 * Used for token types that require IdentityDO access (ses_*, oai_*, hly_sk_*).
 */
async function delegateToOAuth(token: string, env: Env): Promise<VerifyResult> {
  if (!env.OAUTH) {
    return { valid: false, error: 'Session/API key verification requires OAUTH binding' }
  }

  try {
    return await env.OAUTH.verifyToken(token)
  } catch (err) {
    return { valid: false, error: `OAuth delegation failed: ${err instanceof Error ? err.message : 'unknown'}` }
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// App
// ═══════════════════════════════════════════════════════════════════════════

const app = new Hono<{ Bindings: Env }>()

app.use('*', async (c, next) => {
  const allowedOrigins = c.env.ALLOWED_ORIGINS
    ? c.env.ALLOWED_ORIGINS.split(',').map((o) => o.trim())
    : []

  return cors({
    origin: (origin) => {
      if (allowedOrigins.length === 0) return ''
      return allowedOrigins.includes(origin) ? origin : ''
    },
    allowMethods: ['GET', 'POST', 'OPTIONS'],
    allowHeaders: ['Authorization', 'Content-Type', 'Cookie'],
    maxAge: 86400,
  })(c, next)
})

// Health check
app.get('/health', (c) => c.json({ status: 'ok', service: 'auth' }))

// Verify token (POST body or query param)
app.post('/verify', async (c) => {
  const raw: unknown = await c.req.json().catch(() => ({}))
  const body = (typeof raw === 'object' && raw !== null) ? raw as Record<string, unknown> : {}
  const bodyToken = typeof body.token === 'string' ? body.token : undefined
  const token = bodyToken || c.req.query('token')

  if (!token) {
    return c.json({ valid: false, error: 'Token required' }, 400)
  }

  const result = await verifyToken(token, c.env)
  return c.json(result)
})

// Verify from Authorization header
app.get('/verify', async (c) => {
  const auth = c.req.header('Authorization')
  let token: string | undefined

  if (auth?.startsWith('Bearer ')) {
    token = auth.slice(7)
  } else {
    token = c.req.query('token')
  }

  if (!token) {
    return c.json({ valid: false, error: 'Token required' }, 400)
  }

  const result = await verifyToken(token, c.env)
  return c.json(result)
})

/**
 * Parse auth token from cookie header. Supports chunked cookies (auth.0, auth.1, ...).
 */
function parseAuthCookie(cookieHeader: string): string | null {
  // Try single cookie first
  const single = cookieHeader.match(/(?:^|;\s*)auth=([^;]+)/)?.[1]
  if (single) return single
  // Try chunked cookies
  let result = ''
  for (let i = 0; ; i++) {
    const chunk = cookieHeader.match(new RegExp(`(?:^|;\\s*)auth\\.${i}=([^;]+)`))?.[1]
    if (!chunk) break
    result += chunk
  }
  return result || null
}

// Get user from token
app.get('/me', async (c) => {
  const auth = c.req.header('Authorization')
  const cookieHeader = c.req.header('Cookie') || ''
  const cookie = parseAuthCookie(cookieHeader)
  const token = auth?.startsWith('Bearer ') ? auth.slice(7) : cookie

  if (!token) {
    return c.json({ error: 'Not authenticated' }, 401)
  }

  const result = await verifyToken(token, c.env)
  if (!result.valid) {
    return c.json({ error: result.error || 'Invalid token' }, 401)
  }

  return c.json(result.user)
})

// Invalidate cache for a token
app.post('/invalidate', async (c) => {
  // Require authentication (Bearer token, API key, or admin token)
  const auth = c.req.header('Authorization')
  const callerToken = auth?.startsWith('Bearer ') ? auth.slice(7) : undefined

  if (!callerToken) {
    return c.json({ error: 'Authentication required' }, 401)
  }

  const authResult = await verifyToken(callerToken, c.env)
  if (!authResult.valid) {
    return c.json({ error: authResult.error || 'Invalid credentials' }, 401)
  }

  const raw: unknown = await c.req.json().catch(() => ({}))
  const body = (typeof raw === 'object' && raw !== null) ? raw as Record<string, unknown> : {}
  const token = typeof body.token === 'string' ? body.token : undefined

  if (!token) {
    return c.json({ error: 'Token required' }, 400)
  }

  try {
    const cache = caches.default
    const hash = await hashToken(token)
    const cacheKey = new Request(`${CACHE_URL_PREFIX}${hash}`)
    await cache.delete(cacheKey)
    return c.json({ invalidated: true })
  } catch {
    return c.json({ invalidated: false, error: 'Cache operation failed' })
  }
})

// ═══════════════════════════════════════════════════════════════════════════
// RPC Entrypoint - Zero bundle overhead for consumers
// ═══════════════════════════════════════════════════════════════════════════

import { WorkerEntrypoint } from 'cloudflare:workers'

/** Auth result for RPC calls */
export type AuthResult =
  | { ok: true; user: AuthUser }
  | { ok: false; status: number; error: string }

/**
 * AuthRPC - Workers RPC entrypoint for authentication
 *
 * Consumers bind to this via service bindings for zero-bundle-overhead auth.
 *
 * @example
 * ```typescript
 * // wrangler.jsonc
 * "services": [{ "binding": "AUTH", "service": "auth-do", "entrypoint": "AuthRPC" }]
 *
 * // In your worker
 * const result = await env.AUTH.verifyToken(token)
 * ```
 */
export class AuthRPC extends WorkerEntrypoint<Env> {
  /**
   * Verify any token type (JWT, API key, admin token)
   * Results are cached for 5 minutes
   */
  async verifyToken(token: string): Promise<VerifyResult> {
    try {
      // Check required environment
      if (!this.env.WORKOS_CLIENT_ID) {
        return { valid: false, error: 'WORKOS_CLIENT_ID not configured' }
      }
      return await verifyToken(token, this.env)
    } catch (err) {
      console.error('[AuthRPC.verifyToken] Unexpected error:', err)
      return { valid: false, error: err instanceof Error ? err.message : 'Verification failed' }
    }
  }

  /**
   * Get user from token, returns null if invalid
   */
  async getUser(token: string): Promise<AuthUser | null> {
    const result = await this.verifyToken(token)
    return result.valid && result.user ? result.user : null
  }

  /**
   * Authenticate from Authorization header and/or cookie value
   * Returns structured result for middleware use
   */
  async authenticate(
    authorization?: string | null,
    cookie?: string | null
  ): Promise<AuthResult> {
    // Extract token from Authorization header or cookie (supports chunked cookies)
    const token =
      authorization?.replace(/^Bearer\s+/i, '') ||
      (cookie ? parseAuthCookie(cookie) : null)

    if (!token) {
      return { ok: false, status: 401, error: 'No token provided' }
    }

    const result = await this.verifyToken(token)

    if (!result.valid || !result.user) {
      return { ok: false, status: 401, error: result.error || 'Invalid token' }
    }

    return { ok: true, user: result.user }
  }

  /**
   * Check if token has any of the specified roles
   */
  async hasRoles(token: string, roles: string[]): Promise<boolean> {
    const user = await this.getUser(token)
    if (!user?.roles) return false
    return roles.some((r) => user.roles!.includes(r))
  }

  /**
   * Check if token has all of the specified permissions
   */
  async hasPermissions(token: string, permissions: string[]): Promise<boolean> {
    const user = await this.getUser(token)
    if (!user?.permissions) return false
    return permissions.every((p) => user.permissions!.includes(p))
  }

  /**
   * Check if token belongs to an admin user
   */
  async isAdmin(token: string): Promise<boolean> {
    return this.hasRoles(token, ['admin'])
  }

  /**
   * Invalidate cached result for a token
   */
  async invalidate(token: string): Promise<boolean> {
    try {
      const cache = caches.default
      const hash = await hashToken(token)
      const cacheKey = new Request(`${CACHE_URL_PREFIX}${hash}`)
      await cache.delete(cacheKey)
      return true
    } catch {
      return false
    }
  }
}

// AuthService alias — some consumers bind with entrypoint: "AuthService"
// (apps/agents, apps/code, apps/db, apps/src use AuthService; apps/api, events, apis.do use AuthRPC)
export { AuthRPC as AuthService }

// Export Hono app as default (keeps HTTP API working)
export default app
