/**
 * id.org.ai — Agent-First Identity
 *
 * Cloudflare Worker entry point.
 * Routes: id.org.ai, auth.org.ai
 *
 * Every request is authenticated via MCPAuth (three-tier):
 *   L0: No auth — anonymous, read scopes, 30 req/min
 *   L1: ses_* token — session, read+write, 100 req/min
 *   L2+: oai_* key — API key, full scopes, 1000+ req/min
 *
 * Sharding: Each identity gets its own Durable Object instance.
 * The shard key is derived from the request:
 *   - API key (oai_*) → KV lookup: apikey:{key} → identityId
 *   - Session token (ses_*) → KV lookup: session:{token} → identityId
 *   - Claim token (clm_*) → KV lookup: claim:{token} → identityId
 *   - Provision (POST /api/provision) → new UUID (creates new DO)
 *   - Anonymous L0 → no DO needed (schema-only responses)
 *
 * Internal communication: Workers RPC (stub.method()) — no HTTP overhead,
 * no X-Worker-Auth headers, inherently trusted.
 */

import { WorkerEntrypoint } from 'cloudflare:workers'
import { Hono } from 'hono'
import { cors } from 'hono/cors'
import * as jose from 'jose'
import { IdentityDO } from '../src/do/Identity'
import type { IdentityStub } from '../src/do/Identity'
import { MCPAuth } from '../src/mcp/auth'
import type { MCPAuthResult } from '../src/mcp/auth'
import { dispatchTool } from '../src/mcp/tools'
import { ClaimService } from '../src/claim/provision'
import { verifyClaim } from '../src/claim/verify'
import { GitHubApp } from '../src/github/app'
import type { PushEvent } from '../src/github/app'
import { OAuthProvider } from '../src/oauth/provider'
import { SigningKeyManager } from '../src/jwt/signing'
import { buildWorkOSAuthUrl, exchangeWorkOSCode, encodeLoginState, decodeLoginState } from '../src/workos/upstream'
import { validateWorkOSApiKey } from '../src/workos/apikey'
import { createWorkOSApiKey, listWorkOSApiKeys, revokeWorkOSApiKey } from '../src/workos/keys'
import {
  ensureSCIMTables,
  handleDSyncUserCreated,
  handleDSyncUserUpdated,
  handleDSyncUserDeleted,
  handleDSyncGroupCreated,
  handleDSyncGroupUpdated,
  handleDSyncGroupDeleted,
  handleDSyncGroupUserAdded,
  handleDSyncGroupUserRemoved,
  getAdminPortalUrl,
} from '../src/workos/scim'
import type { DSyncEvent, DSyncUser, DSyncGroup, DSyncGroupMembership } from '../src/workos/scim'
import {
  FGA_RESOURCE_TYPES,
  defineResourceTypes,
  checkPermission,
  shareResource,
  unshareResource,
  listAccessible,
  entityTypeToFGA,
} from '../src/workos/fga'
import type { FGACheckRequest, FGARelation } from '../src/workos/fga'
import {
  createVaultSecret,
  getVaultSecret,
  readVaultSecretValue,
  listVaultSecrets,
  updateVaultSecret,
  deleteVaultSecret,
  resolveSecret,
  resolveSecrets,
  interpolateSecrets,
} from '../src/workos/vault'
import type { CreateSecretOptions, UpdateSecretOptions } from '../src/workos/vault'
import {
  PIPES_PROVIDERS,
  getAccessToken,
  listConnections,
  getConnection,
  disconnectConnection,
  getConnectionStatus,
} from '../src/workos/pipes'
import type { PipesProvider } from '../src/workos/pipes'
import {
  generateCSRFToken,
  buildCSRFCookie,
  encodeStateWithCSRF,
  decodeStateWithCSRF,
  extractCSRFFromCookie,
  isAllowedOrigin,
  isSafeRedirectUrl,
  validateOrigin,
} from '../src/csrf'
import { AUDIT_EVENTS } from '../src/audit'
import type { AuditQueryOptions, StoredAuditEvent } from '../src/audit'
import { errorResponse, ErrorCode } from '../src/errors'

export { IdentityDO }

interface Env {
  IDENTITY: DurableObjectNamespace
  SESSIONS: KVNamespace
  DB?: D1Database
  ASSETS?: Fetcher
  AUTH_SECRET: string
  JWKS_SECRET: string
  WORKOS_CLIENT_ID?: string
  WORKOS_API_KEY?: string
  WORKOS_COOKIE_PASSWORD?: string
  WORKOS_WEBHOOK_SECRET?: string
  GITHUB_APP_ID?: string
  GITHUB_APP_PRIVATE_KEY?: string
  GITHUB_WEBHOOK_SECRET?: string
  // Branding for @mdxui/auth SPA
  APP_NAME?: string
  APP_TAGLINE?: string
  REDIRECT_URI?: string
}

type Variables = {
  auth: MCPAuthResult
  identityStub: IdentityStub
}

// ── Auth Service (RPC via Service Binding) ──────────────────────────────
// Exposes verifyToken() as an RPC method for other Cloudflare Workers.
// Other workers bind to this as `env.AUTH` and call `env.AUTH.verifyToken(token)`.

// AuthUser type matching oauth.do's canonical AuthUser interface
type AuthUser = {
  id: string
  email?: string
  name?: string
  image?: string
  organizationId?: string
  roles?: string[]
  permissions?: string[]
  metadata?: Record<string, unknown>
}

type VerifyResult = { valid: true; user: AuthUser; cached?: boolean } | { valid: false; error: string }

type AuthRPCResult = { ok: true; user: AuthUser } | { ok: false; status: number; error: string }

// ── Token Cache Helpers ─────────────────────────────────────────────────
// Uses Cloudflare Cache API to cache verified tokens for 5 minutes.
// Avoids repeated KV lookups and JWT verification on hot paths.

const TOKEN_CACHE_TTL = 5 * 60 // 5 minutes
const CACHE_URL_PREFIX = 'https://id.org.ai/_cache/token/'

async function hashToken(token: string): Promise<string> {
  const data = new TextEncoder().encode(token)
  const hashBuffer = await crypto.subtle.digest('SHA-256', data)
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

async function getCachedUser(token: string): Promise<AuthUser | null> {
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

async function cacheUser(token: string, user: AuthUser): Promise<void> {
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

async function invalidateCachedToken(token: string): Promise<boolean> {
  try {
    const hash = await hashToken(token)
    const cacheKey = new Request(`${CACHE_URL_PREFIX}${hash}`)
    return caches.default.delete(cacheKey)
  } catch {
    return false
  }
}

// ── Negative Cache (invalid tokens) ─────────────────────────────────────
// Caches failed verification results for 60 seconds to prevent repeated
// KV lookups and JWT verification for known-bad tokens.

const NEGATIVE_CACHE_TTL = 60 // 60 seconds
const NEGATIVE_CACHE_URL_PREFIX = 'https://id.org.ai/_cache/neg/'

async function isNegativelyCached(token: string): Promise<boolean> {
  try {
    const hash = await hashToken(token)
    const cacheKey = new Request(`${NEGATIVE_CACHE_URL_PREFIX}${hash}`)
    const cached = await caches.default.match(cacheKey)
    return !!cached
  } catch {
    return false
  }
}

async function cacheNegativeResult(token: string): Promise<void> {
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

// ── Cookie Parsing ──────────────────────────────────────────────────────
// Simple cookie parser for extracting auth tokens from cookie headers.
// Used by authenticate() when called with a raw cookie header string.

function parseCookieValue(cookieHeader: string, name: string): string | null {
  const match = cookieHeader.match(new RegExp(`(?:^|;\\s*)${name}=([^;]*)`))
  return match ? decodeURIComponent(match[1]) : null
}

// ── Cookie Domain Detection ──────────────────────────────────────────────
// When running on a subdomain (e.g. id.headless.ly), set Domain=.headless.ly
// so the auth cookie is shared across all subdomains. On root domains or
// localhost, omit Domain to use the default (exact host).

function getRootDomain(hostname: string): string | null {
  const parts = hostname.split('.')
  if (parts.length <= 2) return null // already root or localhost
  return '.' + parts.slice(-2).join('.') // .headless.ly, .org.ai, etc.
}

// ── JWKS Cache ──────────────────────────────────────────────────────────
// Module-level cache for JWKS verifiers (persists across requests within isolate)
// Supports our own JWKS and WorkOS JWKS (which also verifies oauth.do-issued JWTs).

const jwksCache = new Map<string, { verifier: jose.JWTVerifyGetKey; expiry: number }>()

function getJwksVerifier(jwksUri: string): jose.JWTVerifyGetKey {
  const now = Date.now()
  const cached = jwksCache.get(jwksUri)
  if (cached && cached.expiry > now) return cached.verifier
  const verifier = jose.createRemoteJWKSet(new URL(jwksUri))
  jwksCache.set(jwksUri, { verifier, expiry: now + 3600 * 1000 })
  return verifier
}

// ── AuthService (RPC via Service Binding) ────────────────────────────────
// Implements the full AuthRPC interface from oauth.do/rpc.
// Other workers bind to this as `env.AUTH` and call methods like:
//   env.AUTH.verifyToken(token)
//   env.AUTH.authenticate(authorization, cookie)
//   env.AUTH.hasRoles(token, ['admin'])
//
// Supports four token types:
//   1. ses_* session tokens → KV + IdentityDO validation
//   2. oai_*/hly_sk_* API keys → KV + IdentityDO validation
//   3. sk_* WorkOS API keys → validated against WorkOS API
//   4. JWTs → verified against id.org.ai JWKS, then WorkOS JWKS (also covers oauth.do-issued JWTs)

export class AuthService extends WorkerEntrypoint<Env> {
  // ── verifyToken ─────────────────────────────────────────────────────
  // Verify any token type (session, API key, or WorkOS JWT).
  // Results are cached for 5 minutes via Cache API.

  async verifyToken(token: string): Promise<VerifyResult> {
    // Check negative cache first (known-bad tokens)
    if (await isNegativelyCached(token)) return { valid: false, error: 'Invalid token (cached)' }

    // Check positive cache
    const cached = await getCachedUser(token)
    if (cached) return { valid: true, user: cached, cached: true }

    // Session token (ses_*)
    if (token.startsWith('ses_')) {
      const identityId = await this.env.SESSIONS.get(`session:${token}`)
      if (!identityId) return { valid: false, error: 'Invalid or expired session' }

      const id = this.env.IDENTITY.idFromName(identityId)
      const stub = this.env.IDENTITY.get(id) as unknown as IdentityStub
      const session = await stub.getSession(token)
      if (!session?.valid) return { valid: false, error: 'Invalid session' }

      const identity = await stub.getIdentity(identityId)
      const user: AuthUser = {
        id: identityId,
        name: identity?.name,
        email: identity?.email,
        organizationId: identity?.name,
        permissions: ['read', 'write', 'delete', 'search', 'fetch', 'do', 'try', 'claim'],
      }
      await cacheUser(token, user)
      return { valid: true, user }
    }

    // API key (oai_* or hly_sk_*)
    if (token.startsWith('oai_') || token.startsWith('hly_sk_')) {
      const identityId = await this.env.SESSIONS.get(`apikey:${token}`)
      if (!identityId) return { valid: false, error: 'Invalid API key' }

      const id = this.env.IDENTITY.idFromName(identityId)
      const stub = this.env.IDENTITY.get(id) as unknown as IdentityStub
      const result = await stub.validateApiKey(token)
      if (!result?.valid) return { valid: false, error: 'Invalid or revoked API key' }

      const identity = await stub.getIdentity(identityId)
      const user: AuthUser = {
        id: identityId,
        name: identity?.name,
        email: identity?.email,
        organizationId: identity?.name,
        permissions: result.scopes || ['read', 'write', 'export', 'webhook'],
      }
      await cacheUser(token, user)
      return { valid: true, user }
    }

    // WorkOS API key (sk_*) — validated against WorkOS API
    if (token.startsWith('sk_') && this.env.WORKOS_API_KEY) {
      const result = await validateWorkOSApiKey(token, this.env.WORKOS_API_KEY)
      if (result.valid) {
        const user: AuthUser = {
          id: result.id || 'workos-key',
          name: result.name,
          organizationId: result.organization_id,
          permissions: result.permissions || ['read', 'write'],
        }
        await cacheUser(token, user)
        return { valid: true, user }
      }
      return { valid: false, error: 'Invalid WorkOS API key' }
    }

    // JWT — try our own JWKS first (login flow JWTs), then WorkOS JWKS
    // WorkOS JWKS also covers oauth.do-issued JWTs (signed with WorkOS keys)
    const ownUser = await this.verifyOwnJWT(token)
    if (ownUser) {
      await cacheUser(token, ownUser)
      return { valid: true, user: ownUser }
    }

    const workosUser = await this.verifyWorkOSJWT(token)
    if (workosUser) {
      await cacheUser(token, workosUser)
      return { valid: true, user: workosUser }
    }

    // Try oauth.do JWKS (tokens issued by oauth.do with iss: 'https://oauth.do')
    const oauthDoUser = await this.verifyOAuthDoJWT(token)
    if (oauthDoUser) {
      await cacheUser(token, oauthDoUser)
      return { valid: true, user: oauthDoUser }
    }

    // Cache negative result to prevent repeated verification of bad tokens
    await cacheNegativeResult(token)
    return { valid: false, error: 'Unrecognized token format. Use ses_* (session), oai_*/hly_sk_* (API key), sk_* (WorkOS key), or a JWT.' }
  }

  // ── getUser ─────────────────────────────────────────────────────────
  // Get user from token. Returns null if invalid.

  async getUser(token: string): Promise<AuthUser | null> {
    const result = await this.verifyToken(token)
    return result.valid ? result.user : null
  }

  // ── authenticate ────────────────────────────────────────────────────
  // Authenticate from Authorization header and/or cookie.
  // Designed for middleware use — returns structured result.
  // Supports: Bearer tokens (ses_*, oai_*, hly_sk_*, WorkOS JWT) and cookies.

  async authenticate(authorization?: string | null, cookie?: string | null): Promise<AuthRPCResult> {
    let token: string | null = null

    // Try Bearer header first
    if (authorization?.startsWith('Bearer ')) {
      token = authorization.slice(7)
    }

    // Try cookie if no bearer token
    if (!token && cookie) {
      // Try 'auth' cookie (oauth.do convention), then 'wos-session' (WorkOS AuthKit)
      token = parseCookieValue(cookie, 'auth') ?? parseCookieValue(cookie, 'wos-session') ?? null
    }

    if (!token) {
      return { ok: false, status: 401, error: 'No credentials provided' }
    }

    const result = await this.verifyToken(token)
    if (result.valid) {
      return { ok: true, user: result.user }
    }
    return { ok: false, status: 401, error: result.error }
  }

  // ── hasRoles ────────────────────────────────────────────────────────
  // Check if token has any of the specified roles.

  async hasRoles(token: string, roles: string[]): Promise<boolean> {
    const user = await this.getUser(token)
    if (!user) return false
    const userRoles = user.roles || []
    return roles.some((r) => userRoles.includes(r))
  }

  // ── hasPermissions ──────────────────────────────────────────────────
  // Check if token has all of the specified permissions.

  async hasPermissions(token: string, permissions: string[]): Promise<boolean> {
    const user = await this.getUser(token)
    if (!user) return false
    const userPerms = user.permissions || []
    return permissions.every((p) => userPerms.includes(p))
  }

  // ── isAdmin ─────────────────────────────────────────────────────────
  // Check if token belongs to an admin user.

  async isAdmin(token: string): Promise<boolean> {
    return this.hasRoles(token, ['admin', 'superadmin'])
  }

  // ── invalidate ──────────────────────────────────────────────────────
  // Invalidate cached result for a token.
  // Use when user permissions change or token is revoked.

  async invalidate(token: string): Promise<boolean> {
    // Always clear from Cache API
    await invalidateCachedToken(token)

    // For session tokens: also delete the KV routing entry
    if (token.startsWith('ses_')) {
      await this.env.SESSIONS.delete(`session:${token}`)
      return true
    }

    // For API keys: also delete the KV routing entry
    if (token.startsWith('oai_') || token.startsWith('hly_sk_')) {
      await this.env.SESSIONS.delete(`apikey:${token}`)
      return true
    }

    // For JWTs: cache was already cleared above
    return true
  }

  // ── JWT Verification (private) ──────────────────────────────────────
  // Two-layer JWT verification:
  //   1. Own JWKS: JWTs issued by /callback (login flow) — signed by us
  //   2. WorkOS JWKS: JWTs issued by WorkOS AuthKit (SSO, social) OR oauth.do (auth.apis.do)

  private async verifyOwnJWT(token: string): Promise<AuthUser | null> {
    // Verify JWTs signed by us using keys from DO storage directly.
    // No HTTP round-trip — avoids circular self-fetch to our own JWKS endpoint.
    try {
      const oauthStub = this.env.IDENTITY.get(this.env.IDENTITY.idFromName('oauth')) as unknown as IdentityStub
      const manager = new SigningKeyManager((op) => oauthStub.oauthStorageOp(op))
      const jwksData = await manager.getJWKS()
      const localJWKS = jose.createLocalJWKSet(jwksData as jose.JSONWebKeySet)
      const { payload } = await jose.jwtVerify(token, localJWKS, {
        issuer: 'https://id.org.ai',
      })

      return {
        id: payload.sub || '',
        email: payload.email as string | undefined,
        name: payload.name as string | undefined,
        image: payload.image as string | undefined,
        organizationId: payload.org_id as string | undefined,
        roles: payload.roles as string[] | undefined,
        permissions: payload.permissions as string[] | undefined,
        metadata: payload.metadata as Record<string, unknown> | undefined,
      }
    } catch {
      return null
    }
  }

  private async verifyWorkOSJWT(token: string): Promise<AuthUser | null> {
    // Verifies JWTs signed with WorkOS keys. Accepts two types:
    //   1. WorkOS-issued JWTs (aud === clientId) — SSO, social login
    //   2. oauth.do-issued JWTs (iss === 'https://auth.apis.do') — signed with WorkOS keys
    // Both are verified against the same WorkOS JWKS endpoint.
    const clientId = this.env.WORKOS_CLIENT_ID
    if (!clientId) return null

    const jwksUri = `https://api.workos.com/sso/jwks/${clientId}`

    try {
      const jwks = getJwksVerifier(jwksUri)
      // Verify signature against WorkOS JWKS without audience/issuer constraints,
      // then check either aud === clientId OR iss === 'https://auth.apis.do'
      const { payload } = await jose.jwtVerify(token, jwks)

      const isWorkOSIssued = payload.aud === clientId || (Array.isArray(payload.aud) && payload.aud.includes(clientId))
      const isOAuthDoIssued = payload.iss === 'https://auth.apis.do'

      if (!isWorkOSIssued && !isOAuthDoIssued) return null

      // For oauth.do-issued JWTs, normalize WorkOS scoped permissions
      // (e.g. "admin:write") to platform permissions.
      if (isOAuthDoIssued) {
        const rawPerms = payload.permissions as string[] | undefined
        const roles = payload.roles as string[] | undefined
        const isAdmin = roles?.includes('admin') || rawPerms?.some((p) => p.startsWith('admin:'))
        const permissions = isAdmin
          ? ['read', 'write', 'delete', 'search', 'fetch', 'do', 'try', 'claim', ...(rawPerms || [])]
          : [
              ...(rawPerms || []),
              ...(rawPerms?.some((p) => p.includes(':write')) ? ['write'] : []),
              ...(rawPerms?.some((p) => p.includes(':read')) ? ['read'] : []),
            ]

        return {
          id: payload.sub || '',
          email: payload.email as string | undefined,
          name: payload.name as string | undefined,
          image: payload.picture as string | undefined,
          organizationId: payload.org_id as string | undefined,
          roles,
          permissions,
          metadata: payload.metadata as Record<string, unknown> | undefined,
        }
      }

      // WorkOS-issued JWT — pass through permissions as-is
      return {
        id: payload.sub || '',
        email: payload.email as string | undefined,
        name: payload.name as string | undefined,
        image: payload.picture as string | undefined,
        organizationId: payload.org_id as string | undefined,
        roles: payload.roles as string[] | undefined,
        permissions: payload.permissions as string[] | undefined,
        metadata: payload.metadata as Record<string, unknown> | undefined,
      }
    } catch {
      return null
    }
  }

  private async verifyOAuthDoJWT(token: string): Promise<AuthUser | null> {
    // Verifies JWTs signed by oauth.do (iss: 'https://oauth.do')
    // Uses oauth.do's JWKS endpoint to fetch the public key.
    const jwksUri = 'https://oauth.do/.well-known/jwks.json'

    try {
      const jwks = getJwksVerifier(jwksUri)
      const { payload } = await jose.jwtVerify(token, jwks, {
        issuer: 'https://oauth.do',
      })

      return {
        id: payload.sub || '',
        email: payload.email as string | undefined,
        name: payload.name as string | undefined,
        image: payload.picture as string | undefined,
        organizationId: payload.org_id as string | undefined,
        roles: payload.roles as string[] | undefined,
        permissions: payload.permissions as string[] | undefined,
        metadata: payload.metadata as Record<string, unknown> | undefined,
      }
    } catch {
      return null
    }
  }
}

// AuthRPC alias — events.do and other consumers bind with entrypoint: "AuthRPC"
export { AuthService as AuthRPC }

const app = new Hono<{ Bindings: Env; Variables: Variables }>()

// ── Shard Resolution ─────────────────────────────────────────────────────
// Resolves the identity ID (shard key) from a request's auth credentials.
// Uses KV for token → identityId lookups so each identity gets its own DO.

/**
 * Get a DO stub for a specific identity shard.
 * Returns a typed IdentityStub for direct RPC calls.
 */
function getStubForIdentity(env: Env, identityId: string): IdentityStub {
  const id = env.IDENTITY.idFromName(identityId)
  return env.IDENTITY.get(id) as unknown as IdentityStub
}

/**
 * Extract the API key from a request (oai_* prefix).
 */
function isApiKeyPrefix(s: string): boolean {
  return s.startsWith('oai_') || s.startsWith('hly_sk_') || s.startsWith('sk_')
}

function extractApiKey(request: Request): string | null {
  const header = request.headers.get('x-api-key')
  if (header && isApiKeyPrefix(header)) return header
  const auth = request.headers.get('authorization')
  if (auth?.startsWith('Bearer ')) {
    const token = auth.slice(7)
    if (isApiKeyPrefix(token)) return token
  }
  try {
    const url = new URL(request.url)
    const keyParam = url.searchParams.get('api_key')
    if (keyParam && isApiKeyPrefix(keyParam)) return keyParam
  } catch {
    /* ignore */
  }
  return null
}

/**
 * Extract the session token from a request (ses_* prefix).
 */
function extractSessionToken(request: Request): string | null {
  const auth = request.headers.get('authorization')
  if (auth?.startsWith('Bearer ses_')) return auth.slice(7)
  return null
}

/**
 * Resolve the identity ID (shard key) from the request's auth credentials.
 * Returns null for anonymous/L0 requests that don't need a DO.
 */
async function resolveIdentityId(request: Request, env: Env): Promise<string | null> {
  // 1. API key → KV lookup
  const apiKey = extractApiKey(request)
  if (apiKey) {
    const identityId = await env.SESSIONS.get(`apikey:${apiKey}`)
    return identityId
  }

  // 2. Session token → KV lookup
  const sessionToken = extractSessionToken(request)
  if (sessionToken) {
    const identityId = await env.SESSIONS.get(`session:${sessionToken}`)
    return identityId
  }

  // 3. No credentials → anonymous (no DO needed)
  return null
}

/**
 * Resolve the identity ID from a claim token via KV.
 */
async function resolveIdentityFromClaim(claimToken: string, env: Env): Promise<string | null> {
  if (!claimToken?.startsWith('clm_')) return null
  return env.SESSIONS.get(`claim:${claimToken}`)
}

// ── CORS ──────────────────────────────────────────────────────────────────
// Tightened CORS: only allow specific origins (*.headless.ly, *.org.ai, localhost for dev).
// The origin callback dynamically checks against the allowlist.

app.use(
  '*',
  cors({
    origin: (origin) => {
      if (!origin) return origin
      return isAllowedOrigin(origin) ? origin : ''
    },
    allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization', 'X-API-Key'],
    credentials: true,
  }),
)

// ── Origin Validation for Mutating Requests ──────────────────────────────
// Validates Origin header on POST/PUT/DELETE to prevent cross-origin attacks
// from unlisted origins. Requests without an Origin header are allowed
// (same-origin, non-browser clients like curl/agents).

app.use('*', async (c, next) => {
  const error = validateOrigin(c.req.raw)
  if (error) return error
  await next()
})

// ── Identity Stub Middleware ──────────────────────────────────────────────
// Resolves the shard key from auth credentials and injects the correct
// IdentityDO stub into context. Each identity gets its own DO instance.

app.use('*', async (c, next) => {
  const identityId = await resolveIdentityId(c.req.raw, c.env)

  if (identityId) {
    // Authenticated request — route to identity-specific DO
    c.set('identityStub', getStubForIdentity(c.env, identityId))
  }
  // For anonymous/L0 requests, identityStub is NOT set.
  // Routes that require a stub will handle this explicitly
  // (e.g., provision creates a new identity, claim resolves via KV).

  await next()
})

// ── Health (no auth required) ─────────────────────────────────────────────

app.get('/health', (c) =>
  c.json({
    status: 'ok',
    service: 'id.org.ai',
    tagline: 'Humans. Agents. Identity.',
  }),
)

// ── Auth Config for @mdxui/auth SPA (no auth required) ───────────────────

app.get('/auth-config.json', (c) => {
  const host = c.req.header('host') || 'id.org.ai'
  return c.json({
    clientId: c.env.WORKOS_CLIENT_ID,
    redirectUri: c.env.REDIRECT_URI || `https://${host}/callback`,
    appName: c.env.APP_NAME || host.split('.')[0],
    tagline: c.env.APP_TAGLINE || 'Humans. Agents. Identity.',
    onUnauthenticated: 'landing',
    providers: ['github', 'google', 'microsoft'],
  })
})

// ── OIDC Discovery (no auth required) ─────────────────────────────────────

app.get('/.well-known/openid-configuration', (c) => {
  const provider = getOAuthProvider(c)
  return provider.getOpenIDConfiguration()
})

// ── JWKS Endpoint (no auth required) ────────────────────────────────────────
// Serves the public signing keys for JWT verification by other workers.
// Other workers verify our JWTs by fetching this endpoint.

app.get('/.well-known/jwks.json', async (c) => {
  const oauthStub = getStubForIdentity(c.env, 'oauth')
  const manager = new SigningKeyManager((op) => oauthStub.oauthStorageOp(op))
  const jwks = await manager.getJWKS()
  return c.json(jwks, 200, {
    'Cache-Control': 'public, max-age=3600',
  })
})

// ── WorkOS Login Flow (no auth required) ─────────────────────────────────────
// Human authentication via WorkOS AuthKit (SSO, social login, MFA).
// GET /login → redirect to WorkOS → GET /callback → set cookie → redirect

app.get('/login', async (c) => {
  const clientId = c.env.WORKOS_CLIENT_ID
  if (!clientId || !c.env.WORKOS_API_KEY) {
    return errorResponse(c, 503, ErrorCode.ServiceUnavailable, 'WorkOS is not configured')
  }

  const rawContinue = c.req.query('continue') || c.req.query('redirect_uri') || '/'
  const continueUrl = isSafeRedirectUrl(rawContinue) ? rawContinue : '/'
  const csrf = crypto.randomUUID()
  const state = encodeLoginState(csrf, continueUrl)

  // Store CSRF token for validation on callback (5 min TTL)
  const oauthStub = getStubForIdentity(c.env, 'oauth')
  await oauthStub.oauthStorageOp({
    op: 'put',
    key: `login-csrf:${csrf}`,
    value: { csrf, createdAt: Date.now() },
    options: { expirationTtl: 300 },
  })

  const redirectUri = new URL('/callback', c.req.url).origin + '/callback'
  // Allow forcing a specific provider (e.g. ?provider=GitHubOAuth)
  const provider = c.req.query('provider') || undefined
  const VALID_PROVIDERS = ['authkit', 'GitHubOAuth', 'GoogleOAuth', 'MicrosoftOAuth', 'AppleOAuth']
  const safeProvider = provider && VALID_PROVIDERS.includes(provider) ? provider : undefined
  const authUrl = buildWorkOSAuthUrl(clientId, redirectUri, state, safeProvider)
  return c.redirect(authUrl, 302)
})

app.get('/callback', async (c) => {
  const clientId = c.env.WORKOS_CLIENT_ID
  const apiKey = c.env.WORKOS_API_KEY
  if (!clientId || !apiKey) {
    return errorResponse(c, 503, ErrorCode.ServiceUnavailable, 'WorkOS is not configured')
  }

  const code = c.req.query('code')
  const state = c.req.query('state')
  const error = c.req.query('error')

  if (error) {
    const desc = c.req.query('error_description') || 'Authentication failed'
    return errorResponse(c, 400, ErrorCode.InvalidGrant, desc)
  }

  if (!code || !state) {
    return errorResponse(c, 400, ErrorCode.InvalidRequest, 'Missing code or state parameter')
  }

  // Decode and validate state (CSRF)
  const decoded = decodeLoginState(state)
  if (!decoded) {
    return errorResponse(c, 400, ErrorCode.InvalidRequest, 'Invalid state parameter')
  }

  const oauthStub = getStubForIdentity(c.env, 'oauth')
  const csrfData = await oauthStub.oauthStorageOp({ op: 'get', key: `login-csrf:${decoded.csrf}` })
  if (!csrfData.value) {
    return errorResponse(c, 403, ErrorCode.Forbidden, 'Invalid or expired CSRF token')
  }
  // Consume CSRF token (one-time use)
  await oauthStub.oauthStorageOp({ op: 'delete', key: `login-csrf:${decoded.csrf}` })

  // Exchange code with WorkOS
  let authResult
  try {
    authResult = await exchangeWorkOSCode(clientId, apiKey, code)
  } catch (err: any) {
    return errorResponse(c, 502, ErrorCode.ServerError, err.message)
  }

  // Create or find identity for this human user
  const shardKey = `human:${authResult.user.id}`
  const stub = getStubForIdentity(c.env, shardKey)

  let identity = await stub.getIdentity(shardKey)
  if (!identity) {
    // Create new human identity
    const fullName = [authResult.user.first_name, authResult.user.last_name].filter(Boolean).join(' ')
    identity = await stub.provisionAnonymous(shardKey).then((r) => r.identity)
    // Upgrade to human type + level 2 (claimed via WorkOS)
    await stub.oauthStorageOp({
      op: 'put',
      key: `identity:${shardKey}`,
      value: {
        id: shardKey,
        type: 'human',
        name: fullName || authResult.user.email,
        email: authResult.user.email,
        verified: true,
        level: 2,
        claimStatus: 'claimed',
        workosUserId: authResult.user.id,
        organizationId: authResult.user.organization_id || authResult.organization_id,
        createdAt: Date.now(),
      },
    })
    identity = await stub.getIdentity(shardKey)
  }

  // Sign our own JWT for the auth cookie
  const signingManager = new SigningKeyManager((op) => oauthStub.oauthStorageOp(op))
  const jwt = await signingManager.sign(
    {
      sub: authResult.user.id,
      email: authResult.user.email,
      name: [authResult.user.first_name, authResult.user.last_name].filter(Boolean).join(' ') || undefined,
      org_id: authResult.user.organization_id || authResult.organization_id,
      roles: authResult.user.roles,
      permissions: authResult.user.permissions,
    },
    { issuer: 'https://id.org.ai', expiresIn: 3600 },
  )

  // Build redirect response with auth cookie (validate redirect target)
  const continueUrl = isSafeRedirectUrl(decoded.continue || '/') ? (decoded.continue || '/') : '/'
  const reqUrl = new URL(c.req.url)
  const isSecure = reqUrl.protocol === 'https:'
  const domain = getRootDomain(reqUrl.hostname)
  const cookieFlags = [`auth=${jwt}`, 'HttpOnly', 'Path=/', `SameSite=Lax`, `Max-Age=3600`, ...(isSecure ? ['Secure'] : []), ...(domain ? [`Domain=${domain}`] : [])].join('; ')

  return new Response(null, {
    status: 302,
    headers: {
      Location: continueUrl,
      'Set-Cookie': cookieFlags,
    },
  })
})

// ── Logout ────────────────────────────────────────────────────────────────────

app.get('/logout', (c) => {
  const rawReturnUrl = c.req.query('return_url') || '/'
  const returnUrl = isSafeRedirectUrl(rawReturnUrl) ? rawReturnUrl : '/'
  const reqUrl = new URL(c.req.url)
  const isSecure = reqUrl.protocol === 'https:'
  const domain = getRootDomain(reqUrl.hostname)
  const clearCookie = ['auth=', 'HttpOnly', 'Path=/', 'SameSite=Lax', 'Max-Age=0', ...(isSecure ? ['Secure'] : []), ...(domain ? [`Domain=${domain}`] : [])].join('; ')

  return new Response(null, {
    status: 302,
    headers: {
      Location: returnUrl,
      'Set-Cookie': clearCookie,
    },
  })
})

app.post('/logout', (c) => {
  const reqUrl = new URL(c.req.url)
  const isSecure = reqUrl.protocol === 'https:'
  const domain = getRootDomain(reqUrl.hostname)
  const clearCookie = ['auth=', 'HttpOnly', 'Path=/', 'SameSite=Lax', 'Max-Age=0', ...(isSecure ? ['Secure'] : []), ...(domain ? [`Domain=${domain}`] : [])].join('; ')

  return c.json({ ok: true }, 200, { 'Set-Cookie': clearCookie })
})

// ── Validate API Key Endpoint ────────────────────────────────────────────────
// Validates WorkOS API keys (sk_*) — mirrors oauth.do's POST /validate-api-key

app.post('/validate-api-key', async (c) => {
  if (!c.env.WORKOS_API_KEY) {
    return errorResponse(c, 503, ErrorCode.ServiceUnavailable, 'WorkOS is not configured')
  }

  const body = (await c.req.json().catch(() => ({}))) as { api_key?: string }
  if (!body.api_key) {
    return errorResponse(c, 400, ErrorCode.InvalidRequest, 'api_key is required')
  }

  const result = await validateWorkOSApiKey(body.api_key, c.env.WORKOS_API_KEY)
  return c.json(result)
})

// ── MCP Auth Middleware ───────────────────────────────────────────────────
// Authenticates every request below this point. The auth result is always
// set in context — L0 (anonymous) is a valid result, not an error.
// If no identityStub was resolved (anonymous), MCPAuth returns L0 result.

async function authenticateRequest(c: any, next: () => Promise<void>) {
  const stub = c.get('identityStub')

  // Detect explicit credentials in the request
  const hasExplicitApiKey = !!extractApiKey(c.req.raw)
  const hasExplicitSession = !!extractSessionToken(c.req.raw)

  if (stub) {
    const mcpAuth = new MCPAuth(stub)
    const auth = await mcpAuth.authenticate(c.req.raw)

    // Explicit credentials provided but auth failed → reject (don't silently downgrade to L0)
    if ((hasExplicitApiKey || hasExplicitSession) && !auth.authenticated) {
      return errorResponse(c, 401, ErrorCode.Unauthorized, auth.error || 'Invalid credentials')
    }

    c.set('auth', auth)
  } else if (hasExplicitApiKey || hasExplicitSession) {
    // Credentials provided but couldn't resolve identity from KV → invalid/expired
    return errorResponse(c, 401, ErrorCode.Unauthorized, 'Invalid or expired credentials')
  } else {
    // True anonymous L0 — no credentials provided
    c.set('auth', MCPAuth.anonymousResult())
  }
  await next()
}

app.use('/api/*', authenticateRequest)
app.use('/mcp', authenticateRequest)
app.use('/mcp/*', authenticateRequest)
app.use('/oauth/authorize', authenticateRequest)
app.use('/device', authenticateRequest)

// ── MCP Endpoint ──────────────────────────────────────────────────────────
// Returns capabilities based on auth level. This is the entry point for
// agents connecting via MCP protocol.

app.get('/mcp', async (c) => {
  const auth = c.get('auth')
  const meta = MCPAuth.buildMetaStatic(auth)

  return c.json({
    jsonrpc: '2.0',
    result: {
      protocolVersion: '2024-11-05',
      serverInfo: {
        name: 'id.org.ai',
        version: '1.0.0',
      },
      capabilities: {
        tools: buildToolList(auth),
        resources: buildResourceList(auth),
      },
      _meta: meta,
    },
  })
})

app.post('/mcp', async (c) => {
  const auth = c.get('auth')
  const stub = c.get('identityStub')
  const meta = MCPAuth.buildMetaStatic(auth)

  // Rate limit check
  if (auth.rateLimit && !auth.rateLimit.allowed) {
    // Audit: rate limit exceeded
    if (stub && auth.identityId) {
      await logAuditEvent(stub, {
        event: AUDIT_EVENTS.RATE_LIMIT_EXCEEDED,
        actor: auth.identityId,
        ip: c.req.raw.headers.get('cf-connecting-ip') ?? undefined,
        userAgent: c.req.raw.headers.get('user-agent') ?? undefined,
        metadata: { level: auth.level, remaining: auth.rateLimit.remaining },
      })
    }

    return c.json(
      {
        jsonrpc: '2.0',
        error: {
          code: -32000,
          message: 'Rate limit exceeded',
          data: meta,
        },
      },
      429,
    )
  }

  const body = (await c.req.json()) as { method?: string; params?: any; id?: string | number }

  // Handle MCP initialize
  if (body.method === 'initialize') {
    return c.json({
      jsonrpc: '2.0',
      id: body.id,
      result: {
        protocolVersion: '2024-11-05',
        serverInfo: { name: 'id.org.ai', version: '1.0.0' },
        capabilities: {
          tools: buildToolList(auth),
          resources: buildResourceList(auth),
        },
        _meta: meta,
      },
    })
  }

  // Handle tools/list
  if (body.method === 'tools/list') {
    return c.json({
      jsonrpc: '2.0',
      id: body.id,
      result: {
        tools: buildToolList(auth),
        _meta: meta,
      },
    })
  }

  // Handle tools/call — dispatch to tool handlers
  if (body.method === 'tools/call') {
    const toolName = body.params?.name as string

    // Check capability level — explore is always available, try requires L1+
    const toolLevelMap: Record<string, number> = { explore: 0, search: 0, fetch: 0, try: 1, do: 1 }
    const requiredLevel = toolLevelMap[toolName] ?? 0

    if (requiredLevel > auth.level) {
      return c.json(
        {
          jsonrpc: '2.0',
          id: body.id,
          error: {
            code: -32601,
            message: `Tool "${toolName}" requires Level ${requiredLevel}+ authentication`,
            data: { ...meta, requiredLevel, currentLevel: auth.level },
          },
        },
        403,
      )
    }

    // L1+ tools require a DO stub (authenticated identity)
    if (requiredLevel >= 1 && !stub) {
      return c.json(
        {
          jsonrpc: '2.0',
          id: body.id,
          error: {
            code: -32601,
            message: `Tool "${toolName}" requires authentication`,
            data: meta,
          },
        },
        401,
      )
    }

    // For L0 tools without a stub, pass a null-safe stub
    // (explore, search schema-only, and fetch schema-only don't need the DO)
    const effectiveStub = stub ?? nullStub

    // Dispatch to the tool handler
    const toolResult = await dispatchTool(toolName, body.params?.arguments ?? {}, effectiveStub, auth)

    return c.json({
      jsonrpc: '2.0',
      id: body.id,
      result: { ...toolResult, _meta: meta },
    })
  }

  return c.json(
    {
      jsonrpc: '2.0',
      id: body.id,
      error: { code: -32601, message: 'Method not found', data: meta },
    },
    404,
  )
})

// ── Provision Endpoint ────────────────────────────────────────────────────
// Auto-provisions an anonymous tenant. No auth required.
// Creates a NEW identity with its own Durable Object instance (shard).
// Writes token → identityId mappings to KV for future request routing.

app.post('/api/provision', async (c) => {
  // Generate a new identity ID to use as the shard key.
  // We pass this to the DO so the identity ID matches the shard key.
  const shardKey = crypto.randomUUID()
  const stub = getStubForIdentity(c.env, shardKey)

  try {
    const data = await stub.provisionAnonymous(shardKey)

    // Build the provision result
    const result = {
      tenantId: data.identity.name,
      identityId: data.identity.id,
      sessionToken: data.sessionToken,
      claimToken: data.claimToken,
      level: 1 as const,
      limits: {
        maxEntities: 1000,
        ttlHours: 24,
        maxRequestsPerMinute: 100,
      },
      upgrade: {
        nextLevel: 2 as const,
        action: 'claim' as const,
        description: 'Commit a GitHub Action workflow to claim this tenant',
        url: `https://id.org.ai/claim/${data.claimToken}`,
      },
    }

    // Write KV mappings so future requests can route to this shard.
    // Session token → identityId (24h TTL matches session TTL)
    await c.env.SESSIONS.put(`session:${data.sessionToken}`, data.identity.id, { expirationTtl: 86400 })
    // Claim token → identityId (30 days — claim window)
    await c.env.SESSIONS.put(`claim:${data.claimToken}`, data.identity.id, { expirationTtl: 2592000 })

    // Audit: identity provisioned
    await logAuditEvent(stub, {
      event: AUDIT_EVENTS.IDENTITY_CREATED,
      actor: 'anonymous',
      target: data.identity.id,
      ip: c.req.raw.headers.get('cf-connecting-ip') ?? undefined,
      userAgent: c.req.raw.headers.get('user-agent') ?? undefined,
      metadata: { tenantName: data.identity.name, level: 1 },
    })

    return c.json(result, 201)
  } catch (err: any) {
    return errorResponse(c, 500, ErrorCode.ProvisionFailed, err.message)
  }
})

// ── Claim Status Endpoint ─────────────────────────────────────────────────

app.get('/api/claim/:token', async (c) => {
  const token = c.req.param('token')

  // Resolve shard from claim token via KV
  const identityId = await resolveIdentityFromClaim(token, c.env)
  if (!identityId) {
    return errorResponse(c, 404, ErrorCode.InvalidClaimToken, 'Unknown or expired claim token')
  }
  const stub = getStubForIdentity(c.env, identityId)

  try {
    const status = await verifyClaim(token, stub)
    return c.json(status, status.valid ? 200 : 404)
  } catch (err: any) {
    return errorResponse(c, 500, ErrorCode.VerificationFailed, err.message)
  }
})

// ── Freeze Endpoint ───────────────────────────────────────────────────────
// Requires L1+ auth. Freezes the caller's own tenant.

app.post('/api/freeze', async (c) => {
  const auth = c.get('auth')
  if (!auth.authenticated || !auth.identityId) {
    return errorResponse(c, 401, ErrorCode.Unauthorized, 'Session token required to freeze a tenant')
  }

  // Stub is already set by middleware for authenticated requests
  const stub = c.get('identityStub')
  if (!stub) {
    return errorResponse(c, 500, ErrorCode.ServerError, 'Identity stub not resolved')
  }
  const claimService = new ClaimService(stub)

  try {
    const result = await claimService.freeze(auth.identityId)

    // Audit: identity frozen
    await logAuditEvent(stub, {
      event: AUDIT_EVENTS.IDENTITY_FROZEN,
      actor: auth.identityId,
      target: auth.identityId,
      ip: c.req.raw.headers.get('cf-connecting-ip') ?? undefined,
      userAgent: c.req.raw.headers.get('user-agent') ?? undefined,
      metadata: { stats: result.stats },
    })

    return c.json(result)
  } catch (err: any) {
    return errorResponse(c, 500, ErrorCode.FreezeFailed, err.message)
  }
})

// ── API Key Management Endpoints ─────────────────────────────────────────
// CRUD for API keys. Prefers WorkOS API keys when WORKOS_API_KEY is configured,
// falls back to custom hly_sk_* keys for tenants without WorkOS. Requires L1+.

app.post('/api/keys', async (c) => {
  const auth = c.get('auth')
  if (!auth.authenticated || !auth.identityId) {
    return errorResponse(c, 401, ErrorCode.Unauthorized, 'Authentication required to create API keys')
  }

  const stub = c.get('identityStub')
  if (!stub) {
    return errorResponse(c, 500, ErrorCode.ServerError, 'Identity stub not resolved')
  }

  const body = (await c.req.json().catch(() => ({}))) as {
    name?: string
    scopes?: string[]
    expiresAt?: string
  }

  if (!body.name) {
    return errorResponse(c, 400, ErrorCode.InvalidRequest, 'name is required')
  }

  // Use WorkOS API keys when configured — WorkOS handles generation, rotation, validation
  if (c.env.WORKOS_API_KEY) {
    try {
      const result = await createWorkOSApiKey(c.env.WORKOS_API_KEY, {
        name: body.name,
        permissions: body.scopes,
        expiresAt: body.expiresAt,
      })
      return c.json({ id: result.id, key: result.key, name: result.name }, 201)
    } catch (err: any) {
      return errorResponse(c, 500, ErrorCode.ServerError, err.message)
    }
  }

  // Fallback to custom hly_sk_* keys for tenants without WorkOS
  try {
    const result = await stub.createApiKey({
      name: body.name,
      identityId: auth.identityId,
      scopes: body.scopes,
      expiresAt: body.expiresAt,
    })

    // Write KV mapping so future requests with this key route to the correct DO shard
    await c.env.SESSIONS.put(`apikey:${result.key}`, auth.identityId)

    return c.json(result, 201)
  } catch (err: any) {
    const msg = err.message ?? 'Failed to create API key'
    if (msg.includes('Invalid scope') || msg.includes('in the future') || msg.includes('required')) {
      return errorResponse(c, 400, ErrorCode.InvalidRequest, msg)
    }
    return errorResponse(c, 500, ErrorCode.ServerError, msg)
  }
})

app.get('/api/keys', async (c) => {
  const auth = c.get('auth')
  if (!auth.authenticated || !auth.identityId) {
    return errorResponse(c, 401, ErrorCode.Unauthorized, 'Authentication required to list API keys')
  }

  const stub = c.get('identityStub')
  if (!stub) {
    return errorResponse(c, 500, ErrorCode.ServerError, 'Identity stub not resolved')
  }

  // Use WorkOS API keys when configured
  if (c.env.WORKOS_API_KEY) {
    try {
      const workosKeys = await listWorkOSApiKeys(c.env.WORKOS_API_KEY)
      const keys = workosKeys.map((k) => ({
        id: k.id,
        name: k.name,
        organization_id: k.organization_id,
        created_at: k.created_at,
        last_used_at: k.last_used_at,
      }))
      return c.json({ keys })
    } catch (err: any) {
      return errorResponse(c, 500, ErrorCode.ServerError, err.message)
    }
  }

  // Fallback to custom hly_sk_* keys
  try {
    const keys = await stub.listApiKeys(auth.identityId)
    return c.json({ keys })
  } catch (err: any) {
    return errorResponse(c, 500, ErrorCode.ServerError, err.message)
  }
})

app.delete('/api/keys/:id', async (c) => {
  const auth = c.get('auth')
  if (!auth.authenticated || !auth.identityId) {
    return errorResponse(c, 401, ErrorCode.Unauthorized, 'Authentication required to revoke API keys')
  }

  const stub = c.get('identityStub')
  if (!stub) {
    return errorResponse(c, 500, ErrorCode.ServerError, 'Identity stub not resolved')
  }

  const keyId = c.req.param('id')

  // Use WorkOS API keys when configured
  if (c.env.WORKOS_API_KEY) {
    try {
      const revoked = await revokeWorkOSApiKey(c.env.WORKOS_API_KEY, keyId)
      if (!revoked) {
        return errorResponse(c, 500, ErrorCode.ServerError, 'Failed to revoke WorkOS API key')
      }
      return c.json({ id: keyId, status: 'revoked', revokedAt: new Date().toISOString() })
    } catch (err: any) {
      return errorResponse(c, 500, ErrorCode.ServerError, err.message)
    }
  }

  // Fallback to custom hly_sk_* keys
  try {
    const result = await stub.revokeApiKey(keyId, auth.identityId)
    if (!result) {
      return errorResponse(c, 404, ErrorCode.NotFound, 'API key not found')
    }

    // Clean up KV entry so the revoked key can't route to a DO anymore
    if (result.key) {
      await c.env.SESSIONS.delete(`apikey:${result.key}`)
    }

    // Don't expose the key string in the response
    return c.json({ id: result.id, status: result.status, revokedAt: result.revokedAt })
  } catch (err: any) {
    return errorResponse(c, 500, ErrorCode.ServerError, err.message)
  }
})

// ── Audit Log Query Endpoint ─────────────────────────────────────────────
// Requires L2+ auth. Queries the audit log for the caller's identity DO.

app.get('/api/audit', async (c) => {
  const auth = c.get('auth')
  if (!auth.authenticated || !auth.identityId) {
    return errorResponse(c, 401, ErrorCode.Unauthorized, 'Authentication required to query audit log')
  }
  if (auth.level < 2) {
    return errorResponse(c, 403, ErrorCode.InsufficientLevel, 'L2+ authentication required to access audit logs')
  }

  const stub = c.get('identityStub')
  if (!stub) {
    return errorResponse(c, 500, ErrorCode.ServerError, 'Identity stub not resolved')
  }

  // Build query options from URL params
  const url = new URL(c.req.url)
  const queryParams: AuditQueryOptions = {}
  if (url.searchParams.has('eventPrefix')) queryParams.eventPrefix = url.searchParams.get('eventPrefix')!
  if (url.searchParams.has('actor')) queryParams.actor = url.searchParams.get('actor')!
  if (url.searchParams.has('after')) queryParams.after = url.searchParams.get('after')!
  if (url.searchParams.has('before')) queryParams.before = url.searchParams.get('before')!
  if (url.searchParams.has('limit')) queryParams.limit = parseInt(url.searchParams.get('limit')!, 10)
  if (url.searchParams.has('cursor')) queryParams.cursor = url.searchParams.get('cursor')!

  try {
    const data = await stub.queryAuditLog(queryParams)
    return c.json(data)
  } catch (err: any) {
    return errorResponse(c, 500, ErrorCode.ServerError, err.message)
  }
})

// ── OAuth 2.1 Provider Endpoints ──────────────────────────────────────────
// Wires the OAuthProvider class into the Hono router. The provider uses the
// IdentityDO's storage (via RPC) for client, token, and consent state.

function getOAuthProvider(c: any): OAuthProvider {
  // OAuth state (clients, tokens, consent) lives in a dedicated 'oauth' shard.
  // This is separate from identity sharding — OAuth is a system-level concern.
  const stub = getStubForIdentity(c.env, 'oauth')
  const base = 'https://id.org.ai'
  return new OAuthProvider({
    storage: {
      async get<T = unknown>(key: string): Promise<T | undefined> {
        const result = await stub.oauthStorageOp({ op: 'get', key })
        return result.value as T | undefined
      },
      async put(key: string, value: unknown, options?: { expirationTtl?: number }): Promise<void> {
        await stub.oauthStorageOp({ op: 'put', key, value, options })
      },
      async delete(key: string): Promise<boolean> {
        const result = await stub.oauthStorageOp({ op: 'delete', key })
        return !!result.deleted
      },
      async list<T = unknown>(options?: { prefix?: string; limit?: number }): Promise<Map<string, T>> {
        const result = await stub.oauthStorageOp({ op: 'list', options })
        return new Map(result.entries as Array<[string, T]>)
      },
    },
    config: {
      issuer: base,
      authorizationEndpoint: `${base}/oauth/authorize`,
      tokenEndpoint: `${base}/oauth/token`,
      userinfoEndpoint: `${base}/oauth/userinfo`,
      registrationEndpoint: `${base}/oauth/register`,
      deviceAuthorizationEndpoint: `${base}/oauth/device`,
      revocationEndpoint: `${base}/oauth/revoke`,
      introspectionEndpoint: `${base}/oauth/introspect`,
      jwksUri: `${base}/.well-known/jwks.json`,
    },
    getIdentity: async (id: string) => {
      // Identity data lives in the identity's own shard, not in the oauth shard
      const identityStub = getStubForIdentity(c.env, id)
      const identity = await identityStub.getIdentity(id)
      if (!identity) return null
      return identity as unknown as { id: string; name?: string; handle?: string; email?: string; emailVerified?: boolean; image?: string }
    },
  })
}

// Dynamic Client Registration (RFC 7591)
app.post('/oauth/register', async (c) => {
  const provider = getOAuthProvider(c)
  return provider.handleRegister(c.req.raw)
})

// Authorization Endpoint — CSRF protected
// On GET: generate a CSRF token, set it as a cookie, and embed it in the state parameter.
// On POST (consent submission): validate the CSRF token from cookie + form body.
app.get('/oauth/authorize', async (c) => {
  const auth = c.get('auth')
  const identityId = auth?.authenticated ? (auth.identityId ?? null) : null

  // Generate CSRF token for the consent form
  const oauthStub = getStubForIdentity(c.env, 'oauth')
  const csrfToken = generateCSRFToken()
  // Store the CSRF token in the oauth DO's storage via RPC
  await oauthStub.oauthStorageOp({
    op: 'put',
    key: `csrf:${csrfToken}`,
    value: { token: csrfToken, createdAt: Date.now(), expiresAt: Date.now() + 30 * 60 * 1000 },
  })

  // Inject the CSRF token into the state parameter
  const url = new URL(c.req.url)
  const originalState = url.searchParams.get('state') ?? undefined
  const stateWithCSRF = encodeStateWithCSRF(csrfToken, originalState)
  url.searchParams.set('state', stateWithCSRF)

  // Create a modified request with the CSRF-enhanced state
  const modifiedRequest = new Request(url.toString(), {
    method: c.req.raw.method,
    headers: c.req.raw.headers,
  })

  const provider = getOAuthProvider(c)
  const response = await provider.handleAuthorize(modifiedRequest, identityId)

  // Set the CSRF cookie on the response
  const isSecure = new URL(c.req.url).protocol === 'https:'
  const newResponse = new Response(response.body, response)
  newResponse.headers.append('Set-Cookie', buildCSRFCookie(csrfToken, isSecure))
  return newResponse
})

// Authorization Consent Submission — CSRF validated
app.post('/oauth/authorize', async (c) => {
  const auth = c.get('auth')
  if (!auth?.authenticated || !auth.identityId) {
    return errorResponse(c, 401, ErrorCode.AuthenticationRequired, 'Authentication required to submit authorization consent')
  }

  // Extract CSRF token from cookie
  const cookieCSRF = extractCSRFFromCookie(c.req.raw)

  // Extract CSRF token from the state parameter in the form body
  const clonedRequest = c.req.raw.clone()
  const contentType = c.req.raw.headers.get('content-type') || ''
  let formState: string | undefined
  if (contentType.includes('application/json')) {
    const body = (await clonedRequest.json()) as Record<string, string>
    formState = body.state
  } else {
    const form = await clonedRequest.formData()
    formState = form.get('state') as string | undefined
  }

  let formCSRF: string | null = null
  if (formState) {
    const decoded = decodeStateWithCSRF(formState)
    if (decoded) {
      formCSRF = decoded.csrf
    }
  }

  // Validate CSRF double-submit: cookie token must match state-embedded token
  if (!cookieCSRF || !formCSRF || cookieCSRF !== formCSRF) {
    // Log the CSRF failure
    const auditStub = getStubForIdentity(c.env, 'oauth')
    await auditStub.oauthStorageOp({
      op: 'put',
      key: `audit:${new Date().toISOString()}:csrf.validation.failed:${crypto.randomUUID().slice(0, 8)}`,
      value: {
        event: AUDIT_EVENTS.CSRF_VALIDATION_FAILED,
        actor: auth.identityId,
        ip: c.req.raw.headers.get('cf-connecting-ip') ?? undefined,
        userAgent: c.req.raw.headers.get('user-agent') ?? undefined,
        timestamp: new Date().toISOString(),
      },
    })

    return errorResponse(c, 403, ErrorCode.Forbidden, 'CSRF token mismatch or missing')
  }

  // Validate the CSRF token server-side (check it exists and is not expired)
  const oauthStub = getStubForIdentity(c.env, 'oauth')
  const csrfData = await oauthStub.oauthStorageOp({ op: 'get', key: `csrf:${cookieCSRF}` })

  const csrfValue = csrfData.value as { expiresAt?: number } | undefined
  if (!csrfValue || (csrfValue.expiresAt && Date.now() > csrfValue.expiresAt)) {
    return errorResponse(c, 403, ErrorCode.Forbidden, csrfValue ? 'CSRF token expired' : 'Unknown CSRF token')
  }
  // Consume the token (one-time use)
  await oauthStub.oauthStorageOp({ op: 'delete', key: `csrf:${cookieCSRF}` })

  const provider = getOAuthProvider(c)
  return provider.handleAuthorizeConsent(c.req.raw, auth.identityId)
})

// Token Endpoint
app.post('/oauth/token', async (c) => {
  const provider = getOAuthProvider(c)
  return provider.handleToken(c.req.raw)
})

// Device Authorization (RFC 8628)
app.post('/oauth/device', async (c) => {
  const provider = getOAuthProvider(c)
  return provider.handleDeviceAuthorization(c.req.raw)
})

// Device Verification (browser-side)
app.all('/device', async (c) => {
  const auth = c.get('auth')
  const identityId = auth?.authenticated ? (auth.identityId ?? null) : null
  const provider = getOAuthProvider(c)
  return provider.handleDeviceVerification(c.req.raw, identityId)
})

// UserInfo Endpoint (OIDC Core)
app.get('/oauth/userinfo', async (c) => {
  const provider = getOAuthProvider(c)
  return provider.handleUserinfo(c.req.raw)
})

// Token Introspection (RFC 7662)
app.post('/oauth/introspect', async (c) => {
  const provider = getOAuthProvider(c)
  return provider.handleIntrospect(c.req.raw)
})

// Token Revocation (RFC 7009)
app.post('/oauth/revoke', async (c) => {
  const provider = getOAuthProvider(c)
  return provider.handleRevoke(c.req.raw)
})

// Fallback for unhandled /oauth/* routes
app.all('/oauth/*', async (c) => {
  return errorResponse(c, 404, ErrorCode.NotFound, 'OAuth endpoint not found')
})

// ── Claim page (human-facing) ─────────────────────────────────────────────

app.get('/claim/:token', async (c) => {
  const token = c.req.param('token')

  // Resolve shard from claim token via KV
  const identityId = await resolveIdentityFromClaim(token, c.env)
  if (!identityId) {
    return errorResponse(c, 404, ErrorCode.InvalidClaimToken, 'This claim token is invalid or has expired.')
  }
  const stub = getStubForIdentity(c.env, identityId)
  const status = await verifyClaim(token, stub)

  if (!status.valid) {
    return errorResponse(c, 404, ErrorCode.InvalidClaimToken, 'This claim token is invalid or has expired.')
  }

  // Return claim info for the human-facing claim page
  return c.json({
    claimToken: token,
    status: status.status,
    stats: status.stats,
    instructions: {
      step1: 'Add this GitHub Action workflow to your repository:',
      file: '.github/workflows/headlessly.yml',
      content: buildClaimWorkflow(token),
      step2: 'Push to your main branch',
      step3: 'The push event will link your GitHub identity to this tenant',
    },
  })
})

// ── WorkOS Directory Sync Webhooks ────────────────────────────────────────
// POST /webhooks/workos — receive WorkOS Directory Sync (SCIM) events.
// No auth middleware — WorkOS authenticates via webhook signature.

app.post('/webhooks/workos', async (c) => {
  if (!c.env.DB) return c.json({ error: 'SCIM not configured' }, 503)

  const rawBody = await c.req.text()
  let body: DSyncEvent

  try {
    body = JSON.parse(rawBody) as DSyncEvent
  } catch {
    return c.json({ error: 'Invalid JSON payload' }, 400)
  }

  if (!body.event || !body.data) {
    return c.json({ error: 'Invalid webhook payload' }, 400)
  }

  // Verify webhook signature when WORKOS_WEBHOOK_SECRET is configured.
  // WorkOS signs webhooks with HMAC-SHA256 using the webhook signing secret.
  if (c.env.WORKOS_WEBHOOK_SECRET) {
    const signature = c.req.header('workos-signature')
    if (!signature) {
      return c.json({ error: 'Missing webhook signature' }, 401)
    }

    const isValid = await verifyWorkOSWebhookSignature(
      rawBody,
      signature,
      c.env.WORKOS_WEBHOOK_SECRET,
    )
    if (!isValid) {
      return c.json({ error: 'Invalid webhook signature' }, 401)
    }
  }

  try {
    await ensureSCIMTables(c.env.DB)

    switch (body.event) {
      case 'dsync.user.created': {
        const result = await handleDSyncUserCreated(body.data as DSyncUser, c.env.DB)
        return c.json({ ok: true, ...result })
      }
      case 'dsync.user.updated': {
        const result = await handleDSyncUserUpdated(body.data as DSyncUser, c.env.DB)
        return c.json({ ok: true, ...result })
      }
      case 'dsync.user.deleted': {
        const result = await handleDSyncUserDeleted(body.data as DSyncUser, c.env.DB)
        return c.json({ ok: true, ...result })
      }
      case 'dsync.group.created': {
        const result = await handleDSyncGroupCreated(body.data as DSyncGroup, c.env.DB)
        return c.json({ ok: true, ...result })
      }
      case 'dsync.group.updated': {
        const result = await handleDSyncGroupUpdated(body.data as DSyncGroup, c.env.DB)
        return c.json({ ok: true, ...result })
      }
      case 'dsync.group.deleted': {
        const result = await handleDSyncGroupDeleted(body.data as DSyncGroup, c.env.DB)
        return c.json({ ok: true, ...result })
      }
      case 'dsync.group.user_added': {
        const result = await handleDSyncGroupUserAdded(body.data as DSyncGroupMembership, c.env.DB)
        return c.json({ ok: true, ...result })
      }
      case 'dsync.group.user_removed': {
        const result = await handleDSyncGroupUserRemoved(body.data as DSyncGroupMembership, c.env.DB)
        return c.json({ ok: true, ...result })
      }
      default:
        return c.json({ ok: true, skipped: true, event: body.event })
    }
  } catch (err: any) {
    console.error(`[webhooks/workos] Error handling ${body.event}:`, err)
    return c.json({ error: 'Internal error processing webhook' }, 500)
  }
})

// ── WorkOS Admin Portal ──────────────────────────────────────────────────
// GET /admin-portal — Generate a WorkOS Admin Portal link for SCIM/SSO setup.
// Enterprise IT admins use this to self-service their directory connection.

app.get('/admin-portal', async (c) => {
  const orgId = c.req.query('organization_id')
  if (!orgId) {
    return c.json({ error: 'organization_id query param required' }, 400)
  }

  if (!c.env.WORKOS_API_KEY) {
    return errorResponse(c, 503, ErrorCode.ServiceUnavailable, 'WorkOS is not configured')
  }

  try {
    const result = await getAdminPortalUrl(orgId, c.env.WORKOS_API_KEY)
    return c.json(result)
  } catch (err: any) {
    return errorResponse(c, 500, ErrorCode.ServerError, err.message)
  }
})

// ── FGA (Fine-Grained Authorization) Endpoints ──────────────────────────────
// Entity-level authorization using WorkOS FGA (Zanzibar-style).
// Manages resource types, permission checks, and cross-tenant sharing.

// POST /fga/setup — Initialize FGA resource types (admin only, run once)
app.post('/fga/setup', async (c) => {
  if (!c.env.WORKOS_API_KEY) return c.json({ error: 'WorkOS not configured' }, 503)
  await defineResourceTypes(c.env.WORKOS_API_KEY)
  return c.json({ ok: true, resourceTypes: FGA_RESOURCE_TYPES.length })
})

// POST /fga/check — Check a permission
app.post('/fga/check', async (c) => {
  if (!c.env.WORKOS_API_KEY) return c.json({ error: 'WorkOS not configured' }, 503)
  const body = (await c.req.json()) as FGACheckRequest
  const authorized = await checkPermission(c.env.WORKOS_API_KEY, body)
  return c.json({ authorized })
})

// POST /fga/share — Share a resource cross-tenant
app.post('/fga/share', async (c) => {
  if (!c.env.WORKOS_API_KEY) return c.json({ error: 'WorkOS not configured' }, 503)
  const body = (await c.req.json()) as { resourceType: string; resourceId: string; targetTenant: string; relation?: string }
  const fgaType = entityTypeToFGA(body.resourceType)
  if (!fgaType) return c.json({ error: `Unknown resource type: ${body.resourceType}` }, 400)
  await shareResource(c.env.WORKOS_API_KEY, fgaType, body.resourceId, body.targetTenant, (body.relation as FGARelation) || 'viewer')
  return c.json({ ok: true })
})

// DELETE /fga/share — Revoke cross-tenant sharing
app.delete('/fga/share', async (c) => {
  if (!c.env.WORKOS_API_KEY) return c.json({ error: 'WorkOS not configured' }, 503)
  const body = (await c.req.json()) as { resourceType: string; resourceId: string; targetTenant: string; relation?: string }
  const fgaType = entityTypeToFGA(body.resourceType)
  if (!fgaType) return c.json({ error: `Unknown resource type: ${body.resourceType}` }, 400)
  await unshareResource(c.env.WORKOS_API_KEY, fgaType, body.resourceId, body.targetTenant, (body.relation as FGARelation) || 'viewer')
  return c.json({ ok: true })
})

// GET /fga/accessible — List resources accessible by a user
app.get('/fga/accessible', async (c) => {
  if (!c.env.WORKOS_API_KEY) return c.json({ error: 'WorkOS not configured' }, 503)
  const resourceType = c.req.query('type')
  const userId = c.req.query('user')
  if (!resourceType || !userId) return c.json({ error: 'type and user query params required' }, 400)
  const fgaType = entityTypeToFGA(resourceType)
  if (!fgaType) return c.json({ error: `Unknown resource type: ${resourceType}` }, 400)
  const resources = await listAccessible(c.env.WORKOS_API_KEY, fgaType, userId)
  return c.json({ resources })
})

// ── WorkOS Vault — Secret Management ────────────────────────────────────────
// CRUD for encrypted secrets stored in WorkOS Vault.
// Secrets are used by code functions, workflows, integrations, and API proxies.
// The /vault/resolve endpoint does NOT expose actual secret values in the API
// response — values are only injected by runtime (code execution, workflows).

// POST /vault/secrets — Create a new secret
app.post('/vault/secrets', async (c) => {
  if (!c.env.WORKOS_API_KEY) return c.json({ error: 'WorkOS not configured' }, 503)
  const body = await c.req.json<CreateSecretOptions>()
  if (!body.name || !body.value) {
    return c.json({ error: 'name and value are required' }, 400)
  }
  const secret = await createVaultSecret(c.env.WORKOS_API_KEY, body)
  return c.json(secret, 201)
})

// GET /vault/secrets — List all secrets (metadata only)
app.get('/vault/secrets', async (c) => {
  if (!c.env.WORKOS_API_KEY) return c.json({ error: 'WorkOS not configured' }, 503)
  const env = c.req.query('environment')
  const limit = c.req.query('limit')
  const after = c.req.query('after')
  const result = await listVaultSecrets(c.env.WORKOS_API_KEY, {
    environment: env,
    limit: limit ? parseInt(limit) : undefined,
    after,
  })
  return c.json(result)
})

// GET /vault/secrets/:id — Get secret metadata (no value)
app.get('/vault/secrets/:id', async (c) => {
  if (!c.env.WORKOS_API_KEY) return c.json({ error: 'WorkOS not configured' }, 503)
  const id = c.req.param('id')
  try {
    const secret = await getVaultSecret(c.env.WORKOS_API_KEY, id)
    return c.json(secret)
  } catch {
    return c.json({ error: 'Secret not found' }, 404)
  }
})

// GET /vault/secrets/:id/reveal — Get secret with decrypted value
app.get('/vault/secrets/:id/reveal', async (c) => {
  if (!c.env.WORKOS_API_KEY) return c.json({ error: 'WorkOS not configured' }, 503)
  const id = c.req.param('id')
  try {
    const secret = await readVaultSecretValue(c.env.WORKOS_API_KEY, id)
    return c.json(secret)
  } catch {
    return c.json({ error: 'Secret not found or cannot be revealed' }, 404)
  }
})

// PUT /vault/secrets/:id — Update a secret
app.put('/vault/secrets/:id', async (c) => {
  if (!c.env.WORKOS_API_KEY) return c.json({ error: 'WorkOS not configured' }, 503)
  const id = c.req.param('id')
  const body = await c.req.json<UpdateSecretOptions>()
  const secret = await updateVaultSecret(c.env.WORKOS_API_KEY, id, body)
  return c.json(secret)
})

// DELETE /vault/secrets/:id — Delete a secret
app.delete('/vault/secrets/:id', async (c) => {
  if (!c.env.WORKOS_API_KEY) return c.json({ error: 'WorkOS not configured' }, 503)
  const id = c.req.param('id')
  await deleteVaultSecret(c.env.WORKOS_API_KEY, id)
  return c.json({ ok: true })
})

// POST /vault/resolve — Resolve a secret by name (runtime API)
// NOTE: This endpoint does NOT expose actual secret values in the response.
// Values are only injected into runtime contexts by the code execution worker
// and workflow engine, which call resolveSecret() directly.
app.post('/vault/resolve', async (c) => {
  if (!c.env.WORKOS_API_KEY) return c.json({ error: 'WorkOS not configured' }, 503)
  const body = await c.req.json<{ name?: string; names?: string[]; template?: string }>()

  // Single secret resolution
  if (body.name) {
    try {
      await resolveSecret(c.env.WORKOS_API_KEY, body.name)
      return c.json({ name: body.name, resolved: true })
      // NOTE: We return resolved:true but NOT the value in the response
      // The value should only be injected into runtime contexts, not exposed via API
    } catch {
      return c.json({ name: body.name, resolved: false, error: 'Secret not found' }, 404)
    }
  }

  // Batch resolution
  if (body.names) {
    const resolved = await resolveSecrets(c.env.WORKOS_API_KEY, body.names)
    return c.json({
      resolved: Object.keys(resolved),
      missing: body.names.filter((n) => !(n in resolved)),
    })
  }

  // Template interpolation
  if (body.template) {
    await interpolateSecrets(c.env.WORKOS_API_KEY, body.template)
    return c.json({ interpolated: true })
    // Again, don't return the actual interpolated string via API
  }

  return c.json({ error: 'Provide name, names, or template' }, 400)
})

// ── WorkOS Pipes — Managed OAuth Connections ─────────────────────────────────
// Replaces manual OAuth token management for third-party providers (Slack, GitHub, etc.).
// WorkOS handles the OAuth flow, token storage, and automatic refresh.

// POST /pipes/token — Get a fresh access token for a provider
app.post('/pipes/token', async (c) => {
  if (!c.env.WORKOS_API_KEY) return c.json({ error: 'WorkOS not configured' }, 503)
  const body = await c.req.json<{ provider: string; userId: string; organizationId?: string }>()
  if (!body.provider || !body.userId) {
    return c.json({ error: 'provider and userId are required' }, 400)
  }
  if (!PIPES_PROVIDERS.includes(body.provider as PipesProvider)) {
    return c.json({ error: `Unsupported provider: ${body.provider}. Supported: ${PIPES_PROVIDERS.join(', ')}` }, 400)
  }
  const token = await getAccessToken(c.env.WORKOS_API_KEY, body.provider as PipesProvider, body.userId, body.organizationId)
  return c.json(token)
})

// GET /pipes/connections — List all connections
app.get('/pipes/connections', async (c) => {
  if (!c.env.WORKOS_API_KEY) return c.json({ error: 'WorkOS not configured' }, 503)
  const userId = c.req.query('user_id')
  const orgId = c.req.query('organization_id')
  const provider = c.req.query('provider')
  const result = await listConnections(c.env.WORKOS_API_KEY, {
    userId: userId || undefined,
    organizationId: orgId || undefined,
    provider: (provider as PipesProvider) || undefined,
  })
  return c.json(result)
})

// GET /pipes/connections/:id — Get a specific connection
app.get('/pipes/connections/:id', async (c) => {
  if (!c.env.WORKOS_API_KEY) return c.json({ error: 'WorkOS not configured' }, 503)
  try {
    const connection = await getConnection(c.env.WORKOS_API_KEY, c.req.param('id'))
    return c.json(connection)
  } catch {
    return c.json({ error: 'Connection not found' }, 404)
  }
})

// DELETE /pipes/connections/:id — Disconnect a provider
app.delete('/pipes/connections/:id', async (c) => {
  if (!c.env.WORKOS_API_KEY) return c.json({ error: 'WorkOS not configured' }, 503)
  await disconnectConnection(c.env.WORKOS_API_KEY, c.req.param('id'))
  return c.json({ ok: true })
})

// GET /pipes/status — Get connection status for all providers
app.get('/pipes/status', async (c) => {
  if (!c.env.WORKOS_API_KEY) return c.json({ error: 'WorkOS not configured' }, 503)
  const userId = c.req.query('user_id')
  const orgId = c.req.query('organization_id')
  if (!userId) return c.json({ error: 'user_id query param required' }, 400)
  const status = await getConnectionStatus(c.env.WORKOS_API_KEY, userId, orgId || undefined)
  return c.json({ providers: status })
})

// ── GitHub webhook endpoint ───────────────────────────────────────────────

app.post('/webhook/github', async (c) => {
  const signature = c.req.header('x-hub-signature-256')
  const event = c.req.header('x-github-event')
  const deliveryId = c.req.header('x-github-delivery')
  const body = await c.req.text()

  // Validate required environment variables
  if (!c.env.GITHUB_WEBHOOK_SECRET || !c.env.GITHUB_APP_ID || !c.env.GITHUB_APP_PRIVATE_KEY) {
    return errorResponse(c, 503, ErrorCode.ServiceUnavailable, 'GitHub App is not configured')
  }

  const githubApp = new GitHubApp({
    webhookSecret: c.env.GITHUB_WEBHOOK_SECRET,
    appId: c.env.GITHUB_APP_ID,
    privateKey: c.env.GITHUB_APP_PRIVATE_KEY,
  })

  // Verify webhook signature
  if (!(await githubApp.verifySignature(body, signature ?? ''))) {
    return errorResponse(c, 401, ErrorCode.InvalidSignature, 'Webhook signature verification failed')
  }

  // Handle push events — the core claim-by-commit flow
  if (event === 'push') {
    const push = JSON.parse(body) as PushEvent

    // The GitHubApp.handlePush needs to fetch the workflow file from GitHub,
    // parse the claim token, then route to the correct DO shard.
    // We use a sharded stub resolver that wraps handlePush.
    const result = await handlePushWithSharding(githubApp, push, c.env)

    return c.json({
      event: 'push',
      delivery: deliveryId,
      ...result,
    })
  }

  // Handle installation events for logging/telemetry
  if (event === 'installation') {
    const payload = JSON.parse(body) as { action: string; installation: { id: number; account: { login: string } } }
    return c.json({
      received: true,
      event: 'installation',
      action: payload.action,
      account: payload.installation?.account?.login,
      delivery: deliveryId,
    })
  }

  // Handle installation_repositories events
  if (event === 'installation_repositories') {
    return c.json({
      received: true,
      event: 'installation_repositories',
      delivery: deliveryId,
    })
  }

  // Acknowledge all other events
  return c.json({
    received: true,
    event,
    delivery: deliveryId,
  })
})

// ── Fallback: serve @mdxui/auth SPA or 404 ───────────────────────────────

app.all('*', async (c) => {
  // If ASSETS binding exists, serve static SPA files
  if (c.env.ASSETS) {
    const response = await c.env.ASSETS.fetch(c.req.raw)
    if (response.status !== 404) return response
  }
  return errorResponse(c, 404, ErrorCode.NotFound, 'The requested endpoint does not exist')
})

export default app

// ============================================================================
// GitHub Push Sharding
// ============================================================================

/**
 * Handle a GitHub push webhook with identity sharding.
 *
 * The GitHubApp.handlePush method needs a DO stub, but the webhook doesn't
 * carry auth credentials — it carries a claim token embedded in the workflow
 * YAML. We resolve the claim token to an identity via KV, then pass the
 * correct shard's stub to handlePush.
 *
 * Flow:
 *   1. Check if any commit touches the headlessly workflow file
 *   2. If not, return early (no claim)
 *   3. Fetch the workflow file from GitHub
 *   4. Parse the claim token from the YAML
 *   5. Resolve identity ID from claim token via KV
 *   6. Get the correct DO stub for that identity
 *   7. Call the claim method on that specific DO via RPC
 */
async function handlePushWithSharding(
  githubApp: GitHubApp,
  push: PushEvent,
  env: Env,
): Promise<{
  claimed: boolean
  claimToken?: string
  tenantId?: string
  level?: number
  branch?: string
  error?: string
}> {
  // Check if any commit touches the headlessly workflow
  const WORKFLOW_PATH = '.github/workflows/headlessly.yml'
  const touchedWorkflow = push.commits.some((c) => c.added.includes(WORKFLOW_PATH) || c.modified.includes(WORKFLOW_PATH))

  if (!touchedWorkflow) {
    return { claimed: false }
  }

  const branch = push.ref.replace('refs/heads/', '')

  if (!push.installation?.id) {
    return { claimed: false, branch, error: 'missing_installation_id' }
  }

  // Fetch the workflow file to extract the claim token
  let yamlContent: string | null = null
  try {
    yamlContent = await githubApp.fetchWorkflowContent(push.repository.full_name, push.ref, push.installation.id)
  } catch (err: any) {
    return { claimed: false, branch, error: `fetch_workflow_failed: ${err.message}` }
  }

  if (!yamlContent) {
    return { claimed: false, branch, error: 'workflow_file_not_found' }
  }

  const claimToken = githubApp.parseClaimToken(yamlContent)
  if (!claimToken) {
    return { claimed: false, branch, error: 'no_claim_token_in_workflow' }
  }

  // Resolve the identity shard from the claim token
  const identityId = await resolveIdentityFromClaim(claimToken, env)
  if (!identityId) {
    return { claimed: false, claimToken, branch, error: 'unknown_claim_token' }
  }

  // Get the DO stub for this specific identity and execute the claim via RPC
  const stub = getStubForIdentity(env, identityId)

  try {
    const result = await stub.claim({
      claimToken,
      githubUserId: String(push.sender.id),
      githubUsername: push.sender.login,
      githubEmail: push.sender.email,
      repo: push.repository.full_name,
      branch,
    })

    if (!result.success) {
      // Audit: claim failed
      await logAuditEvent(stub, {
        event: AUDIT_EVENTS.CLAIM_FAILED,
        actor: push.sender.login,
        target: identityId,
        metadata: { claimToken, repo: push.repository.full_name, branch, error: result.error },
      })

      return { claimed: false, claimToken, branch, error: result.error ?? 'claim_failed' }
    }

    // Audit: claim completed
    await logAuditEvent(stub, {
      event: AUDIT_EVENTS.CLAIM_COMPLETED,
      actor: push.sender.login,
      target: result.identity?.id ?? identityId,
      metadata: {
        claimToken,
        repo: push.repository.full_name,
        branch,
        githubUserId: String(push.sender.id),
        level: result.identity?.level,
      },
    })

    return {
      claimed: true,
      claimToken,
      tenantId: result.identity?.id,
      level: result.identity?.level,
      branch,
    }
  } catch (err: any) {
    return { claimed: false, claimToken, branch, error: `claim_request_failed: ${err.message}` }
  }
}

// ============================================================================
// Audit Logging Helper
// ============================================================================

/**
 * Fire-and-forget audit event logger.
 *
 * Writes an audit event to the identity's Durable Object storage via RPC.
 * This is intentionally fire-and-forget: audit logging MUST NEVER break
 * the primary request flow.
 *
 * The event is stored with key format: `audit:{timestamp}:{event}:{randomSuffix}`
 */
async function logAuditEvent(
  stub: IdentityStub,
  event: {
    event: string
    actor?: string
    target?: string
    ip?: string
    userAgent?: string
    metadata?: Record<string, unknown>
  },
): Promise<void> {
  try {
    const timestamp = new Date().toISOString()
    const suffix = crypto.randomUUID().slice(0, 8)
    const key = `audit:${timestamp}:${event.event}:${suffix}`
    await stub.writeAuditEvent(key, { ...event, timestamp, key } as StoredAuditEvent)
  } catch {
    // Fire-and-forget: audit logging should never break the primary flow
  }
}

// ============================================================================
// Null-safe Stub for L0 (Anonymous) Requests
// ============================================================================

/**
 * A no-op IdentityStub for L0 requests that don't have a real DO.
 * All methods return empty/null results. Only used for schema-only tools
 * (explore, search schema, fetch schema) at L0 that technically receive
 * a stub but never call write methods.
 */
const nullStub: IdentityStub = {
  async getIdentity() {
    return null
  },
  async provisionAnonymous() {
    throw new Error('Not available at L0')
  },
  async claim() {
    return { success: false, error: 'Not available at L0' }
  },
  async getSession() {
    return { valid: false }
  },
  async validateApiKey() {
    return { valid: false }
  },
  async createApiKey() {
    throw new Error('Not available at L0')
  },
  async listApiKeys() {
    return []
  },
  async revokeApiKey() {
    return null
  },
  async checkRateLimit() {
    return { allowed: true, remaining: 30, resetAt: Date.now() + 60_000 }
  },
  async verifyClaimToken() {
    return { valid: false }
  },
  async freezeIdentity() {
    throw new Error('Not available at L0')
  },
  async mcpSearch() {
    return { results: [], total: 0, limit: 20, offset: 0 }
  },
  async mcpFetch() {
    return { type: '', data: null }
  },
  async mcpDo() {
    return { success: false, entity: '', verb: '', error: 'Not available at L0' }
  },
  async oauthStorageOp() {
    return {}
  },
  async writeAuditEvent() {},
  async queryAuditLog() {
    return { events: [], hasMore: false }
  },
}

// ============================================================================
// WorkOS Webhook Signature Verification
// ============================================================================

/**
 * Verify a WorkOS webhook signature.
 *
 * WorkOS sends a `workos-signature` header containing a timestamp and
 * HMAC-SHA256 signature. Format: `t={timestamp}, v1={signature}`
 *
 * Verification:
 *   1. Parse the timestamp and signature from the header
 *   2. Build the signed payload: `{timestamp}.{body}`
 *   3. Compute HMAC-SHA256 with the webhook secret
 *   4. Compare signatures in constant time
 */
async function verifyWorkOSWebhookSignature(
  body: string,
  signatureHeader: string,
  secret: string,
): Promise<boolean> {
  try {
    // Parse "t={timestamp}, v1={signature}" format
    const parts: Record<string, string> = {}
    for (const part of signatureHeader.split(',')) {
      const [key, ...valueParts] = part.trim().split('=')
      if (key && valueParts.length) {
        parts[key.trim()] = valueParts.join('=').trim()
      }
    }

    const timestamp = parts['t']
    const expectedSig = parts['v1']
    if (!timestamp || !expectedSig) return false

    // Build the signed payload: "{timestamp}.{body}"
    const signedPayload = `${timestamp}.${body}`

    const encoder = new TextEncoder()
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign'],
    )
    const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(signedPayload))
    const computedSig = Array.from(new Uint8Array(sig), (b) => b.toString(16).padStart(2, '0')).join('')

    // Constant-time comparison
    if (computedSig.length !== expectedSig.length) return false
    let mismatch = 0
    for (let i = 0; i < computedSig.length; i++) {
      mismatch |= computedSig.charCodeAt(i) ^ expectedSig.charCodeAt(i)
    }
    return mismatch === 0
  } catch {
    return false
  }
}

// ============================================================================
// Helpers
// ============================================================================

/**
 * Build the list of MCP tools available at the given auth level.
 *
 * Tools by level:
 *   L0+: explore, search, fetch
 *   L1+: try, do
 */
function buildToolList(auth: MCPAuthResult): Array<{ name: string; description: string; inputSchema: Record<string, unknown> }> {
  const tools: Array<{ name: string; description: string; inputSchema: Record<string, unknown> }> = []

  // explore — available at all levels (L0+)
  tools.push({
    name: 'explore',
    description: 'Discover all 32 entity schemas with verbs, fields, and relationships. Start here to understand the system.',
    inputSchema: {
      type: 'object',
      properties: {
        type: { type: 'string', description: 'Specific entity type to explore (e.g. Contact, Deal, Subscription). Omit for full system overview.' },
        depth: {
          type: 'string',
          enum: ['summary', 'full'],
          description: 'Detail level: summary (names + verbs) or full (complete schemas with field types). Default: summary',
        },
      },
    },
  })

  // search — available at all levels (L0+)
  tools.push({
    name: 'search',
    description: 'Search entities across the graph — schemas, identities, organizations, and data',
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string', description: 'Search query' },
        type: { type: 'string', description: 'Entity type to search (e.g. Contact, schema, identity)' },
        limit: { type: 'number', description: 'Max results (default 10, max 100)' },
      },
      required: ['query'],
    },
  })

  // fetch — available at all levels (L0+)
  tools.push({
    name: 'fetch',
    description: 'Fetch a specific entity, schema, or session. Use type=schema to get entity definitions.',
    inputSchema: {
      type: 'object',
      properties: {
        type: { type: 'string', description: 'Resource type: schema, identity, session, or any entity name (Contact, Deal, etc.)' },
        id: { type: 'string', description: 'Resource ID. For schema type, this is the entity name.' },
        fields: { type: 'array', items: { type: 'string' }, description: 'Optional: specific fields to return' },
      },
      required: ['type'],
    },
  })

  // try — available at L1+ (requires session)
  if (auth.level >= 1) {
    tools.push({
      name: 'try',
      description:
        'Execute-with-rollback. Run a sequence of operations and see the results WITHOUT persisting anything. Shows what would happen: entities created, events emitted, side effects triggered.',
      inputSchema: {
        type: 'object',
        properties: {
          operations: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                entity: { type: 'string', description: 'Entity type (e.g. Contact, Deal, Subscription)' },
                verb: { type: 'string', description: 'Verb to execute (e.g. create, close, qualify)' },
                data: { type: 'object', description: 'Operation data' },
              },
              required: ['entity', 'verb', 'data'],
            },
            description: 'Sequence of operations to simulate (max 50)',
          },
        },
        required: ['operations'],
      },
    })
  }

  // do — available at L1+ (requires session)
  if (auth.level >= 1) {
    tools.push({
      name: 'do',
      description: 'Execute any action on an entity for real. Creates/updates entities, emits events, triggers workflows.',
      inputSchema: {
        type: 'object',
        properties: {
          entity: { type: 'string', description: 'Entity type (e.g. Contact, Deal, Subscription)' },
          verb: { type: 'string', description: 'Verb to execute (e.g. create, update, close, qualify)' },
          data: { type: 'object', description: 'Operation data (fields, values, relationships)' },
        },
        required: ['entity', 'verb', 'data'],
      },
    })
  }

  return tools
}

/**
 * Build the list of MCP resources available at the given auth level.
 */
function buildResourceList(auth: MCPAuthResult): Array<{ name: string; description: string; uri: string }> {
  const resources: Array<{ name: string; description: string; uri: string }> = []

  resources.push({
    name: 'schema',
    description: 'Identity schema and type definitions',
    uri: 'id://schema',
  })

  if (auth.authenticated && auth.identityId) {
    resources.push({
      name: 'identity',
      description: 'Current authenticated identity',
      uri: `id://identity/${auth.identityId}`,
    })
  }

  return resources
}

/**
 * Build the GitHub Action workflow YAML for claim-by-commit.
 */
function buildClaimWorkflow(claimToken: string): string {
  return `name: Claim headless.ly tenant
on:
  push:
    branches: [main, master]
permissions:
  id-token: write
  contents: read
jobs:
  claim:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dot-org-ai/id@v1
        with:
          tenant: '${claimToken}'
`
}
