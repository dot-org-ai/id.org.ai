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
import { corsMiddleware, originValidationMiddleware, isAllowedOrigin, validateOrigin } from './middleware/origin'
import * as jose from 'jose'
import { IdentityDO } from '../src/do/Identity'
import type { IdentityStub } from '../src/do/Identity'
import type { Env, Variables, AuthRPCResult, AuthUser, VerifyResult } from './types'
import { parseCookieValue, buildAuthCookieHeaders, buildClearAuthCookieHeaders, getRootDomain } from './utils/cookies'
import { isApiKeyPrefix, extractApiKey, extractSessionToken } from './utils/extract'
import { authenticateRequest } from './middleware/auth'
import {
  getStubForIdentity,
  resolveIdentityId,
  resolveIdentityFromClaim,
  getLocalJwks,
  extractWorkOSUserFromJWT,
  identityStubMiddleware,
} from './middleware/tenant'
import { renderLandingPage } from './views/landing'
import { GitHubApp } from '../src/github/app'
import type { PushEvent } from '../src/github/app'
import { oauthRoutes, getOAuthProvider } from './routes/oauth'
import { claimRoutes } from './routes/claim'
import { SigningKeyManager } from '../src/jwt/signing'
import { DEFAULT_CALLBACK_URL, LEGACY_AUTH_ORIGIN, LEGACY_JWKS_URL, LEGACY_WORKOS_BRIDGE_ISSUER } from '../src/auth'
import {
  fetchWorkOSUser,
  extractGitHubId,
  fetchGitHubUsername,
  fetchOrgInfo,
  updateWorkOSUser,
  createWorkOSOrganization,
  createWorkOSMembership,
  listUserOrgMemberships,
  listOrgMembers,
  sendOrgInvitation,
} from '../src/workos/upstream'
import { validateWorkOSApiKey } from '../src/workos/apikey'
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
import { FGA_RESOURCE_TYPES, defineResourceTypes, checkPermission, shareResource, unshareResource, listAccessible, entityTypeToFGA } from '../src/workos/fga'
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
import { PIPES_PROVIDERS, getAccessToken, listConnections, getConnection, disconnectConnection, getConnectionStatus } from '../src/workos/pipes'
import type { PipesProvider } from '../src/workos/pipes'
import { AUDIT_EVENTS } from '../src/audit'
import { errorResponse, ErrorCode } from '../src/errors'
import { getCachedUser, cacheUser, invalidateCachedToken, isNegativelyCached, cacheNegativeResult } from './utils/cache'
import { logAuditEvent } from './utils/audit'
import { auditRoutes } from './routes/audit'
import { authRoutes } from './routes/auth'
import { apiKeyRoutes } from './routes/api-keys'
import { mcpRoutes } from './routes/mcp'

export { IdentityDO }

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

      const org = payload.org as { id?: string; name?: string; domains?: string[] } | undefined
      return {
        id: payload.sub || '',
        email: payload.email as string | undefined,
        name: payload.name as string | undefined,
        image: payload.image as string | undefined,
        organizationId: org?.id || (payload.org_id as string | undefined),
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
    //   2. Legacy oauth.do bridge JWTs (iss === 'https://auth.apis.do') — signed with WorkOS keys
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
      const isOAuthDoIssued = payload.iss === LEGACY_WORKOS_BRIDGE_ISSUER

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
    // Verifies JWTs signed by the legacy oauth.do compatibility surface.
    const jwksUri = LEGACY_JWKS_URL

    try {
      const jwks = getJwksVerifier(jwksUri)
      const { payload } = await jose.jwtVerify(token, jwks, {
        issuer: LEGACY_AUTH_ORIGIN,
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

// ── CORS ──────────────────────────────────────────────────────────────────
// Tightened CORS: only allow specific origins (*.headless.ly, *.org.ai, localhost for dev).
// The origin callback dynamically checks against the allowlist.

app.use('*', corsMiddleware)

// ── Origin Validation for Mutating Requests ──────────────────────────────
// Validates Origin header on POST/PUT/DELETE to prevent cross-origin attacks
// from unlisted origins. Requests without an Origin header are allowed
// (same-origin, non-browser clients like curl/agents).

app.use('*', originValidationMiddleware)

// ── Identity Stub Middleware ──────────────────────────────────────────────
// Resolves the shard key from auth credentials and injects the correct
// IdentityDO stub into context. Each identity gets its own DO instance.

app.use('*', identityStubMiddleware)

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
  return c.json({
    clientId: 'id_org_ai_dash',
    apiHostname: 'https://id.org.ai',
    redirectUri: 'https://id.org.ai/dash/profile',
    basePath: '/dash',
    appName: c.env.APP_NAME || 'id.org.ai',
    tagline: c.env.APP_TAGLINE || 'Humans. Agents. Identity.',
    onUnauthenticated: 'redirect',
    redirectUrl: 'https://id.org.ai/login',
    signOutRedirectUri: 'https://id.org.ai/',
    loginUrl: 'https://id.org.ai/login',
  })
})

// ── Dashboard SPA ────────────────────────────────────────────────────────
// Requires authentication. Unauthenticated users get redirected to /login.
// /dash/assets/* is served by ASSETS binding. All other /dash/* routes serve
// the SPA index.html so client-side routing works.

// Auth gate middleware — verifies JWT before serving any /dash/* SPA route.
// Static assets (js, css, fonts, etc.) are exempted so the ASSETS binding
// can serve them without a valid session cookie.
app.use('/dash/*', async (c, next) => {
  const pathname = new URL(c.req.url).pathname

  // Let static asset requests and OAuth callback through unguarded.
  // Assets are identified by having a file extension (e.g. .js, .css, .woff2).
  // /dash/callback must load the SPA so IdProvider can exchange the ?code= param.
  if (/\.[a-zA-Z0-9]+$/.test(pathname) || new URL(c.req.url).searchParams.has('code')) {
    return next()
  }

  const cookie = c.req.header('cookie')
  if (!cookie) {
    return c.redirect('/', 302)
  }

  const jwt = parseCookieValue(cookie, 'auth')
  if (!jwt) {
    return c.redirect('/', 302)
  }

  try {
    const oauthStub = getStubForIdentity(c.env, 'oauth')
    const manager = new SigningKeyManager((op) => oauthStub.oauthStorageOp(op))
    const jwks = await manager.getJWKS()
    const localJwks = jose.createLocalJWKSet(jwks)
    await jose.jwtVerify(jwt, localJwks, { issuer: 'https://id.org.ai' })
  } catch {
    return c.redirect('/', 302)
  }

  await next()
})

app.get('/dash', (c) => {
  // Already authenticated by middleware above
  return c.redirect('/dash/profile', 302)
})

app.get('/dash/*', async (c) => {
  // Serve static assets (js, css, etc.) — auth middleware exempts these
  if (c.env.ASSETS) {
    const assetResponse = await c.env.ASSETS.fetch(c.req.raw)
    if (assetResponse.status !== 404) return assetResponse
  }

  // Serve SPA index.html for all authenticated non-asset routes
  if (c.env.ASSETS) {
    const indexUrl = new URL('/dash/index.html', c.req.url)
    const indexReq = new Request(indexUrl, c.req.raw)
    return c.env.ASSETS.fetch(indexReq)
  }
  return errorResponse(c, 404, ErrorCode.NotFound, 'Dashboard not available')
})

// ── User Info (GET /me) ──────────────────────────────────────────────────
// Returns the authenticated user's profile. Compatible with oauth.do SDK's getUser().

app.get('/me', async (c) => {
  const authorization = c.req.header('Authorization')
  const cookie = c.req.header('Cookie')

  // Extract token: Bearer header first, then auth cookie
  let token: string | null = null
  if (authorization?.startsWith('Bearer ')) {
    token = authorization.slice(7)
  }
  if (!token && cookie) {
    token = parseCookieValue(cookie, 'auth') ?? parseCookieValue(cookie, 'wos-session') ?? null
  }
  if (!token) {
    return c.json({ error: 'Unauthorized' }, 401)
  }

  // Session token (ses_*) → KV lookup → DO
  if (token.startsWith('ses_')) {
    const identityId = await c.env.SESSIONS.get(`session:${token}`)
    if (!identityId) return c.json({ error: 'Unauthorized' }, 401)
    const stub = getStubForIdentity(c.env, identityId)
    const session = await stub.getSession(token)
    if (!session?.valid) return c.json({ error: 'Unauthorized' }, 401)
    const identity = await stub.getIdentity(identityId)
    return c.json({
      id: identityId,
      name: identity?.name,
      email: identity?.email,
      organizationId: identity?.name,
    })
  }

  // API key (oai_* or hly_sk_*) → KV lookup → DO
  if (token.startsWith('oai_') || token.startsWith('hly_sk_')) {
    const identityId = await c.env.SESSIONS.get(`apikey:${token}`)
    if (!identityId) return c.json({ error: 'Unauthorized' }, 401)
    const stub = getStubForIdentity(c.env, identityId)
    const result = await stub.validateApiKey(token)
    if (!result?.valid) return c.json({ error: 'Unauthorized' }, 401)
    const identity = await stub.getIdentity(identityId)
    return c.json({
      id: identityId,
      name: identity?.name,
      email: identity?.email,
      organizationId: identity?.name,
      permissions: result.scopes || ['read', 'write', 'export', 'webhook'],
    })
  }

  // JWT — verify against our own JWKS (id.org.ai-signed)
  try {
    const oauthStub = getStubForIdentity(c.env, 'oauth')
    const manager = new SigningKeyManager((op) => oauthStub.oauthStorageOp(op))
    const jwksData = await manager.getJWKS()
    const localJWKS = jose.createLocalJWKSet(jwksData as jose.JSONWebKeySet)
    const { payload } = await jose.jwtVerify(token, localJWKS, { issuer: 'https://id.org.ai' })
    const org = payload.org as { id?: string } | undefined
    return c.json({
      id: payload.sub || '',
      email: payload.email as string | undefined,
      name: payload.name as string | undefined,
      image: payload.image as string | undefined,
      organizationId: org?.id || (payload.org_id as string | undefined),
      roles: payload.roles as string[] | undefined,
      permissions: payload.permissions as string[] | undefined,
    })
  } catch {
    /* not our JWT, try next */
  }

  // JWT — verify against WorkOS JWKS
  const clientId = c.env.WORKOS_CLIENT_ID
  if (clientId) {
    try {
      const jwks = getJwksVerifier(`https://api.workos.com/sso/jwks/${clientId}`)
      const { payload } = await jose.jwtVerify(token, jwks)
      return c.json({
        id: payload.sub || '',
        email: payload.email as string | undefined,
        name: (payload.name || payload.first_name) as string | undefined,
        image: payload.picture as string | undefined,
        organizationId: payload.org_id as string | undefined,
        roles: payload.roles as string[] | undefined,
        permissions: payload.permissions as string[] | undefined,
      })
    } catch {
      /* not a WorkOS JWT */
    }
  }

  return c.json({ error: 'Unauthorized' }, 401)
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

// ── Auth Routes (login, callback, logout, session, widget-token) ─────────────
// Mounted before authenticateRequest — these routes handle their own auth.
app.route('', authRoutes)
app.route('', oauthRoutes)
app.route('', claimRoutes)

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
app.use('/api/*', authenticateRequest)
app.use('/mcp', authenticateRequest)
app.use('/mcp/*', authenticateRequest)
app.route('', auditRoutes)
app.route('', mcpRoutes)
app.route('', apiKeyRoutes)

// ── Organization Management Endpoints ────────────────────────────────────
// CRUD for organizations. Uses WorkOS Organization + Membership APIs.
// Requires L1+ auth. The authenticated user's WorkOS user ID is resolved
// from the identity record stored in the DO.

/**
 * Resolve the WorkOS user ID from the authenticated identity.
 */
async function resolveWorkOSUserId(stub: IdentityStub, identityId: string): Promise<string | null> {
  const stored = await stub.oauthStorageOp({ op: 'get', key: `identity:${identityId}` })
  const record = stored.value as { workosUserId?: string } | null
  return record?.workosUserId ?? null
}

// POST /api/orgs — Create a new organization
app.post('/api/orgs', async (c) => {
  if (!c.env.WORKOS_API_KEY) {
    return errorResponse(c, 503, ErrorCode.ServerError, 'WorkOS not configured')
  }

  const body = (await c.req.json().catch(() => ({}))) as { name?: string }
  if (!body.name || body.name.trim().length === 0) {
    return errorResponse(c, 400, ErrorCode.InvalidRequest, 'name is required')
  }

  // Resolve WorkOS user ID: standard auth (ses_*/API key) or JWT fallback
  let workosUserId: string | null = null
  const auth = c.get('auth')
  if (auth.authenticated && auth.identityId) {
    const stub = c.get('identityStub')
    if (stub) {
      workosUserId = await resolveWorkOSUserId(stub, auth.identityId)
    }
  }
  if (!workosUserId) {
    const jwt = await extractWorkOSUserFromJWT(c.req.raw, c.env)
    if (jwt?.sub) workosUserId = jwt.sub
  }
  if (!workosUserId) {
    return errorResponse(c, 401, ErrorCode.Unauthorized, 'Authentication required')
  }

  // 1. Create the organization in WorkOS
  const org = await createWorkOSOrganization(c.env.WORKOS_API_KEY, body.name.trim())
  if (!org) {
    return errorResponse(c, 500, ErrorCode.ServerError, 'Failed to create organization in WorkOS')
  }

  // 2. Add the creator as admin member
  const membershipCreated = await createWorkOSMembership(c.env.WORKOS_API_KEY, workosUserId, org.id, 'admin')
  if (!membershipCreated) {
    return errorResponse(c, 500, ErrorCode.ServerError, 'Organization created but failed to add membership')
  }

  return c.json({
    id: org.id,
    name: org.name,
    workosOrgId: org.id,
  }, 201)
})

// GET /api/orgs — List the authenticated user's organizations
app.get('/api/orgs', async (c) => {
  if (!c.env.WORKOS_API_KEY) {
    return errorResponse(c, 503, ErrorCode.ServerError, 'WorkOS not configured')
  }

  // Resolve WorkOS user ID: standard auth (ses_*/API key) or JWT fallback
  let workosUserId: string | null = null
  const auth = c.get('auth')
  if (auth.authenticated && auth.identityId) {
    const stub = c.get('identityStub')
    if (stub) {
      workosUserId = await resolveWorkOSUserId(stub, auth.identityId)
    }
  }
  if (!workosUserId) {
    const jwt = await extractWorkOSUserFromJWT(c.req.raw, c.env)
    if (jwt?.sub) workosUserId = jwt.sub
  }
  if (!workosUserId) {
    return errorResponse(c, 401, ErrorCode.Unauthorized, 'Authentication required')
  }

  const memberships = await listUserOrgMemberships(c.env.WORKOS_API_KEY, workosUserId)

  // Fetch org details for each membership
  const orgs = await Promise.all(
    memberships.map(async (m) => {
      const orgInfo = await fetchOrgInfo(c.env.WORKOS_API_KEY!, m.organization_id)
      return {
        id: m.organization_id,
        name: orgInfo?.name ?? m.organization_id,
        role: m.role?.slug ?? 'member',
        domains: orgInfo?.domains ?? [],
      }
    }),
  )

  return c.json({ organizations: orgs })
})

// GET /api/orgs/:id/members — List members of an organization
app.get('/api/orgs/:id/members', async (c) => {
  if (!c.env.WORKOS_API_KEY) {
    return errorResponse(c, 503, ErrorCode.ServerError, 'WorkOS not configured')
  }

  // Require auth: standard or JWT
  const auth = c.get('auth')
  const jwt = (!auth.authenticated || !auth.identityId) ? await extractWorkOSUserFromJWT(c.req.raw, c.env) : null
  if (!auth.authenticated && !jwt) {
    return errorResponse(c, 401, ErrorCode.Unauthorized, 'Authentication required')
  }

  const orgId = c.req.param('id')
  const members = await listOrgMembers(c.env.WORKOS_API_KEY, orgId)

  return c.json({
    members: members.map((m) => ({
      id: m.id,
      userId: m.user_id,
      role: m.role?.slug ?? 'member',
      status: m.status,
      createdAt: m.created_at,
    })),
  })
})

// POST /api/orgs/:id/invitations — Send an invitation to join an organization
app.post('/api/orgs/:id/invitations', async (c) => {
  if (!c.env.WORKOS_API_KEY) {
    return errorResponse(c, 503, ErrorCode.ServerError, 'WorkOS not configured')
  }

  // Require auth: standard or JWT
  const auth = c.get('auth')
  const jwt = (!auth.authenticated || !auth.identityId) ? await extractWorkOSUserFromJWT(c.req.raw, c.env) : null
  if (!auth.authenticated && !jwt) {
    return errorResponse(c, 401, ErrorCode.Unauthorized, 'Authentication required')
  }

  const orgId = c.req.param('id')
  const body = (await c.req.json().catch(() => ({}))) as { email?: string; role?: string }

  if (!body.email) {
    return errorResponse(c, 400, ErrorCode.InvalidRequest, 'email is required')
  }

  const sent = await sendOrgInvitation(c.env.WORKOS_API_KEY, body.email, orgId, body.role || 'member')
  if (!sent) {
    return errorResponse(c, 500, ErrorCode.ServerError, 'Failed to send invitation')
  }

  return c.json({ ok: true, email: body.email, organizationId: orgId }, 201)
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

    const isValid = await verifyWorkOSWebhookSignature(rawBody, signature, c.env.WORKOS_WEBHOOK_SECRET)
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

// ── WorkOS Actions ────────────────────────────────────────────────────────
// Synchronous hooks called by WorkOS during authentication/registration.
// These run BEFORE the user is redirected, so any user updates (external_id,
// metadata) will be reflected in the WorkOS JWT template on this same request.

/**
 * Verify WorkOS action request signature (HMAC-SHA256).
 * Header format: WorkOS-Signature: t=<timestamp_ms>,v1=<hex_signature>
 */
async function verifyActionSignature(rawBody: string, sigHeader: string, secret: string, toleranceMs = 300_000): Promise<boolean> {
  const parts = Object.fromEntries(
    sigHeader
      .split(',')
      .map((p) => p.split('='))
      .map(([k, ...v]) => [k, v.join('=')]),
  )
  const timestamp = parts['t']
  const signature = parts['v1']
  if (!timestamp || !signature) return false

  // Replay protection
  if (Math.abs(Date.now() - Number(timestamp)) > toleranceMs) return false

  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  const mac = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${timestamp}.${rawBody}`))
  const expected = Array.from(new Uint8Array(mac))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')

  return expected === signature
}

/**
 * Sign a WorkOS action response (HMAC-SHA256).
 * Returns the full response envelope with signature.
 */
async function signActionResponse(
  type: 'authentication' | 'user_registration',
  verdict: 'Allow' | 'Deny',
  secret: string,
  errorMessage?: string,
): Promise<object> {
  const timestamp = Date.now()
  const payload = { timestamp, verdict, error_message: errorMessage ?? null }
  const payloadJson = JSON.stringify(payload)

  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  const mac = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${timestamp}.${payloadJson}`))
  const signature = Array.from(new Uint8Array(mac))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')

  return { object: `${type}_action_response`, payload, signature }
}

/**
 * Authentication Action — runs after user authenticates, before redirect.
 * Enriches the WorkOS user with GitHub numeric ID as external_id + metadata
 * so it's available in JWT templates on this same authentication request.
 */
app.post('/actions/authentication', async (c) => {
  const secret = c.env.WORKOS_ACTIONS_SECRET
  const apiKey = c.env.WORKOS_API_KEY

  // WorkOS requires a valid action response format — errorResponse() returns
  // standard JSON which WorkOS can't parse, causing "Endpoint response invalid".
  // Always return a signed Allow response; log errors for debugging.
  if (!secret) {
    console.error('[actions/authentication] WORKOS_ACTIONS_SECRET not configured')
    return c.json({ object: 'authentication_action_response', payload: { timestamp: Date.now(), verdict: 'Allow', error_message: null }, signature: '' })
  }

  const rawBody = await c.req.text()
  const sigHeader = c.req.header('workos-signature') || c.req.header('WorkOS-Signature') || ''

  if (!(await verifyActionSignature(rawBody, sigHeader, secret))) {
    console.error('[actions/authentication] Invalid signature — allowing with fail-open')
    return c.json(await signActionResponse('authentication', 'Allow', secret))
  }

  let action: Record<string, unknown> = {}
  try {
    action = JSON.parse(rawBody)
  } catch {
    console.error('[actions/authentication] Failed to parse body')
    return c.json(await signActionResponse('authentication', 'Allow', secret))
  }
  const userId = (action?.user as Record<string, unknown>)?.id || (action?.userData as Record<string, unknown>)?.id

  // Enrich user with GitHub ID + username if available
  if (apiKey && userId) {
    try {
      const workosUser = await fetchWorkOSUser(apiKey, userId as string)
      if (workosUser) {
        const githubId = extractGitHubId(workosUser)
        if (githubId) {
          const githubUsername = await fetchGitHubUsername(githubId)
          await updateWorkOSUser(apiKey, userId as string, {
            external_id: githubId,
            metadata: {
              github_id: githubId,
              ...(githubUsername ? { github_username: githubUsername } : {}),
            },
          })
        }
      }
    } catch (err) {
      console.error('[actions/authentication] Enrichment failed:', err)
    }
  }

  return c.json(await signActionResponse('authentication', 'Allow', secret))
})

/**
 * User Registration Action — runs after registration, before provisioning.
 * Currently allows all registrations. Can be extended to enforce domain
 * policies, block disposable emails, etc.
 */
app.post('/actions/registration', async (c) => {
  const secret = c.env.WORKOS_ACTIONS_SECRET

  if (!secret) {
    console.error('[actions/registration] WORKOS_ACTIONS_SECRET not configured')
    return c.json({ object: 'user_registration_action_response', payload: { timestamp: Date.now(), verdict: 'Allow', error_message: null }, signature: '' })
  }

  const rawBody = await c.req.text()
  const sigHeader = c.req.header('workos-signature') || c.req.header('WorkOS-Signature') || ''

  if (!(await verifyActionSignature(rawBody, sigHeader, secret))) {
    console.error('[actions/registration] Invalid signature — allowing with fail-open')
    return c.json(await signActionResponse('user_registration', 'Allow', secret))
  }

  return c.json(await signActionResponse('user_registration', 'Allow', secret))
})

// ── Fallback: serve @mdxui/auth SPA or 404 ───────────────────────────────

// Authenticated users on the landing page → redirect to dashboard
app.get('/', async (c) => {
  const cookie = c.req.header('cookie')
  if (cookie) {
    const jwt = parseCookieValue(cookie, 'auth')
    if (jwt) {
      try {
        const oauthStub = getStubForIdentity(c.env, 'oauth')
        const manager = new SigningKeyManager((op) => oauthStub.oauthStorageOp(op))
        const jwks = await manager.getJWKS()
        const localJwks = jose.createLocalJWKSet(jwks)
        await jose.jwtVerify(jwt, localJwks, { issuer: 'https://id.org.ai' })
        return c.redirect('/dash/profile', 302)
      } catch {
        // Invalid cookie — fall through to landing page
      }
    }
  }
  // Not authenticated — serve landing page
  if (c.env.ASSETS) {
    return c.env.ASSETS.fetch(c.req.raw)
  }
  return c.text('id.org.ai', 200)
})

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

    // Persist GitHub ID to WorkOS as external_id (if identity has a WorkOS user ID)
    if (env.WORKOS_API_KEY && result.identity) {
      const stored = await stub.oauthStorageOp({ op: 'get', key: `identity:${identityId}` })
      const workosUserId = (stored.value as any)?.workosUserId
      if (workosUserId) {
        updateWorkOSUser(env.WORKOS_API_KEY, workosUserId, {
          external_id: String(push.sender.id),
          metadata: { github_id: String(push.sender.id), github_username: push.sender.login },
        }).catch(() => {}) // Best-effort, don't fail the claim
      }
    }

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
// Null-safe Stub for L0 (Anonymous) Requests
// ============================================================================

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
async function verifyWorkOSWebhookSignature(body: string, signatureHeader: string, secret: string): Promise<boolean> {
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
    const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
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


