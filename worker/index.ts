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
import { corsMiddleware, originValidationMiddleware } from './middleware/origin'
import * as jose from 'jose'
import { IdentityDO } from '../src/server/do/Identity'
import type { IdentityStub } from '../src/server/do/Identity'
import type { Env, Variables, AuthRPCResult, AuthUser, VerifyResult } from './types'
import { parseCookieValue } from './utils/cookies'
import { authenticateRequest } from './middleware/auth'
import {
  getStubForIdentity,
  getSigningKeyManager,
  identityStubMiddleware,
} from './middleware/tenant'
import { oauthRoutes, getOAuthProvider } from './routes/oauth'
import { claimRoutes } from './routes/claim'
import { LEGACY_AUTH_ORIGIN, LEGACY_JWKS_URL, LEGACY_WORKOS_BRIDGE_ISSUER } from '../src/sdk/auth'
import { validateWorkOSApiKey } from '../src/sdk/workos/apikey'
import { errorResponse, ErrorCode } from '../src/sdk/errors'
import { getCachedUser, cacheUser, invalidateCachedToken, isNegativelyCached, cacheNegativeResult } from './utils/cache'
import { auditRoutes } from './routes/audit'
import { authRoutes } from './routes/auth'
import { apiKeyRoutes } from './routes/api-keys'
import { mcpRoutes } from './routes/mcp'
import { workosRoutes } from './routes/workos'
import { githubRoutes } from './routes/github'

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
      const manager = getSigningKeyManager(this.env)
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
    const manager = getSigningKeyManager(c.env)
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
    const manager = getSigningKeyManager(c.env)
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
  const xIssuer = c.req.header('X-Issuer')
  const issuer = xIssuer ? xIssuer.replace(/\/$/, '') : provider.issuer
  return c.json({
    issuer,
    authorization_endpoint: `${issuer}/oauth/authorize`,
    token_endpoint: `${issuer}/oauth/token`,
    registration_endpoint: `${issuer}/oauth/register`,
    revocation_endpoint: `${issuer}/oauth/revoke`,
    userinfo_endpoint: `${issuer}/oauth/userinfo`,
    introspection_endpoint: `${issuer}/oauth/introspect`,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    device_authorization_endpoint: `${issuer}/oauth/device`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials', 'urn:ietf:params:oauth:grant-type:device_code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256', 'ES256'],
    scopes_supported: ['openid', 'profile', 'email', 'offline_access'],
    token_endpoint_auth_methods_supported: ['none', 'client_secret_basic', 'client_secret_post'],
    code_challenge_methods_supported: ['S256'],
    claims_supported: ['sub', 'name', 'preferred_username', 'picture', 'email', 'email_verified'],
  }, 200, { 'Cache-Control': 'public, max-age=3600' })
})

// ── OAuth Authorization Server Metadata (RFC 8414) ────────────────────────

app.get('/.well-known/oauth-authorization-server', (c) => {
  const provider = getOAuthProvider(c)
  const xIssuer = c.req.header('X-Issuer')
  const issuer = xIssuer ? xIssuer.replace(/\/$/, '') : provider.issuer
  return c.json(
    {
      issuer,
      authorization_endpoint: `${issuer}/oauth/authorize`,
      token_endpoint: `${issuer}/oauth/token`,
      registration_endpoint: `${issuer}/oauth/register`,
      revocation_endpoint: `${issuer}/oauth/revoke`,
      jwks_uri: `${issuer}/.well-known/jwks.json`,
      introspection_endpoint: `${issuer}/oauth/introspect`,
      userinfo_endpoint: `${issuer}/oauth/userinfo`,
      device_authorization_endpoint: `${issuer}/oauth/device`,
      scopes_supported: ['openid', 'profile', 'email', 'offline_access'],
      response_types_supported: ['code'],
      grant_types_supported: [
        'authorization_code',
        'refresh_token',
        'client_credentials',
        'urn:ietf:params:oauth:grant-type:device_code',
      ],
      token_endpoint_auth_methods_supported: ['none', 'client_secret_basic', 'client_secret_post'],
      code_challenge_methods_supported: ['S256'],
    },
    200,
    {
      'Cache-Control': 'public, max-age=3600',
    }
  )
})

// ── OAuth Protected Resource Metadata (RFC 9728) ──────────────────────────────
// Tells MCP clients which authorization server protects this resource.

app.get('/.well-known/oauth-protected-resource', (c) => {
  const provider = getOAuthProvider(c)
  const xIssuer = c.req.header('X-Issuer')
  const issuer = xIssuer ? xIssuer.replace(/\/$/, '') : provider.issuer
  return c.json({
    resource: issuer,
    authorization_servers: [issuer],
    scopes_supported: ['openid', 'profile', 'email'],
    bearer_methods_supported: ['header'],
  }, 200, { 'Cache-Control': 'public, max-age=3600' })
})

// ── JWKS Endpoint (no auth required) ────────────────────────────────────────
// Serves the public signing keys for JWT verification by other workers.
// Other workers verify our JWTs by fetching this endpoint.

app.get('/.well-known/jwks.json', async (c) => {
  const manager = getSigningKeyManager(c.env)
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
app.route('', workosRoutes)
app.route('', githubRoutes)

// ── Fallback: serve @mdxui/auth SPA or 404 ───────────────────────────────

// Authenticated users on the landing page → redirect to dashboard
app.get('/', async (c) => {
  const cookie = c.req.header('cookie')
  if (cookie) {
    const jwt = parseCookieValue(cookie, 'auth')
    if (jwt) {
      try {
        const manager = getSigningKeyManager(c.env)
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
