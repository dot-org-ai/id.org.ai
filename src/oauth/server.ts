/**
 * OAuth 2.1 Server Implementation
 *
 * Creates a Hono app that implements OAuth 2.1 authorization server endpoints:
 * - /.well-known/oauth-authorization-server (RFC 8414)
 * - /.well-known/oauth-protected-resource (draft-ietf-oauth-resource-metadata)
 * - /.well-known/jwks.json (JWKS endpoint)
 * - /authorize (authorization endpoint)
 * - /callback (upstream OAuth callback)
 * - /token (token endpoint)
 * - /introspect (token introspection - RFC 7662)
 * - /register (dynamic client registration - RFC 7591)
 * - /userinfo (OpenID Connect UserInfo)
 * - /revoke (token revocation - RFC 7009)
 * - /device_authorization (RFC 8628 Device Authorization)
 * - /device (Device verification page)
 *
 * This server acts as a federated OAuth 2.1 server:
 * - It is an OAuth SERVER to downstream clients (Claude, ChatGPT, etc.)
 * - It is an OAuth CLIENT to upstream providers (WorkOS, Auth0, etc.)
 */

import { Hono } from 'hono'
import { cors } from 'hono/cors'
import type { OAuthStorage } from './storage'
import type { OAuthUser, UpstreamOAuthConfig } from './types'
import type { DevModeConfig, DevUser, TestHelpers } from './dev'
import { createTestHelpers } from './dev'
import type { SigningKeyManager } from '../jwt'

// Import helper factories
import {
  createGetEffectiveIssuer,
  createValidateRedirectUriScheme,
  createValidateScopes,
  createEnsureSigningKey,
  createGenerateAccessToken,
  type ServerContext,
} from './helpers'

// Import route modules
import {
  createDiscoveryRoutes,
  createAuthorizeRoutes,
  createTokenRoutes,
  createClientRoutes,
  createDeviceRoutes,
  createIntrospectRoutes,
} from './routes/index'

/**
 * Configuration for the OAuth 2.1 server
 */
export interface OAuth21ServerConfig {
  /** Server issuer URL (e.g., https://mcp.do) */
  issuer: string
  /** Storage backend for users, clients, tokens */
  storage: OAuthStorage
  /** Upstream OAuth provider configuration (optional if devMode enabled) */
  upstream?: UpstreamOAuthConfig
  /** Development mode configuration (no upstream provider needed) */
  devMode?: DevModeConfig
  /** Supported scopes */
  scopes?: string[]
  /** Access token lifetime in seconds (default: 3600) */
  accessTokenTtl?: number
  /** Refresh token lifetime in seconds (default: 2592000 = 30 days) */
  refreshTokenTtl?: number
  /** Authorization code lifetime in seconds (default: 600 = 10 minutes) */
  authCodeTtl?: number
  /** Enable dynamic client registration */
  enableDynamicRegistration?: boolean
  /** Callback after successful user authentication */
  onUserAuthenticated?: (user: OAuthUser) => void | Promise<void>
  /**
   * Callback after token revocation (RFC 7009)
   * Use this to invalidate caches (e.g., auth worker cache) when tokens are revoked.
   * The callback receives the revoked token value.
   */
  onTokenRevoked?: (token: string, tokenTypeHint?: string) => void | Promise<void>
  /** Enable debug logging */
  debug?: boolean
  /** Allowed CORS origins (default: issuer origin only in production, '*' in dev mode) */
  allowedOrigins?: string[]
  /**
   * Signing key manager for JWT access tokens (optional)
   * If provided, access tokens will be signed JWTs instead of opaque tokens.
   * This enables the JWKS and introspection endpoints.
   */
  signingKeyManager?: SigningKeyManager
  /**
   * Use JWT access tokens instead of opaque tokens (default: false)
   * Requires signingKeyManager to be set, or will auto-create one in memory.
   */
  useJwtAccessTokens?: boolean
  /**
   * Trusted issuers for X-Issuer header validation (optional).
   * If set, only X-Issuer values in this list will be accepted.
   * If not set, any valid URL is accepted (backwards compatible).
   */
  trustedIssuers?: string[]
  /**
   * Require authentication for dynamic client registration (optional)
   * If true, registration endpoint requires either an admin token or valid Bearer token
   */
  requireRegistrationAuth?: boolean
  /**
   * Admin token for client registration (optional)
   * If set, clients can provide this token via x-admin-token header to register
   */
  adminToken?: string
  /**
   * Trusted (first-party) client IDs that skip the consent screen.
   * These are clients you own and control (e.g., your own SPA, CLI).
   * Third-party clients (Claude, ChatGPT, etc.) will always see a consent screen.
   * The special value 'first-party' (used by /login) is always trusted.
   */
  trustedClientIds?: string[]
  /**
   * Skip consent screen entirely for all clients (default: false).
   * Use this only in development or when consent is handled externally.
   */
  skipConsent?: boolean
}

/**
 * Extended Hono app with test helpers and signing key manager
 */
export interface OAuth21Server extends Hono {
  /** Test helpers for E2E testing (only available in devMode) */
  testHelpers?: TestHelpers
  /** Signing key manager (available if useJwtAccessTokens is enabled) */
  signingKeyManager?: SigningKeyManager
}

/**
 * Create an OAuth 2.1 server as a Hono app
 *
 * @example
 * ```typescript
 * import { createOAuth21Server, MemoryOAuthStorage } from 'id.org.ai/oauth'
 *
 * const oauthServer = createOAuth21Server({
 *   issuer: 'https://mcp.do',
 *   storage: new MemoryOAuthStorage(),
 *   upstream: {
 *     provider: 'workos',
 *     apiKey: env.WORKOS_API_KEY,
 *     clientId: env.WORKOS_CLIENT_ID,
 *   },
 * })
 *
 * // Mount on your main app
 * app.route('/', oauthServer)
 * ```
 *
 * @example Development mode (no upstream provider)
 * ```typescript
 * const oauthServer = createOAuth21Server({
 *   issuer: 'https://test.mcp.do',
 *   storage: new MemoryOAuthStorage(),
 *   devMode: {
 *     enabled: true,
 *     users: [
 *       { id: 'test-user', email: 'test@example.com', password: 'test123' }
 *     ],
 *     allowAnyCredentials: true,
 *   },
 * })
 *
 * // Access test helpers for Playwright
 * const { accessToken } = await oauthServer.testHelpers.getAccessToken('user-id', 'client-id')
 * ```
 */
export function createOAuth21Server(config: OAuth21ServerConfig): OAuth21Server {
  const {
    issuer: defaultIssuer,
    storage,
    upstream,
    devMode,
    scopes = ['openid', 'profile', 'email', 'offline_access'],
    accessTokenTtl = 3600, // 1 hour
    refreshTokenTtl = 2592000,
    authCodeTtl = 600,
    enableDynamicRegistration = true,
    onUserAuthenticated,
    onTokenRevoked,
    debug = false,
    allowedOrigins,
    signingKeyManager: providedSigningKeyManager,
    useJwtAccessTokens = false,
    trustedIssuers,
    requireRegistrationAuth = false,
    adminToken,
    trustedClientIds = [],
    skipConsent = false,
  } = config

  // Validate configuration
  if (!devMode?.enabled && !upstream) {
    throw new Error('Either upstream configuration or devMode must be provided')
  }

  // Security warning: devMode should never be used in production
  const nodeEnv = (globalThis as { process?: { env?: { NODE_ENV?: string } } }).process?.env?.NODE_ENV
  if (devMode?.enabled && nodeEnv === 'production') {
    console.warn(
      '[OAuth] WARNING: devMode is enabled in a production environment!\n' +
        'This bypasses upstream OAuth security and allows simple password authentication.\n' +
        'This is a critical security risk. Set devMode.enabled = false for production.',
    )
  }

  const app = new Hono() as OAuth21Server

  // ═══════════════════════════════════════════════════════════════════════════
  // Signing Key Manager (mutable — lazily initialized by ensureSigningKey)
  // ═══════════════════════════════════════════════════════════════════════════

  let signingKeyManager = providedSigningKeyManager

  const getSigningKeyManager = (): SigningKeyManager | undefined => signingKeyManager
  const setSigningKeyManager = (skm: SigningKeyManager) => {
    signingKeyManager = skm
    app.signingKeyManager = skm
  }

  // Attach signing key manager if provided
  if (providedSigningKeyManager) {
    app.signingKeyManager = providedSigningKeyManager
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Shared Helpers
  // ═══════════════════════════════════════════════════════════════════════════

  const getEffectiveIssuer = createGetEffectiveIssuer(defaultIssuer, trustedIssuers, debug)
  const validateRedirectUriScheme = createValidateRedirectUriScheme(devMode)
  const validateScopes = createValidateScopes(scopes)
  const ensureSigningKey = createEnsureSigningKey(getSigningKeyManager, setSigningKeyManager)
  const generateAccessToken = createGenerateAccessToken(defaultIssuer, accessTokenTtl, ensureSigningKey)

  // ═══════════════════════════════════════════════════════════════════════════
  // Dev Mode Initialization
  // ═══════════════════════════════════════════════════════════════════════════

  const devUsers = new Map<string, DevUser>()

  if (devMode?.enabled && devMode.users) {
    for (const user of devMode.users) {
      devUsers.set(user.email.toLowerCase(), user)
    }
  }

  if (devMode?.enabled) {
    app.testHelpers = createTestHelpers(storage, devUsers, {
      accessTokenTtl,
      refreshTokenTtl,
      authCodeTtl,
      ...(devMode.allowAnyCredentials !== undefined && { allowAnyCredentials: devMode.allowAnyCredentials }),
    })
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // CORS Middleware
  // ═══════════════════════════════════════════════════════════════════════════

  const corsOrigins = allowedOrigins ?? (devMode?.enabled ? ['*'] : [new URL(defaultIssuer).origin])
  app.use(
    '*',
    cors({
      origin: (origin) => {
        // If '*' is in the list, allow all origins
        if (corsOrigins.includes('*')) {
          return origin || '*'
        }
        // Otherwise, check if the origin is in the allowed list
        if (origin && corsOrigins.includes(origin)) {
          return origin
        }
        // Return null to deny the request
        return null
      },
      allowMethods: ['GET', 'POST', 'OPTIONS'],
      allowHeaders: ['Content-Type', 'Authorization'],
      exposeHeaders: ['WWW-Authenticate'],
    }),
  )

  // ═══════════════════════════════════════════════════════════════════════════
  // Build ServerContext (shared across all route modules)
  // ═══════════════════════════════════════════════════════════════════════════

  const ctx: ServerContext = {
    defaultIssuer,
    storage,
    upstream,
    devMode,
    scopes,
    accessTokenTtl,
    refreshTokenTtl,
    authCodeTtl,
    enableDynamicRegistration,
    onUserAuthenticated,
    onTokenRevoked,
    debug,
    corsOrigins,
    useJwtAccessTokens,
    requireRegistrationAuth,
    adminToken,
    trustedClientIds,
    skipConsent,
    testHelpers: app.testHelpers,
    getEffectiveIssuer,
    validateRedirectUriScheme,
    validateScopes,
    ensureSigningKey,
    generateAccessToken,
    getSigningKeyManager,
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Mount Route Modules
  // ═══════════════════════════════════════════════════════════════════════════

  app.route('/', createDiscoveryRoutes(ctx))
  app.route('/', createAuthorizeRoutes(ctx))
  app.route('/', createTokenRoutes(ctx))
  app.route('/', createClientRoutes(ctx))
  app.route('/', createIntrospectRoutes(ctx))
  app.route('/', createDeviceRoutes(ctx))

  return app
}
