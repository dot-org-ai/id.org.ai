/**
 * Shared helpers for the OAuth 2.1 server
 *
 * These functions are used across multiple route modules and are
 * extracted here to keep route modules focused on endpoint logic.
 */

import type { Context } from 'hono'
import type { OAuthStorage } from './storage'
import type { OAuthUser, UpstreamOAuthConfig } from './types'
import type { DevModeConfig, TestHelpers } from './dev'
import { SigningKeyManager, signAccessToken } from '../jwt'

/**
 * Compute the refresh token expiresAt timestamp in milliseconds.
 *
 * Centralizes the TTL -> millisecond-epoch calculation so every code path
 * uses the same formula.  Returns `undefined` when refreshTokenTtl is 0
 * (meaning "never expire").
 *
 * @param refreshTokenTtl - TTL in **seconds** (e.g. 2592000 for 30 days)
 * @param now             - Current time in milliseconds (default: Date.now())
 */
export function computeRefreshTokenExpiry(refreshTokenTtl: number, now: number = Date.now()): number | undefined {
  if (refreshTokenTtl <= 0) return undefined
  return now + refreshTokenTtl * 1000
}

/**
 * Shared context available to all route modules.
 *
 * Created once in createOAuth21Server and passed to each route factory.
 */
export interface ServerContext {
  /** Default issuer URL */
  defaultIssuer: string
  /** Storage backend */
  storage: OAuthStorage
  /** Upstream OAuth provider configuration */
  upstream?: UpstreamOAuthConfig | undefined
  /** Development mode configuration */
  devMode?: DevModeConfig | undefined
  /** Supported scopes */
  scopes: string[]
  /** Access token TTL in seconds */
  accessTokenTtl: number
  /** Refresh token TTL in seconds */
  refreshTokenTtl: number
  /** Auth code TTL in seconds */
  authCodeTtl: number
  /** Enable dynamic client registration */
  enableDynamicRegistration: boolean
  /** Callback after user authentication */
  onUserAuthenticated?: ((user: OAuthUser) => void | Promise<void>) | undefined
  /** Callback after token revocation */
  onTokenRevoked?: ((token: string, tokenTypeHint?: string) => void | Promise<void>) | undefined
  /** Enable debug logging */
  debug: boolean
  /** Allowed CORS origins */
  corsOrigins: string[]
  /** Use JWT access tokens */
  useJwtAccessTokens: boolean
  /** Require authentication for registration */
  requireRegistrationAuth: boolean
  /** Admin token for registration */
  adminToken?: string | undefined
  /** Trusted (first-party) client IDs that skip consent */
  trustedClientIds: string[]
  /** Skip consent screen for all clients */
  skipConsent: boolean
  /** Test helpers (only in dev mode) */
  testHelpers?: TestHelpers | undefined
  /** Get effective issuer for a request */
  getEffectiveIssuer: (c: Context) => string
  /** Validate redirect URI scheme */
  validateRedirectUriScheme: (uri: string) => string | null
  /** Validate and filter requested scopes */
  validateScopes: (requestedScope: string | undefined) => string | undefined
  /** Ensure signing key is available */
  ensureSigningKey: () => Promise<{
    kid: string
    alg: 'RS256'
    privateKey: CryptoKey
    publicKey: CryptoKey
    createdAt: number
  }>
  /** Generate a JWT access token */
  generateAccessToken: (user: OAuthUser, clientId: string, scope: string, issuerOverride?: string) => Promise<string>
  /** Get the current signing key manager (may be lazily initialized) */
  getSigningKeyManager: () => SigningKeyManager | undefined
}

/**
 * Create the getEffectiveIssuer helper.
 *
 * Supports dynamic issuers via X-Issuer header for multi-tenant scenarios.
 */
export function createGetEffectiveIssuer(defaultIssuer: string, trustedIssuers: string[] | undefined, debug: boolean): (c: Context) => string {
  return (c: Context): string => {
    const xIssuer = c.req.header('X-Issuer')
    if (xIssuer) {
      // Validate it's a proper URL
      try {
        new URL(xIssuer)
        const normalized = xIssuer.replace(/\/$/, '') // Remove trailing slash
        // If trustedIssuers is configured, only accept values in the list
        if (trustedIssuers) {
          if (!trustedIssuers.includes(normalized)) {
            if (debug) {
              console.warn('[OAuth] X-Issuer not in trustedIssuers list:', normalized)
            }
            return defaultIssuer
          }
        }
        return normalized
      } catch {
        if (debug) {
          console.warn('[OAuth] Invalid X-Issuer header:', xIssuer)
        }
      }
    }
    return defaultIssuer
  }
}

/**
 * Create the validateRedirectUriScheme helper.
 *
 * Check if a redirect URI requires HTTPS (production enforcement).
 */
export function createValidateRedirectUriScheme(devMode?: DevModeConfig): (uri: string) => string | null {
  return (uri: string): string | null => {
    if (devMode?.enabled) return null
    try {
      const parsed = new URL(uri)
      const host = parsed.hostname
      if (parsed.protocol === 'http:' && host !== 'localhost' && host !== '127.0.0.1') {
        return 'redirect_uri must use HTTPS (except for localhost development)'
      }
    } catch {
      // URL parsing errors are handled elsewhere
    }
    return null
  }
}

/**
 * Create the validateScopes helper.
 *
 * Validate and filter requested scopes against the server's configured scopes.
 * Returns only the scopes that are allowed, or undefined if no valid scopes.
 */
export function createValidateScopes(scopes: string[]): (requestedScope: string | undefined) => string | undefined {
  return (requestedScope: string | undefined): string | undefined => {
    if (!requestedScope) return undefined
    const requested = requestedScope.split(/\s+/).filter(Boolean)
    const allowed = requested.filter((s) => scopes.includes(s))
    return allowed.length > 0 ? allowed.join(' ') : undefined
  }
}

/**
 * Create an in-memory storage op for the SigningKeyManager.
 * Used when no external signing key manager is provided and one needs
 * to be lazily created.
 */
function createInMemoryStorageOp(): (op: {
  op: 'get' | 'put' | 'delete' | 'list'
  key?: string
  value?: unknown
  options?: { expirationTtl?: number; prefix?: string; limit?: number }
}) => Promise<Record<string, unknown>> {
  const store = new Map<string, unknown>()
  return async (op) => {
    switch (op.op) {
      case 'get':
        return { value: store.get(op.key!) }
      case 'put':
        store.set(op.key!, op.value)
        return {}
      case 'delete':
        store.delete(op.key!)
        return {}
      case 'list': {
        const entries: Record<string, unknown> = {}
        for (const [k, v] of store) {
          if (!op.options?.prefix || k.startsWith(op.options.prefix)) {
            entries[k] = v
          }
        }
        return entries
      }
      default:
        return {}
    }
  }
}

/**
 * Create the ensureSigningKey helper.
 *
 * Get or create signing key, lazily initializing the signing key manager if needed.
 */
export function createEnsureSigningKey(
  getSigningKeyManager: () => SigningKeyManager | undefined,
  setSigningKeyManager: (skm: SigningKeyManager) => void,
): () => Promise<{
  kid: string
  alg: 'RS256'
  privateKey: CryptoKey
  publicKey: CryptoKey
  createdAt: number
}> {
  return async () => {
    let signingKeyManager = getSigningKeyManager()
    if (!signingKeyManager) {
      // Create an in-memory key manager lazily
      signingKeyManager = new SigningKeyManager(createInMemoryStorageOp())
      setSigningKeyManager(signingKeyManager)
    }
    return signingKeyManager.getCurrentKey()
  }
}

/**
 * Create the generateAccessToken helper.
 *
 * Generate a JWT access token for a user.
 */
export function createGenerateAccessToken(
  defaultIssuer: string,
  accessTokenTtl: number,
  ensureSigningKey: () => Promise<{
    kid: string
    alg: 'RS256'
    privateKey: CryptoKey
    publicKey: CryptoKey
    createdAt: number
  }>,
): (user: OAuthUser, clientId: string, scope: string, issuerOverride?: string) => Promise<string> {
  return async (user: OAuthUser, clientId: string, scope: string, issuerOverride?: string): Promise<string> => {
    const key = await ensureSigningKey()
    return signAccessToken(
      key,
      {
        sub: user.id,
        client_id: clientId,
        scope,
        email: user.email,
        name: user.name,
        // Include RBAC claims from user
        ...(user.organizationId && { org_id: user.organizationId }),
        ...(user.roles && user.roles.length > 0 && { roles: user.roles }),
        ...(user.permissions && user.permissions.length > 0 && { permissions: user.permissions }),
      },
      {
        issuer: issuerOverride || defaultIssuer,
        audience: clientId,
        expiresIn: accessTokenTtl,
      },
    )
  }
}
