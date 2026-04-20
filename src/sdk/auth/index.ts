/**
 * Auth utilities for id.org.ai
 *
 * id.org.ai is the canonical auth origin. oauth.do remains a compatibility
 * surface during the WorkOS custom-domain migration.
 */

export const CANONICAL_AUTH_ORIGIN = 'https://id.org.ai'
export const CANONICAL_API_ORIGIN = CANONICAL_AUTH_ORIGIN
export const CANONICAL_AUTH_HOSTNAME = 'id.org.ai'
export const CANONICAL_AUTHKIT_DOMAIN = CANONICAL_AUTH_HOSTNAME
export const CANONICAL_JWKS_URL = `${CANONICAL_AUTH_ORIGIN}/.well-known/jwks.json`

export const LEGACY_AUTH_ORIGIN = 'https://oauth.do'
export const LEGACY_AUTH_HOSTNAME = 'oauth.do'
export const LEGACY_AUTHKIT_DOMAIN = 'login.oauth.do'
export const LEGACY_JWKS_URL = `${LEGACY_AUTH_ORIGIN}/.well-known/jwks.json`
export const LEGACY_WORKOS_BRIDGE_ISSUER = 'https://auth.apis.do'

export const TOKEN_FILE_NAME = 'token'
export const CANONICAL_TOKEN_DIRNAME = '.id.org.ai'
export const LEGACY_TOKEN_DIRNAME = '.oauth.do'
export const CANONICAL_KEYCHAIN_SERVICE = 'id.org.ai'
export const LEGACY_KEYCHAIN_SERVICE = 'oauth.do'

export const DEFAULT_CALLBACK_PATH = '/api/callback'
export const DEFAULT_CALLBACK_URL = `${CANONICAL_AUTH_ORIGIN}${DEFAULT_CALLBACK_PATH}`

export const ID_ORG_AI_CLI_CLIENT_ID = 'id_org_ai_cli'
export const OAUTH_DO_CLI_CLIENT_ID = 'oauth_do_cli'
export const AUTO_DEV_CLI_CLIENT_ID = 'auto_dev_cli'

export const COMPATIBLE_AUTH_ORIGINS = [CANONICAL_AUTH_ORIGIN, LEGACY_AUTH_ORIGIN] as const
export const COMPATIBLE_KEYCHAIN_SERVICES = [CANONICAL_KEYCHAIN_SERVICE, LEGACY_KEYCHAIN_SERVICE] as const
export const COMPATIBLE_TOKEN_DIRNAMES = [CANONICAL_TOKEN_DIRNAME, LEGACY_TOKEN_DIRNAME] as const
export const COMPATIBLE_AUTH_ISSUERS = [CANONICAL_AUTH_ORIGIN, LEGACY_AUTH_ORIGIN, LEGACY_WORKOS_BRIDGE_ISSUER] as const

export function getAuthEndpoint(path: string, origin: string = CANONICAL_AUTH_ORIGIN): string {
  return new URL(path, origin).toString()
}

export function getDefaultCallbackUrl(origin: string = CANONICAL_AUTH_ORIGIN): string {
  return getAuthEndpoint(DEFAULT_CALLBACK_PATH, origin)
}

export function isCompatibleAuthIssuer(issuer?: string | null): boolean {
  return !!issuer && COMPATIBLE_AUTH_ISSUERS.includes(issuer as (typeof COMPATIBLE_AUTH_ISSUERS)[number])
}

export function buildAuthUrl(options: { redirectUri: string; scope?: string; state?: string }): string {
  const url = new URL(getAuthEndpoint('/oauth/authorize'))
  url.searchParams.set('redirect_uri', options.redirectUri)
  url.searchParams.set('scope', options.scope ?? 'openid profile email')
  url.searchParams.set('response_type', 'code')
  if (options.state) url.searchParams.set('state', options.state)
  return url.toString()
}

// ── RPC Contract Types ─────────────────────────────────────────────────
// Canonical types for the auth service binding RPC contract.
// Consumed by oauth.do/rpc and @headlessly/types.

export interface AuthUser {
  id: string
  email?: string
  name?: string
  image?: string
  organizationId?: string
  org?: string
  roles?: string[]
  permissions?: string[]
  /**
   * Platform-scoped role, orthogonal to tenant `roles[]`.
   * Set to 'superadmin' when the user's org is the platform org (PLATFORM_ORG_ID).
   */
  platformRole?: 'superadmin'
  metadata?: Record<string, unknown>
}

export type VerifyResult = { valid: true; user: AuthUser; cached?: boolean } | { valid: false; error: string }

export type AuthResult = { ok: true; user: AuthUser } | { ok: false; status: number; error: string }
