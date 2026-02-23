/**
 * Auth utilities for id.org.ai
 *
 * Wraps WorkOS AuthKit for human authentication.
 * Custom AuthKit domain: id.org.ai
 */

export function buildAuthUrl(options: {
  redirectUri: string
  scope?: string
  state?: string
}): string {
  const url = new URL('https://id.org.ai/oauth/authorize')
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
  metadata?: Record<string, unknown>
}

export type VerifyResult = { valid: true; user: AuthUser; cached?: boolean } | { valid: false; error: string }

export type AuthResult = { ok: true; user: AuthUser } | { ok: false; status: number; error: string }
