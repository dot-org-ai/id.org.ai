/**
 * Token Revocation endpoint handler (RFC 7009)
 */

import type { Context } from 'hono'
import type { OAuthStorage } from '../storage'
import type { OAuthError } from '../types'

/**
 * Configuration for Revoke handler
 */
export interface RevokeHandlerConfig {
  /** Storage backend */
  storage: OAuthStorage
  /** Callback after token revocation */
  onTokenRevoked?: ((token: string, tokenTypeHint?: string) => void | Promise<void>) | undefined
}

/**
 * Create the token revocation endpoint handler (POST /revoke)
 */
export function createRevokeHandler(config: RevokeHandlerConfig) {
  const { storage, onTokenRevoked } = config

  return async (c: Context): Promise<Response> => {
    const formData = await c.req.parseBody()
    const token = String(formData['token'] || '')
    const tokenTypeHint = String(formData['token_type_hint'] || '')

    if (!token) {
      return c.json({ error: 'invalid_request', error_description: 'token is required' } as OAuthError, 400)
    }

    // Try to revoke as access token first
    if (tokenTypeHint !== 'refresh_token') {
      await storage.revokeAccessToken(token)
    }

    // Then try as refresh token
    if (tokenTypeHint !== 'access_token') {
      await storage.revokeRefreshToken(token)
    }

    // Call revocation callback if configured (for cache invalidation, etc.)
    if (onTokenRevoked) {
      await onTokenRevoked(token, tokenTypeHint || undefined)
    }

    // RFC 7009 says to return 200 OK even if token was invalid
    return c.json({ success: true })
  }
}
