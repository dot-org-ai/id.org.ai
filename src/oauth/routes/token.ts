/**
 * Token endpoint
 *
 * - POST /token — Token exchange (authorization_code, refresh_token, client_credentials, device_code)
 */

import { Hono } from 'hono'
import type { OAuthError } from '../types'
import type { ServerContext } from '../helpers'
import {
  handleAuthorizationCodeGrant,
  handleRefreshTokenGrant,
  handleClientCredentialsGrant,
  handleDeviceCodeGrant,
  type JWTSigningOptions,
} from '../endpoints/index'

/**
 * Create the token routes sub-app
 */
export function createTokenRoutes(ctx: ServerContext): Hono {
  const app = new Hono()

  /**
   * Token endpoint - exchanges authorization code for tokens
   */
  app.post('/token', async (c) => {
    const contentType = c.req.header('content-type')
    let params: Record<string, string>

    if (contentType?.includes('application/json')) {
      try {
        const raw: unknown = await c.req.json()
        if (typeof raw !== 'object' || raw === null) {
          return c.json({ error: 'invalid_request', error_description: 'Request body must be a JSON object' } as OAuthError, 400)
        }
        // Coerce all values to strings for consistent handling
        params = Object.fromEntries(Object.entries(raw as Record<string, unknown>).map(([k, v]) => [k, v == null ? '' : String(v)]))
      } catch {
        return c.json({ error: 'invalid_request', error_description: 'Invalid JSON body' } as OAuthError, 400)
      }
    } else {
      const formData = await c.req.parseBody()
      params = Object.fromEntries(Object.entries(formData).map(([k, v]) => [k, String(v)]))
    }

    const grantType = params['grant_type']

    if (ctx.debug) {
      console.log('[OAuth] Token request:', { grantType, clientId: params['client_id'] })
    }

    // JWT signing options
    const jwtSigningOptions: JWTSigningOptions | undefined = ctx.useJwtAccessTokens
      ? {
          issuer: ctx.defaultIssuer,
          getSigningKey: ctx.ensureSigningKey,
        }
      : undefined

    if (grantType === 'authorization_code') {
      return handleAuthorizationCodeGrant(c, params, ctx.storage, ctx.accessTokenTtl, ctx.refreshTokenTtl, ctx.debug, jwtSigningOptions)
    } else if (grantType === 'refresh_token') {
      return handleRefreshTokenGrant(c, params, ctx.storage, ctx.accessTokenTtl, ctx.refreshTokenTtl, ctx.debug, jwtSigningOptions)
    } else if (grantType === 'client_credentials') {
      return handleClientCredentialsGrant(c, params, ctx.storage, ctx.accessTokenTtl, ctx.debug, jwtSigningOptions)
    } else if (grantType === 'urn:ietf:params:oauth:grant-type:device_code') {
      return handleDeviceCodeGrant(c, params, ctx.storage, ctx.accessTokenTtl, ctx.refreshTokenTtl, ctx.debug, jwtSigningOptions)
    } else if (grantType === 'device_code') {
      // Also accept short form for convenience
      return handleDeviceCodeGrant(c, params, ctx.storage, ctx.accessTokenTtl, ctx.refreshTokenTtl, ctx.debug, jwtSigningOptions)
    } else {
      return c.json({ error: 'unsupported_grant_type', error_description: 'grant_type not supported' } as OAuthError, 400)
    }
  })

  return app
}
