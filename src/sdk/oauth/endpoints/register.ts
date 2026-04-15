/**
 * Dynamic Client Registration endpoint handler (RFC 7591)
 */

import type { Context } from 'hono'
import type { OAuthStorage } from '../storage'
import type { OAuthClient, OAuthError } from '../types'
import { generateToken, hashClientSecret } from '../pkce'

/**
 * Configuration for Register handler
 */
export interface RegisterHandlerConfig {
  /** Storage backend */
  storage: OAuthStorage
  /** Enable debug logging */
  debug: boolean
  /** Require authentication for registration */
  requireRegistrationAuth: boolean
  /** Admin token for client registration */
  adminToken?: string | undefined
  /** Function to validate redirect URI scheme */
  validateRedirectUriScheme: (uri: string) => string | null
}

/**
 * Create the client registration endpoint handler (POST /register)
 */
export function createRegisterHandler(config: RegisterHandlerConfig) {
  const { storage, debug, requireRegistrationAuth, adminToken, validateRedirectUriScheme } = config

  return async (c: Context): Promise<Response> => {
    // Check if authentication is required
    if (requireRegistrationAuth || adminToken) {
      const xAdminToken = c.req.header('x-admin-token')
      const authHeader = c.req.header('authorization')
      let authenticated = false

      // Check admin token
      if (adminToken && xAdminToken === adminToken) {
        authenticated = true
      }

      // Check Bearer token (must be a valid access token)
      if (!authenticated && authHeader?.startsWith('Bearer ')) {
        const token = authHeader.slice(7)
        // Verify it's a valid token in storage
        const storedToken = await storage.getAccessToken(token)
        if (storedToken && Date.now() <= storedToken.expiresAt) {
          authenticated = true
        }
      }

      if (!authenticated) {
        return c.json({ error: 'unauthorized', error_description: 'Authentication required for client registration' } as OAuthError, 401)
      }
    }

    let body: unknown
    try {
      body = await c.req.json()
    } catch {
      return c.json({ error: 'invalid_client_metadata', error_description: 'Invalid JSON body' } as OAuthError, 400)
    }

    if (typeof body !== 'object' || body === null) {
      return c.json({ error: 'invalid_client_metadata', error_description: 'Request body must be a JSON object' } as OAuthError, 400)
    }

    const parsed = body as Record<string, unknown>

    if (debug) {
      console.log('[OAuth] Client registration:', parsed)
    }

    if (typeof parsed['client_name'] !== 'string' || !parsed['client_name']) {
      return c.json({ error: 'invalid_client_metadata', error_description: 'client_name is required' } as OAuthError, 400)
    }

    if (!Array.isArray(parsed['redirect_uris']) || parsed['redirect_uris'].length === 0 || !parsed['redirect_uris'].every((u: unknown) => typeof u === 'string')) {
      return c.json({ error: 'invalid_client_metadata', error_description: 'redirect_uris is required and must be an array of strings' } as OAuthError, 400)
    }

    // Enforce HTTPS for redirect URIs in production
    for (const uri of parsed['redirect_uris'] as string[]) {
      const schemeErr = validateRedirectUriScheme(uri)
      if (schemeErr) {
        return c.json({ error: 'invalid_client_metadata', error_description: schemeErr } as OAuthError, 400)
      }
    }

    // Generate client credentials
    const clientId = `client_${generateToken(24)}`
    const clientSecret = generateToken(48)
    const clientSecretHash = await hashClientSecret(clientSecret)

    const client: OAuthClient = {
      clientId,
      clientSecretHash,
      clientName: parsed['client_name'] as string,
      redirectUris: parsed['redirect_uris'] as string[],
      grantTypes: (parsed['grant_types'] as OAuthClient['grantTypes']) || ['authorization_code', 'refresh_token'],
      responseTypes: (parsed['response_types'] as OAuthClient['responseTypes']) || ['code'],
      tokenEndpointAuthMethod: (parsed['token_endpoint_auth_method'] as OAuthClient['tokenEndpointAuthMethod']) || 'client_secret_basic',
      ...(typeof parsed['scope'] === 'string' && { scope: parsed['scope'] }),
      createdAt: Date.now(),
    }

    await storage.saveClient(client)

    // Return client credentials (secret is only shown once)
    return c.json(
      {
        client_id: clientId,
        client_secret: clientSecret,
        client_id_issued_at: Math.floor(client.createdAt / 1000),
        client_secret_expires_at: 0, // Never expires
        client_name: client.clientName,
        redirect_uris: client.redirectUris,
        grant_types: client.grantTypes,
        response_types: client.responseTypes,
        token_endpoint_auth_method: client.tokenEndpointAuthMethod,
        scope: client.scope,
      },
      201
    )
  }
}
