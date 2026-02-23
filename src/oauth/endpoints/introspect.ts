/**
 * Token Introspection endpoint handler (RFC 7662)
 *
 * Allows resource servers to validate tokens
 */

import type { Context } from 'hono'
import type { OAuthStorage } from '../storage'
import type { SigningKeyManager } from '../../jwt'
import { decodeJWT } from '../jwt-verify'
import { verifyJWTWithKeyManager } from '../../jwt'

/**
 * Configuration for Introspect handler
 */
export interface IntrospectHandlerConfig {
  /** Default issuer URL */
  defaultIssuer: string
  /** Storage backend */
  storage: OAuthStorage
  /** Signing key manager (optional) */
  signingKeyManager?: SigningKeyManager | undefined
  /** Use JWT access tokens */
  useJwtAccessTokens: boolean
  /** Enable debug logging */
  debug: boolean
  /** Function to get effective issuer from request */
  getEffectiveIssuer: (c: Context) => string
  /** Function to ensure signing key is available */
  ensureSigningKey: () => Promise<{
    kid: string
    alg: 'RS256'
    privateKey: CryptoKey
    publicKey: CryptoKey
    createdAt: number
  }>
  /** Get the current signing key manager (may be lazily initialized) */
  getSigningKeyManager: () => SigningKeyManager | undefined
}

/**
 * Create the token introspection endpoint handler (POST /introspect)
 */
export function createIntrospectHandler(config: IntrospectHandlerConfig) {
  const { storage, defaultIssuer, useJwtAccessTokens, getEffectiveIssuer, ensureSigningKey, getSigningKeyManager } = config

  return async (c: Context): Promise<Response> => {
    const contentType = c.req.header('content-type')
    let token: string | undefined

    if (contentType?.includes('application/json')) {
      try {
        const body: unknown = await c.req.json()
        if (typeof body === 'object' && body !== null && typeof (body as Record<string, unknown>)['token'] === 'string') {
          token = (body as { token: string }).token
        }
      } catch {
        return c.json({ active: false })
      }
    } else {
      const formData = await c.req.parseBody()
      token = String(formData['token'] || '')
    }

    if (!token) {
      return c.json({ active: false })
    }

    // Try to decode as JWT first
    const decoded = decodeJWT(token)
    if (decoded) {
      // It's a JWT - verify signature and claims using verifyJWTWithKeyManager
      const effectiveIssuer = getEffectiveIssuer(c)
      const signingKeyManager = getSigningKeyManager()

      if (!signingKeyManager && !useJwtAccessTokens) {
        return c.json({ active: false })
      }

      // Ensure signing key manager is initialized
      await ensureSigningKey()
      const currentSigningKeyManager = getSigningKeyManager()
      if (!currentSigningKeyManager) {
        return c.json({ active: false })
      }

      // Verify signature and exp using the key manager (no issuer - we check manually for multi-issuer support)
      const payload = await verifyJWTWithKeyManager(token, currentSigningKeyManager)
      if (!payload) {
        return c.json({ active: false })
      }

      // Check issuer - accept tokens from any issuer we could have issued
      const iss = payload['iss']
      if (iss && iss !== effectiveIssuer && iss !== defaultIssuer) {
        return c.json({ active: false })
      }

      return c.json({
        active: true,
        sub: payload.sub,
        client_id: payload.client_id,
        scope: payload.scope,
        exp: payload['exp'],
        iat: payload['iat'],
        iss: payload['iss'],
        token_type: 'Bearer',
      })
    }

    // Not a JWT - check opaque token storage
    const storedToken = await storage.getAccessToken(token)
    if (!storedToken) {
      return c.json({ active: false })
    }

    // Check expiration
    if (Date.now() > storedToken.expiresAt) {
      return c.json({ active: false })
    }

    return c.json({
      active: true,
      sub: storedToken.userId,
      client_id: storedToken.clientId,
      scope: storedToken.scope,
      exp: Math.floor(storedToken.expiresAt / 1000),
      iat: Math.floor(storedToken.issuedAt / 1000),
      token_type: storedToken.tokenType,
    })
  }
}
