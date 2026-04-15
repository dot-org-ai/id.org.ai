/**
 * UserInfo endpoint handler (OpenID Connect)
 *
 * Returns claims about the authenticated user based on granted scopes.
 */

import type { Context } from 'hono'
import type { OAuthStorage } from '../storage'
import type { SigningKeyManager } from '../../jwt'
import { decodeJWT, verifyJWT } from '../jwt-verify'

/**
 * Configuration for UserInfo handler
 */
export interface UserInfoHandlerConfig {
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
}

/**
 * Create the UserInfo endpoint handler (GET /userinfo)
 */
export function createUserInfoHandler(config: UserInfoHandlerConfig) {
  const { storage, defaultIssuer, signingKeyManager, useJwtAccessTokens, getEffectiveIssuer, ensureSigningKey } = config

  return async (c: Context): Promise<Response> => {
    const authHeader = c.req.header('authorization')
    if (!authHeader?.startsWith('Bearer ')) {
      c.header('WWW-Authenticate', 'Bearer')
      return c.json({ error: 'invalid_token', error_description: 'Bearer token required' }, 401)
    }

    const token = authHeader.slice(7)
    let userId: string | undefined
    let grantedScope: string | undefined

    // Try JWT first
    const decoded = decodeJWT(token)
    if (decoded) {
      // Verify JWT signature
      let signatureValid = false
      if (signingKeyManager || useJwtAccessTokens) {
        try {
          const key = await ensureSigningKey()
          const effectiveIssuer = getEffectiveIssuer(c)
          const result = await verifyJWT(token, {
            publicKey: key.publicKey,
            issuer: decoded.payload.iss === effectiveIssuer ? effectiveIssuer : defaultIssuer,
          })
          signatureValid = result.valid
        } catch {
          signatureValid = false
        }
      }

      if (!signatureValid) {
        c.header('WWW-Authenticate', 'Bearer error="invalid_token"')
        return c.json({ error: 'invalid_token', error_description: 'Token verification failed' }, 401)
      }

      const now = Math.floor(Date.now() / 1000)
      if (decoded.payload.exp && decoded.payload.exp < now) {
        c.header('WWW-Authenticate', 'Bearer error="invalid_token"')
        return c.json({ error: 'invalid_token', error_description: 'Token expired' }, 401)
      }

      userId = decoded.payload.sub
      grantedScope = decoded.payload['scope'] as string | undefined
    } else {
      // Opaque token - look up in storage
      const storedToken = await storage.getAccessToken(token)
      if (!storedToken || Date.now() > storedToken.expiresAt) {
        c.header('WWW-Authenticate', 'Bearer error="invalid_token"')
        return c.json({ error: 'invalid_token', error_description: 'Token is invalid or expired' }, 401)
      }
      userId = storedToken.userId
      grantedScope = storedToken.scope
    }

    if (!userId) {
      c.header('WWW-Authenticate', 'Bearer error="invalid_token"')
      return c.json({ error: 'invalid_token', error_description: 'Token has no subject' }, 401)
    }

    const user = await storage.getUser(userId)
    if (!user) {
      c.header('WWW-Authenticate', 'Bearer error="invalid_token"')
      return c.json({ error: 'invalid_token', error_description: 'User not found' }, 401)
    }

    // Build claims based on granted scopes
    const scopeSet = new Set((grantedScope || '').split(/\s+/).filter(Boolean))

    // 'sub' is always returned per OIDC spec
    const claims: Record<string, unknown> = { sub: user.id }

    // 'profile' scope: name, picture, etc.
    if (scopeSet.has('profile')) {
      if (user.name) claims['name'] = user.name
      const picture = user.metadata?.['picture']
      if (picture) claims['picture'] = picture
    }

    // 'email' scope: email, email_verified
    if (scopeSet.has('email')) {
      if (user.email) {
        claims['email'] = user.email
        claims['email_verified'] = true // Upstream provider already verified
      }
    }

    return c.json(claims)
  }
}
