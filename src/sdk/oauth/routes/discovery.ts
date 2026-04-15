/**
 * Discovery / Well-Known endpoints
 *
 * - GET /.well-known/oauth-authorization-server (RFC 8414)
 * - GET /.well-known/oauth-protected-resource (draft-ietf-oauth-resource-metadata)
 * - GET /.well-known/jwks.json (JWKS endpoint)
 */

import { Hono } from 'hono'
import type { OAuthResourceMetadata } from '../types'
import type { ServerContext } from '../helpers'

/**
 * Create the discovery routes sub-app
 */
export function createDiscoveryRoutes(ctx: ServerContext): Hono {
  const app = new Hono()

  /**
   * OAuth 2.1 Authorization Server Metadata (RFC 8414)
   */
  app.get('/.well-known/oauth-authorization-server', (c) => {
    const issuer = ctx.getEffectiveIssuer(c)
    const metadata = {
      issuer,
      authorization_endpoint: `${issuer}/authorize`,
      token_endpoint: `${issuer}/token`,
      ...(ctx.enableDynamicRegistration && { registration_endpoint: `${issuer}/register` }),
      revocation_endpoint: `${issuer}/revoke`,
      // JWKS and introspection endpoints (always advertised, but JWKS only works if signing keys available)
      jwks_uri: `${issuer}/.well-known/jwks.json`,
      introspection_endpoint: `${issuer}/introspect`,
      userinfo_endpoint: `${issuer}/userinfo`,
      scopes_supported: ctx.scopes,
      response_types_supported: ['code'],
      device_authorization_endpoint: `${issuer}/device_authorization`,
      grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials', 'urn:ietf:params:oauth:grant-type:device_code'],
      token_endpoint_auth_methods_supported: ['none', 'client_secret_basic', 'client_secret_post'],
      code_challenge_methods_supported: ['S256'],
    }

    return c.json(metadata)
  })

  /**
   * OAuth 2.1 Protected Resource Metadata
   */
  app.get('/.well-known/oauth-protected-resource', (c) => {
    const issuer = ctx.getEffectiveIssuer(c)
    const metadata: OAuthResourceMetadata = {
      resource: issuer,
      authorization_servers: [issuer],
      scopes_supported: ctx.scopes,
      bearer_methods_supported: ['header'],
    }

    return c.json(metadata)
  })

  /**
   * JWKS endpoint - exposes public signing keys
   */
  app.get('/.well-known/jwks.json', async (c) => {
    try {
      const signingKeyManager = ctx.getSigningKeyManager()
      if (!signingKeyManager && !ctx.useJwtAccessTokens) {
        // No signing keys configured - return empty JWKS
        return c.json({ keys: [] })
      }

      // Ensure signing key manager is initialized
      await ctx.ensureSigningKey()
      // Export ALL keys (current + rotated) so tokens signed with older keys can still be verified
      const currentManager = ctx.getSigningKeyManager()
      const jwks = await currentManager!.getJWKS()
      return c.json(jwks)
    } catch (err) {
      if (ctx.debug) {
        console.error('[OAuth] JWKS error:', err)
      }
      return c.json({ keys: [] })
    }
  })

  return app
}
