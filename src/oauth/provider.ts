/**
 * OAuth 2.1 Provider for id.org.ai
 *
 * Implements:
 *   - Authorization Code + PKCE (mandatory per OAuth 2.1)
 *   - Refresh tokens with rotation
 *   - Client credentials for service-to-service
 *   - Dynamic Client Registration (RFC 7591)
 *   - OIDC Discovery
 *   - Device Flow (RFC 8628) for agents without browsers
 *
 * TODO: Rewrite from scratch with @cloudflare/workers-oauth-provider
 */

export interface OAuthConfig {
  issuer: string
  authorizationEndpoint: string
  tokenEndpoint: string
  userinfoEndpoint: string
  jwksUri?: string
}

export class OAuthProvider {
  constructor(
    private config: OAuthConfig,
  ) {}

  getOpenIDConfiguration(): Response {
    return Response.json({
      issuer: this.config.issuer,
      authorization_endpoint: this.config.authorizationEndpoint,
      token_endpoint: this.config.tokenEndpoint,
      userinfo_endpoint: this.config.userinfoEndpoint,
      jwks_uri: this.config.jwksUri,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials', 'urn:ietf:params:oauth:grant-type:device_code'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['RS256', 'ES256'],
      scopes_supported: ['openid', 'profile', 'email', 'offline_access'],
      token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
      code_challenge_methods_supported: ['S256'],
      claims_supported: ['sub', 'name', 'preferred_username', 'picture', 'email', 'email_verified'],
    })
  }
}
