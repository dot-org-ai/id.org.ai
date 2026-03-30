// src/services/oauth/types.ts

/**
 * OAuthService — thin facade interface over OAuthProvider.
 * Methods return Response objects (matching OAuthProvider's API).
 * Typed Result<T, E> returns are deferred to the internal decomposition phase.
 */

export interface OAuthConfig {
  issuer: string
  authorizationEndpoint: string
  tokenEndpoint: string
  userinfoEndpoint: string
  registrationEndpoint: string
  deviceAuthorizationEndpoint: string
  revocationEndpoint: string
  introspectionEndpoint: string
  jwksUri: string
}

export interface OAuthService {
  // OAuth 2.1 Flow Handlers
  handleRegister(request: Request): Promise<Response>
  handleAuthorize(request: Request, identityId?: string | null): Promise<Response>
  handleAuthorizeConsent(request: Request, identityId: string): Promise<Response>
  handleToken(request: Request): Promise<Response>
  handleDeviceAuthorization(request: Request): Promise<Response>
  handleDeviceVerification(request: Request, identityId?: string | null): Promise<Response>
  handleUserinfo(request: Request): Promise<Response>
  handleIntrospect(request: Request): Promise<Response>
  handleRevoke(request: Request): Promise<Response>

  // Discovery
  getOpenIDConfiguration(): Record<string, unknown>

  // Client seeding (merges ensureOAuthDoClient + ensureCliClient + ensureWebClients)
  ensureDefaultClients(): Promise<void>
}
