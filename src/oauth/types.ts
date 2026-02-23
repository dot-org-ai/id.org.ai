/**
 * Core OAuth 2.1 Types
 *
 * Canonical type definitions for OAuth 2.1 server implementation.
 * These types define the storage interface and data structures
 * for the OAuth 2.1 authorization server.
 *
 * Zero external dependencies — pure data structures.
 */

/**
 * OAuth 2.1 User - represents an authenticated user
 */
export interface OAuthUser {
  /** Unique user identifier */
  id: string
  /** User's email address */
  email?: string
  /** User's display name */
  name?: string
  /** Organization/tenant the user belongs to */
  organizationId?: string
  /** Upstream auth provider (e.g., 'workos', 'google', 'github') */
  provider?: string
  /** User's ID in the upstream provider */
  providerId?: string
  /** User roles for RBAC */
  roles?: string[]
  /** User permissions for fine-grained access */
  permissions?: string[]
  /** Additional user metadata */
  metadata?: Record<string, unknown>
  /** When the user was created */
  createdAt: number
  /** When the user was last updated */
  updatedAt: number
  /** When the user last logged in */
  lastLoginAt?: number
}

/**
 * OAuth 2.1 Organization - represents a tenant/organization
 */
export interface OAuthOrganization {
  /** Unique organization identifier */
  id: string
  /** Organization name */
  name: string
  /** Organization slug (URL-safe identifier) */
  slug?: string
  /** Verified email domains for the organization */
  domains?: string[]
  /** Organization metadata */
  metadata?: Record<string, unknown>
  /** When the organization was created */
  createdAt: number
  /** When the organization was last updated */
  updatedAt: number
}

/**
 * OAuth 2.1 Client - represents a registered OAuth client (e.g., Claude, ChatGPT)
 */
export interface OAuthClient {
  /** Unique client identifier */
  clientId: string
  /** Client secret (hashed) - optional for public clients */
  clientSecretHash?: string
  /** Client name for display */
  clientName: string
  /** Allowed redirect URIs */
  redirectUris: string[]
  /** Allowed grant types */
  grantTypes: ('authorization_code' | 'refresh_token' | 'client_credentials')[]
  /** Allowed response types */
  responseTypes: ('code' | 'token')[]
  /** Token endpoint auth method */
  tokenEndpointAuthMethod: 'none' | 'client_secret_basic' | 'client_secret_post'
  /** Allowed scopes */
  scope?: string
  /** Client metadata (logo, contacts, etc.) */
  metadata?: Record<string, unknown>
  /** When the client was registered */
  createdAt: number
  /** When the client registration expires (0 = never) */
  expiresAt?: number
}

/**
 * OAuth 2.1 Authorization Code - short-lived code exchanged for tokens
 */
export interface OAuthAuthorizationCode {
  /** The authorization code */
  code: string
  /** Client that requested the code */
  clientId: string
  /** User who authorized the request */
  userId: string
  /** Redirect URI used in the authorization request */
  redirectUri: string
  /** Granted scopes */
  scope?: string
  /** PKCE code challenge */
  codeChallenge?: string
  /** PKCE code challenge method (always S256 for OAuth 2.1) */
  codeChallengeMethod?: 'S256'
  /** When the code was issued */
  issuedAt: number
  /** When the code expires (typically 10 minutes) */
  expiresAt: number
  /** Client's state parameter for CSRF protection (passed back to client) */
  state?: string
  /** Server's upstream state for validating upstream provider callback */
  upstreamState?: string
  /** Effective issuer for multi-tenant scenarios (stored from X-Issuer header) */
  effectiveIssuer?: string
  /** Temporary storage for access token JWT during platform exchange flow */
  exchangeAccessToken?: string
  /** Temporary storage for refresh token during platform exchange flow */
  exchangeRefreshToken?: string
}

/**
 * OAuth 2.1 Access Token metadata
 */
export interface OAuthAccessToken {
  /** The access token (or token identifier) */
  token: string
  /** Token type (always 'Bearer' for OAuth 2.1) */
  tokenType: 'Bearer'
  /** Client the token was issued to */
  clientId: string
  /** User the token represents */
  userId: string
  /** Granted scopes */
  scope?: string
  /** When the token was issued */
  issuedAt: number
  /** When the token expires */
  expiresAt: number
}

/**
 * OAuth 2.1 Refresh Token metadata
 */
export interface OAuthRefreshToken {
  /** The refresh token */
  token: string
  /** Client the token was issued to */
  clientId: string
  /** User the token represents */
  userId: string
  /** Granted scopes */
  scope?: string
  /** When the token was issued */
  issuedAt: number
  /** When the token expires (0 = never) */
  expiresAt?: number
  /** Whether the token has been revoked */
  revoked?: boolean
}

/**
 * OAuth 2.1 Grant - represents a user's authorization grant to a client
 */
export interface OAuthGrant {
  /** Unique grant identifier */
  id: string
  /** User who granted authorization */
  userId: string
  /** Client that received authorization */
  clientId: string
  /** Granted scopes */
  scope?: string
  /** When the grant was created */
  createdAt: number
  /** When the grant was last used */
  lastUsedAt?: number
  /** Whether the grant has been revoked */
  revoked?: boolean
}

/**
 * OAuth 2.1 Authorization Server Metadata
 * As defined in RFC 8414
 */
export interface OAuthServerMetadata {
  /** Authorization server's issuer identifier (URL) */
  issuer: string
  /** URL of the authorization endpoint */
  authorization_endpoint: string
  /** URL of the token endpoint */
  token_endpoint: string
  /** URL of the dynamic client registration endpoint */
  registration_endpoint?: string
  /** URL of the JWKS endpoint */
  jwks_uri?: string
  /** Supported scopes */
  scopes_supported?: string[]
  /** Supported response types */
  response_types_supported: string[]
  /** Supported grant types */
  grant_types_supported: string[]
  /** Supported token endpoint auth methods */
  token_endpoint_auth_methods_supported: string[]
  /** Supported PKCE code challenge methods */
  code_challenge_methods_supported: string[]
  /** URL of the token revocation endpoint */
  revocation_endpoint?: string
  /** URL of the token introspection endpoint */
  introspection_endpoint?: string
  /** URL of the userinfo endpoint */
  userinfo_endpoint?: string
}

/**
 * OAuth 2.1 Protected Resource Metadata
 * As defined in draft-ietf-oauth-resource-metadata
 */
export interface OAuthResourceMetadata {
  /** Resource server identifier (URL) */
  resource: string
  /** Authorization servers that can issue tokens for this resource */
  authorization_servers?: string[]
  /** Scopes required to access this resource */
  scopes_supported?: string[]
  /** Bearer token methods supported */
  bearer_methods_supported?: ('header' | 'body' | 'query')[]
  /** Resource documentation URL */
  resource_documentation?: string
}

/**
 * Token response from the token endpoint
 */
export interface TokenResponse {
  /** The access token */
  access_token: string
  /** Token type (always 'Bearer') */
  token_type: 'Bearer'
  /** Token lifetime in seconds */
  expires_in: number
  /** Refresh token (if granted) */
  refresh_token?: string
  /** Granted scopes (if different from requested) */
  scope?: string
}

/**
 * Error response from OAuth endpoints
 */
export interface OAuthError {
  /** Error code */
  error: string
  /** Human-readable error description */
  error_description?: string
  /** URI for more information */
  error_uri?: string
}

/**
 * Base configuration shared by all upstream OAuth providers
 */
interface UpstreamOAuthConfigBase {
  /** API key or client secret */
  apiKey: string
  /** Client ID */
  clientId: string
}

/**
 * Configuration for known OAuth providers (WorkOS, Auth0, Okta)
 * These providers have well-known endpoints, so no custom endpoints needed
 */
interface KnownProviderConfig extends UpstreamOAuthConfigBase {
  /** Provider type */
  provider: 'workos' | 'auth0' | 'okta'
  /** Authorization endpoint (optional override) */
  authorizationEndpoint?: string
  /** Token endpoint (optional override) */
  tokenEndpoint?: string
  /** JWKS URI (optional override) */
  jwksUri?: string
}

/**
 * Configuration for custom OAuth providers
 * Custom providers require explicit endpoint configuration
 */
interface CustomProviderConfig extends UpstreamOAuthConfigBase {
  /** Provider type */
  provider: 'custom'
  /** Authorization endpoint (required for custom providers) */
  authorizationEndpoint: string
  /** Token endpoint (required for custom providers) */
  tokenEndpoint: string
  /** JWKS URI (optional for custom providers) */
  jwksUri?: string
}

/**
 * Upstream OAuth provider configuration (e.g., WorkOS)
 * Discriminated union based on provider type
 */
export type UpstreamOAuthConfig = KnownProviderConfig | CustomProviderConfig

/**
 * OAuth 2.0 Device Authorization Grant (RFC 8628)
 * Device code issued to clients for input-constrained devices
 */
export interface OAuthDeviceCode {
  /** The device verification code (long, cryptographically secure) */
  deviceCode: string
  /** The user code (short, human-readable, e.g., "WDJB-MJHT") */
  userCode: string
  /** Client that requested the device code */
  clientId: string
  /** Requested scopes */
  scope?: string
  /** When the device code was issued */
  issuedAt: number
  /** When the device code expires */
  expiresAt: number
  /** Polling interval in seconds */
  interval: number
  /** User who authorized the request (set when user completes authorization) */
  userId?: string
  /** Whether the user has authorized this device */
  authorized?: boolean
  /** Whether the user denied authorization */
  denied?: boolean
  /** Effective issuer for multi-tenant scenarios */
  effectiveIssuer?: string
  /** Last time the client polled for token (for slow_down enforcement) */
  lastPollTime?: number
}

/**
 * OAuth 2.1 Consent - records a user's consent for a client to access specific scopes
 */
export interface OAuthConsent {
  /** User who granted consent */
  userId: string
  /** Client that received consent */
  clientId: string
  /** Scopes the user consented to */
  scopes: string[]
  /** When consent was granted */
  createdAt: number
  /** When consent was last updated */
  updatedAt: number
}

/**
 * Device Authorization Response (RFC 8628 Section 3.2)
 */
export interface DeviceAuthorizationResponse {
  /** The device verification code */
  device_code: string
  /** The end-user verification code */
  user_code: string
  /** The end-user verification URI */
  verification_uri: string
  /** Optional verification URI with user_code embedded */
  verification_uri_complete?: string
  /** Lifetime of device_code and user_code in seconds */
  expires_in: number
  /** Minimum polling interval in seconds (default: 5) */
  interval?: number
}
