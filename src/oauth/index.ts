// Core OAuth 2.1 types (canonical, from @dotdo/oauth)
export type {
  OAuthUser,
  OAuthOrganization,
  OAuthClient,
  OAuthAuthorizationCode,
  OAuthAccessToken,
  OAuthRefreshToken,
  OAuthGrant,
  OAuthServerMetadata,
  OAuthResourceMetadata,
  TokenResponse,
  OAuthError,
  UpstreamOAuthConfig,
  OAuthDeviceCode,
  OAuthConsent,
  DeviceAuthorizationResponse,
} from './types'

// OAuth 2.1 Storage interface + in-memory implementation
export { MemoryOAuthStorage } from './storage'
export type { OAuthStorage, ListOptions } from './storage'

// OAuth 2.1 Provider implementation
export { OAuthProvider } from './provider'
export type { OAuthConfig, OAuthProviderClient } from './provider'

// OAuth 2.1 Server factory + routes
export { createOAuth21Server } from './server'
export type { OAuth21ServerConfig, OAuth21Server } from './server'

// Shared helpers
export { computeRefreshTokenExpiry } from './helpers'
export type { ServerContext } from './helpers'

// PKCE + crypto utilities (canonical, from @dotdo/oauth)
export {
  generateCodeVerifier,
  generateCodeChallenge,
  verifyCodeChallenge,
  generatePkce,
  generateState,
  generateToken,
  generateAuthorizationCode,
  hashClientSecret,
  verifyClientSecret,
  base64UrlEncode,
  base64UrlDecode,
  constantTimeEqual,
} from './pkce'

// JWT signing + verification (re-exported from ../jwt for convenience)
export * from '../jwt'

// JWT verification with JWKS support (canonical, from @dotdo/oauth)
export { verifyJWT, decodeJWT, isJWTExpired, clearJWKSCache } from './jwt-verify'
export type { JWTVerifyResult, JWTVerifyOptions, JWTHeader, JWTPayload } from './jwt-verify'

// Consent screen generation (canonical, from @dotdo/oauth)
export { generateConsentScreenHtml, getScopeDescription, consentCoversScopes } from './consent'
export type { ConsentScreenOptions } from './consent'

// Guards / validation (canonical, from @dotdo/oauth)
export {
  assertValid,
  ValidationError,
  isStripeWebhookEvent,
  isStripeApiError,
  isJWTHeader,
  isJWTPayload,
  isSerializedSigningKey,
  isStringArray,
  isIntrospectionResponse,
} from './guards'
export type { StripeWebhookEvent, IntrospectionResponseShape } from './guards'

// Dev helpers for testing (canonical, from @dotdo/oauth)
export { createTestHelpers, generateLoginFormHtml } from './dev'
export type { DevModeConfig, DevUser, TestHelpers } from './dev'
