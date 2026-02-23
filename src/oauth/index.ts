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
