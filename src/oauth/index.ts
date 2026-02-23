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
