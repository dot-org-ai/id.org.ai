/**
 * OAuth endpoint handlers
 *
 * Re-exports all endpoint handlers for clean imports
 */

// Authorization endpoints
export {
  createAuthorizeHandler,
  createLoginGetHandler,
  createLoginPostHandler,
  createCallbackHandler,
  createExchangeHandler,
  createConsentPostHandler,
  type AuthorizeHandlerConfig,
} from './authorize'

// Token endpoints
export {
  authenticateClient,
  handleAuthorizationCodeGrant,
  handleRefreshTokenGrant,
  handleClientCredentialsGrant,
  handleDeviceCodeGrant,
  type ClientAuthResult,
  type JWTSigningOptions,
} from './token'

// Device Authorization Grant (RFC 8628)
export {
  createDeviceAuthorizationHandler,
  createDeviceGetHandler,
  createDevicePostHandler,
  type DeviceHandlerConfig,
} from './device'

// UserInfo endpoint (OIDC)
export { createUserInfoHandler, type UserInfoHandlerConfig } from './userinfo'

// Dynamic client registration (RFC 7591)
export { createRegisterHandler, type RegisterHandlerConfig } from './register'

// Token introspection (RFC 7662)
export { createIntrospectHandler, type IntrospectHandlerConfig } from './introspect'

// Token revocation (RFC 7009)
export { createRevokeHandler, type RevokeHandlerConfig } from './revoke'
