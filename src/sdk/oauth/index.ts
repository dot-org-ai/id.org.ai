/**
 * id.org.ai/oauth — Complete OAuth 2.1 Primitive Set
 *
 * This module re-exports the full suite of OAuth 2.1 primitives that have
 * been moved from @dotdo/oauth into id.org.ai as the canonical location.
 *
 * Modules:
 *   - types        — Core data structures (OAuthUser, OAuthClient, tokens, grants, etc.)
 *   - storage      — OAuthStorage interface + MemoryOAuthStorage implementation
 *   - provider     — OAuthProvider class (DO-backed authorization server)
 *   - server       — createOAuth21Server factory + Hono route modules
 *   - helpers      — Shared server context, issuer resolution, scope validation
 *   - pkce         — PKCE + crypto utilities (code challenge, hashing, token gen)
 *   - jwt          — JWT signing (SigningKeyManager, signAccessToken, signIdToken)
 *   - jwt-verify   — JWT verification with JWKS support (verifyJWT, decodeJWT)
 *   - consent      — Consent screen HTML generation + scope descriptions
 *   - guards       — Runtime type guards for JSON validation
 *   - dev          — Dev/test helpers (test users, login forms)
 *   - stripe       — Stripe identity linkage (customer mapping, webhook handling)
 *
 * @module oauth
 */

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
export type { StripeWebhookEvent as StripeWebhookEventGuard, IntrospectionResponseShape } from './guards'

// Dev helpers for testing (canonical, from @dotdo/oauth)
export { createTestHelpers, generateLoginFormHtml } from './dev'
export type { DevModeConfig, DevUser, TestHelpers } from './dev'

// Stripe identity linkage (canonical, from @dotdo/oauth)
export {
  ensureStripeCustomer,
  getStripeCustomer,
  linkStripeCustomer,
  handleStripeWebhook,
  verifyStripeWebhook,
  createStripeClient,
  parseStripeSignature,
  computeStripeSignature,
  timingSafeEqual,
  verifyStripeWebhookAsync,
} from './stripe'
export type {
  StripeCustomer,
  StripeSubscription,
  StripeWebhookEventType,
  StripeWebhookEvent,
  StripeStorage,
  OAuthUserWithStripe,
  StripeClient,
} from './stripe'
