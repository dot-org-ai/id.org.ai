/**
 * Authorization endpoints
 *
 * - GET /authorize — Authorization endpoint
 * - GET /login — Simple login redirect for first-party apps
 * - POST /login — Dev mode login form submission
 * - GET /api/callback — Upstream OAuth callback
 * - POST /exchange — Platform token exchange
 * - POST /consent — Consent form submission (allow/deny)
 */

import { Hono } from 'hono'
import type { ServerContext } from '../helpers'
import {
  createAuthorizeHandler,
  createLoginGetHandler,
  createLoginPostHandler,
  createCallbackHandler,
  createExchangeHandler,
  createConsentPostHandler,
  type AuthorizeHandlerConfig,
} from '../endpoints/index'

/**
 * Create the authorization routes sub-app
 */
export function createAuthorizeRoutes(ctx: ServerContext): Hono {
  const app = new Hono()

  // Shared config for authorization handlers
  const authorizeHandlerConfig: AuthorizeHandlerConfig = {
    defaultIssuer: ctx.defaultIssuer,
    storage: ctx.storage,
    upstream: ctx.upstream,
    devMode: ctx.devMode,
    scopes: ctx.scopes,
    accessTokenTtl: ctx.accessTokenTtl,
    refreshTokenTtl: ctx.refreshTokenTtl,
    authCodeTtl: ctx.authCodeTtl,
    onUserAuthenticated: ctx.onUserAuthenticated,
    debug: ctx.debug,
    corsOrigins: ctx.corsOrigins,
    testHelpers: ctx.testHelpers,
    getEffectiveIssuer: ctx.getEffectiveIssuer,
    validateRedirectUriScheme: ctx.validateRedirectUriScheme,
    validateScopes: ctx.validateScopes,
    generateAccessToken: ctx.generateAccessToken,
    trustedClientIds: ctx.trustedClientIds,
    skipConsent: ctx.skipConsent,
  }

  app.get('/authorize', createAuthorizeHandler(authorizeHandlerConfig))
  app.get('/login', createLoginGetHandler(authorizeHandlerConfig))
  app.post('/login', createLoginPostHandler(authorizeHandlerConfig))
  app.get('/api/callback', createCallbackHandler(authorizeHandlerConfig))
  app.post('/exchange', createExchangeHandler(authorizeHandlerConfig))
  app.post('/consent', createConsentPostHandler(authorizeHandlerConfig))

  return app
}
