/**
 * Token introspection, revocation, and userinfo endpoints
 *
 * - POST /introspect — Token introspection (RFC 7662)
 * - POST /revoke — Token revocation (RFC 7009)
 * - GET /userinfo — OpenID Connect UserInfo
 */

import { Hono } from 'hono'
import type { ServerContext } from '../helpers'
import { createIntrospectHandler, createRevokeHandler, createUserInfoHandler } from '../endpoints/index'

/**
 * Create the introspection / revocation / userinfo routes sub-app
 */
export function createIntrospectRoutes(ctx: ServerContext): Hono {
  const app = new Hono()

  app.post(
    '/introspect',
    createIntrospectHandler({
      defaultIssuer: ctx.defaultIssuer,
      storage: ctx.storage,
      signingKeyManager: ctx.getSigningKeyManager(),
      useJwtAccessTokens: ctx.useJwtAccessTokens,
      debug: ctx.debug,
      getEffectiveIssuer: ctx.getEffectiveIssuer,
      ensureSigningKey: ctx.ensureSigningKey,
      getSigningKeyManager: ctx.getSigningKeyManager,
    }),
  )

  app.get(
    '/userinfo',
    createUserInfoHandler({
      defaultIssuer: ctx.defaultIssuer,
      storage: ctx.storage,
      signingKeyManager: ctx.getSigningKeyManager(),
      useJwtAccessTokens: ctx.useJwtAccessTokens,
      debug: ctx.debug,
      getEffectiveIssuer: ctx.getEffectiveIssuer,
      ensureSigningKey: ctx.ensureSigningKey,
    }),
  )

  app.post(
    '/revoke',
    createRevokeHandler({
      storage: ctx.storage,
      onTokenRevoked: ctx.onTokenRevoked,
    }),
  )

  return app
}
