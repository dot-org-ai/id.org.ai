/**
 * Client registration / management endpoints
 *
 * - POST /register — Dynamic client registration (RFC 7591)
 */

import { Hono } from 'hono'
import type { ServerContext } from '../helpers'
import { createRegisterHandler } from '../endpoints/index'

/**
 * Create the client registration routes sub-app
 */
export function createClientRoutes(ctx: ServerContext): Hono {
  const app = new Hono()

  if (ctx.enableDynamicRegistration) {
    app.post(
      '/register',
      createRegisterHandler({
        storage: ctx.storage,
        debug: ctx.debug,
        requireRegistrationAuth: ctx.requireRegistrationAuth,
        adminToken: ctx.adminToken,
        validateRedirectUriScheme: ctx.validateRedirectUriScheme,
      }),
    )
  }

  return app
}
