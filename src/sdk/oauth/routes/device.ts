/**
 * Device Authorization Grant endpoints (RFC 8628)
 *
 * - POST /device_authorization — Issue device_code and user_code
 * - GET /device — Device verification page
 * - POST /device — Process device authorization
 */

import { Hono } from 'hono'
import type { ServerContext } from '../helpers'
import { createDeviceAuthorizationHandler, createDeviceGetHandler, createDevicePostHandler } from '../endpoints/index'

/**
 * Create the device flow routes sub-app
 */
export function createDeviceRoutes(ctx: ServerContext): Hono {
  const app = new Hono()

  const deviceHandlerConfig = {
    storage: ctx.storage,
    debug: ctx.debug,
    devMode: ctx.devMode,
    getEffectiveIssuer: ctx.getEffectiveIssuer,
    validateScopes: ctx.validateScopes,
  }

  app.post('/device_authorization', createDeviceAuthorizationHandler(deviceHandlerConfig))
  app.get('/device', createDeviceGetHandler(deviceHandlerConfig))
  app.post('/device', createDevicePostHandler(deviceHandlerConfig))

  return app
}
