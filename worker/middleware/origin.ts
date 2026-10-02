/**
 * CORS and origin validation middleware for id.org.ai worker
 *
 * Wraps isAllowedOrigin/validateOrigin from src/csrf/ into Hono middleware.
 */

import { cors } from 'hono/cors'
import { isAllowedOrigin, validateOrigin } from '../../src/sdk/csrf'

// Re-export for consumers that need the raw functions
export { isAllowedOrigin, validateOrigin }

const allowlistedCors = cors({
  origin: (origin) => {
    if (!origin) return origin
    return isAllowedOrigin(origin) ? origin : ''
  },
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization', 'X-API-Key'],
  credentials: true,
})

/**
 * Navigation endpoints no other origin may read with credentials: the consent
 * page (the person, their workspaces) and its POST, whose fetch-submit answer
 * carries an authorization code (phase 5 review S3).
 */
const NO_CORS = /^\/oauth\/authorize$/

export async function corsMiddleware(c: any, next: () => Promise<void>) {
  if (NO_CORS.test(new URL(c.req.url).pathname)) return next()
  return allowlistedCors(c, next)
}

export async function originValidationMiddleware(c: any, next: () => Promise<void>) {
  const error = validateOrigin(c.req.raw)
  if (error) return error
  await next()
}
