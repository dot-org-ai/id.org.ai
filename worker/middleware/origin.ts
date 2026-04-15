/**
 * CORS and origin validation middleware for id.org.ai worker
 *
 * Wraps isAllowedOrigin/validateOrigin from src/csrf/ into Hono middleware.
 */

import { cors } from 'hono/cors'
import { isAllowedOrigin, validateOrigin } from '../../src/sdk/csrf'

// Re-export for consumers that need the raw functions
export { isAllowedOrigin, validateOrigin }

export const corsMiddleware = cors({
  origin: (origin) => {
    if (!origin) return origin
    return isAllowedOrigin(origin) ? origin : ''
  },
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization', 'X-API-Key'],
  credentials: true,
})

export async function originValidationMiddleware(c: any, next: () => Promise<void>) {
  const error = validateOrigin(c.req.raw)
  if (error) return error
  await next()
}
