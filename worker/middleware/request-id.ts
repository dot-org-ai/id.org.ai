/**
 * Request IDs (docs/product-update/spec/backend.md#b1).
 *
 * Every response carries `X-Request-Id`: Cloudflare's `cf-ray` when present,
 * otherwise `req_` plus 8 random base62 characters (the mock shows req_7Hk2Qp9w).
 * The id is on the context as `requestId` for logs, audit records and the
 * developer details on error pages. Mounted first in worker/index.ts.
 */
import type { MiddlewareHandler } from 'hono'

const BASE62 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'

export function newRequestId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(8))
  let id = 'req_'
  // 248 is the largest multiple of 62 below 256; re-draw the rest so every character is uniform.
  for (let i = 0; i < bytes.length; i++) {
    let b = bytes[i]!
    while (b >= 248) b = crypto.getRandomValues(new Uint8Array(1))[0]!
    id += BASE62[b % 62]
  }
  return id
}

/** cf-ray is `<16 hex>-<colo>`; anything else is ignored rather than reflected. */
function fromRay(ray: string | undefined): string | null {
  return ray && /^[0-9a-f]{16}(-[A-Z]{3})?$/.test(ray) ? ray : null
}

export const requestIdMiddleware: MiddlewareHandler<{ Variables: { requestId: string } }> = async (c, next) => {
  const id = fromRay(c.req.header('cf-ray')) ?? newRequestId()
  c.set('requestId', id)
  await next()
  // A WebSocket upgrade can't be rebuilt; every other response gets the header.
  if (c.res.status === 101) return
  try {
    c.res.headers.set('X-Request-Id', id)
  } catch {
    // Responses from fetch() / ASSETS have immutable headers: copy, then set.
    c.res = new Response(c.res.body, c.res)
    c.res.headers.set('X-Request-Id', id)
  }
}
