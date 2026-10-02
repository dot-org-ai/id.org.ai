/**
 * Long-lived caching for the auth UI's hashed assets (docs/product-update/spec/backend.md#b0).
 *
 * The ASSETS binding serves worker/public/ but sets no long-lived caching. Every
 * file under /auth/ carries a content hash, and /fonts/geist/ holds the pinned
 * geist@1.7.2 files, so a 200 is safe to cache forever. Anything ASSETS doesn't
 * have falls through to the rest of the app.
 */
import { Hono } from 'hono'
import type { Context, Next } from 'hono'
import type { Env, Variables } from '../types'

type AppContext = Context<{ Bindings: Env; Variables: Variables }>

export const IMMUTABLE = 'public, max-age=31536000, immutable'

async function serveImmutable(c: AppContext, next: Next, cors: boolean): Promise<Response | void> {
  if (!c.env.ASSETS) return next()
  const res = await c.env.ASSETS.fetch(c.req.raw)
  if (res.status === 404) {
    await res.body?.cancel()
    return next()
  }
  if (res.status !== 200) return res
  const out = new Response(res.body, res)
  out.headers.set('Cache-Control', IMMUTABLE)
  // Email templates load Geist from id.org.ai inside mail clients and webmail.
  if (cors) out.headers.set('Access-Control-Allow-Origin', '*')
  return out
}

export const staticUiRoutes = new Hono<{ Bindings: Env; Variables: Variables }>()
// Only content-hashed names (written by scripts/build-ui.mjs) and the pinned fonts are immutable.
staticUiRoutes.get('/auth/:file{[a-z0-9-]+\\.[0-9a-f]{10}\\.(?:css|js)}', (c, next) => serveImmutable(c, next, false))
staticUiRoutes.get('/fonts/geist/:file{[A-Za-z0-9-]+\\.woff2}', (c, next) => serveImmutable(c, next, true))
