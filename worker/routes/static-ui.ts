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

async function serveImmutable(c: AppContext, next: Next): Promise<Response | void> {
  if (!c.env.ASSETS) return next()
  const res = await c.env.ASSETS.fetch(c.req.raw)
  if (res.status === 404) return next()
  if (res.status !== 200) return res
  const out = new Response(res.body, res)
  out.headers.set('Cache-Control', IMMUTABLE)
  return out
}

export const staticUiRoutes = new Hono<{ Bindings: Env; Variables: Variables }>()
staticUiRoutes.get('/auth/*', serveImmutable)
staticUiRoutes.get('/fonts/*', serveImmutable)
