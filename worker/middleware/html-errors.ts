/**
 * Browsers never see raw JSON errors (docs/product-update/spec/backend.md#b1).
 *
 * On the browser-facing routes, and for the catch-all 404 anywhere, a JSON
 * error answered to a browser navigation is replaced with the error template
 * (worker/ui/errors.ts), at the same status, with the request ID in its
 * details. API callers (no text/html in Accept, not a navigation) keep the
 * JSON byte for byte.
 */
import type { Context, MiddlewareHandler } from 'hono'
import type { Env, Variables } from '../types'
import { kindForApiError, renderErrorPage, type ErrorContext } from '../ui/errors'

/** A browser navigation or form post: Accept includes text/html, or Sec-Fetch-Mode is navigate. */
export function wantsHtml(c: Context): boolean {
  const accept = c.req.header('accept') ?? ''
  return accept.includes('text/html') || c.req.header('sec-fetch-mode') === 'navigate'
}

/** Routes a person reaches in a browser. Everything else is an API, whatever its Accept says. */
const BROWSER_PATHS = [
  /^\/login(\/|$)/,
  /^\/logout$/,
  /^\/api\/callback$/,
  /^\/callback$/,
  /^\/api\/org-select$/,
  /^\/oauth\/authorize$/,
  /^\/device(\/|$)/,
  /^\/magic-link\//,
  /^\/claim\/[^/]+(\/repo)?$/,
]

const CATCH_ALL = 'The requested endpoint does not exist'

export const htmlErrorsMiddleware: MiddlewareHandler<{ Bindings: Env; Variables: Variables }> = async (c, next) => {
  await next()
  const res = c.res
  if (res.status < 400 || !wantsHtml(c)) return
  if (!(res.headers.get('content-type') ?? '').includes('application/json')) return
  const body = (await res
    .clone()
    .json()
    .catch(() => null)) as { error?: unknown; error_description?: unknown } | null
  if (!body || typeof body.error !== 'string') return
  const description = typeof body.error_description === 'string' ? body.error_description : undefined
  const path = new URL(c.req.url).pathname
  const catchAll = res.status === 404 && body.error === 'not_found' && description === CATCH_ALL
  if (!catchAll && !BROWSER_PATHS.some((re) => re.test(path))) return

  const kind = kindForApiError(res.status, body.error, description)
  const ctx: ErrorContext = { requestId: c.get('requestId'), code: body.error, description }
  if (path === '/oauth/authorize') {
    // The client and the rejected redirect_uri go in the details as text; nothing links to it.
    const clientId = c.req.query('client_id')
    if (clientId) ctx.client = { id: clientId.slice(0, 200) }
    if (kind === 'redirect_not_registered') ctx.redirect = (c.req.query('redirect_uri') ?? '').slice(0, 500) || undefined
  }
  const retryAfter = Number(res.headers.get('retry-after'))
  if (Number.isFinite(retryAfter) && retryAfter > 0) ctx.retryAfterSeconds = retryAfter

  const page = await renderErrorPage(c, kind, ctx, res.status)
  const cookies = res.headers.getSetCookie()
  // Replace outright: the JSON response's headers (caching, CORS) must not
  // carry over onto the page; only its cookies do.
  c.res = undefined as unknown as Response
  for (const cookie of cookies) page.headers.append('Set-Cookie', cookie)
  if (retryAfter > 0) page.headers.set('Retry-After', String(retryAfter))
  c.res = page
}
