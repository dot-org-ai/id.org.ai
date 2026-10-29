/**
 * Email-code sign-in that starts at an app's own page (phase 7's 1b, without
 * id.org.ai's email form): the Fund I deck at pitch.startups.studio first.
 *
 *   /oauth/authorize?…&provider=email&login_hint=<email>   (trusted client)
 *     → /login?provider=email&login_hint=…&continue=<authorize>
 *     → WorkOS Magic Auth emails the 6-digit code (the 'web' budget path)
 *     → 303 /login/code/:flow
 *   GET  /login/code/:flow         1b; ?code= prefills the boxes and never submits
 *   POST /login/code/:flow         checks the code (verifyFlowCode), signs the
 *                                  person in and continues to authorize, which
 *                                  answers the app with its code
 *   POST /login/code/:flow/resend  a new code, under the same send budgets
 *
 * WorkOS sends the email (its code, as it works today); id.org.ai sends none.
 * The flow is bound to the browser that asked: starting it sets the flow's
 * cookie (SameSite=Strict) and every later step needs it, so a code someone
 * else asked for can't sign this browser in. "Use a different email" goes back
 * to the app (its redirect_uri's origin), never to an id.org.ai form.
 */
import { Hono, type Context } from 'hono'
import type { Env, Variables } from '../types'
import { bareOrigin, renderPage } from '../ui/render'
import { renderErrorPage } from '../ui/errors'
import { EmailCode, type EmailCodeError } from '../ui/screens/EmailCode'
import type { TileContent } from '../ui/components'
import { errorResponse, ErrorCode } from '../../src/sdk/errors'
import { createWorkOSMagicAuth } from '../../src/sdk/workos/upstream'
import { requestOriginOf } from '../utils/relying-parties'
import { parseCookieValue } from '../utils/cookies'
import { clientIpOf, reserveCodeSend, resetCodeGuesses } from '../utils/code-guard'
import { siteIcon } from '../utils/app-icon'
import { TRUSTED_ACCOUNT_CLIENT_ID } from './oauth'
import { FLOW_TTL_MS, flowStorage, loadFlow, startMagicLink, verifyFlowCode, type MagicFlow } from './magic-link'

type C = Context<{ Bindings: Env; Variables: Variables }>

const app = new Hono<{ Bindings: Env; Variables: Variables }>()

/** Seconds after a send before 1b offers another code. */
const RESEND_AFTER_SECONDS = 30

const isHttps = (c: C) => new URL(c.req.url).protocol === 'https:'
/** __Host- on https (host-only, Secure, Path=/: no sibling host can plant it); plain on http://localhost. */
const flowCookieName = (c: C) => (isHttps(c) ? '__Host-id_code' : 'id_code')

/** The flow cookie: the browser that asked for the code. Path=/ because __Host- requires it; the value is the flow. */
function flowCookie(c: C, flowId: string | null): string {
  return `${flowCookieName(c)}=${flowId ?? ''}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${flowId ? FLOW_TTL_MS / 1000 : 0}${isHttps(c) ? '; Secure' : ''}`
}

/**
 * Send the code to `email` and go to 1b. `continueUrl` was resolved by /login
 * under its policy. Null when the address isn't one or a budget is spent: the
 * caller falls back to its usual page.
 */
export async function startEmailCode(c: C, email: string, continueUrl: string): Promise<Response | null> {
  // Only on the way to a trusted-account authorize request: not a code sender for anyone's continue.
  try {
    const to = new URL(continueUrl, requestOriginOf(c.req.url))
    if (to.origin !== requestOriginOf(c.req.url) || to.pathname !== '/oauth/authorize' || to.searchParams.get('client_id') !== TRUSTED_ACCOUNT_CLIENT_ID) return null
  } catch {
    return null
  }
  const result = await startMagicLink(c.env, { email, continue: continueUrl }, { kind: 'web', ip: clientIpOf(c.req.raw) })
  if (!result.ok) return null
  const flowId = new URL(result.verify_url).pathname.split('/').pop()!
  return new Response(null, { status: 303, headers: { Location: `/login/code/${flowId}`, 'Set-Cookie': flowCookie(c, flowId), 'Cache-Control': 'no-store' } })
}

/**
 * Where a signed-in Verify's redirects go beyond this origin: the continue URL's origin, and for a continue that is
 * our own /oauth/authorize, its redirect_uri's (the code goes there next). The browser holds a form post's whole
 * redirect chain to the page's CSP form-action, so without them Chrome stops at the first hop off id.org.ai. The
 * continue already passed /login's policy; authorize checks the redirect_uri itself when it runs.
 */
export function continueOrigins(continueUrl: string, requestOrigin: string): string[] {
  const out: string[] = []
  try {
    const u = new URL(continueUrl, requestOrigin)
    if (u.origin !== requestOrigin) out.push(u.origin)
    else if (u.pathname === '/oauth/authorize') {
      const redirect = u.searchParams.get('redirect_uri')
      const origin = redirect ? bareOrigin(new URL(redirect).origin) : null
      if (origin && origin !== 'null') out.push(origin)
    }
  } catch {
    // not a URL: nothing beyond 'self'
  }
  return out
}

/** "Use a different email": back to the app that sent them (its own sign-in page), else id.org.ai's. */
function differentEmailHref(continueUrl: string, requestOrigin: string): string {
  const [app] = continueOrigins(continueUrl, requestOrigin)
  return app && app.startsWith('http') ? `${app}/` : `/login?${new URLSearchParams({ continue: continueUrl })}`
}

/** The host of the app that sent them (https only): the same origin "Use a different email" goes back to. */
export function referringHost(continueUrl: string, requestOrigin: string): string | undefined {
  const [app] = continueOrigins(continueUrl, requestOrigin)
  return app?.startsWith('https://') ? new URL(app).host : undefined
}

/** 1b's connector ends at the app that sent them, by the icon its own site declares (app-icon.ts); else the mail icon. */
async function referringApp(env: Env, continueUrl: string, requestOrigin: string): Promise<{ name: string; tile: TileContent } | undefined> {
  const host = referringHost(continueUrl, requestOrigin)
  const icon = host ? await siteIcon(env, host) : undefined
  return host && icon ? { name: host, tile: { kind: 'logo', src: icon, monogram: host.charAt(0) } } : undefined
}

/** The live 'web' flow this browser asked for, or null. */
async function boundFlow(c: C, flowId: string): Promise<MagicFlow | null> {
  const flow = await loadFlow(c.env, flowId, 'web')
  if (!flow) return null
  return parseCookieValue(c.req.header('cookie') || '', flowCookieName(c)) === flowId ? flow : null
}

async function renderCode(c: C, flowId: string, flow: MagicFlow, opts: { code?: string; error?: EmailCodeError; status?: number } = {}): Promise<Response> {
  const sentAt = flow.sentAt ?? flow.createdAt
  const here = requestOriginOf(c.req.url)
  const referrer = await referringApp(c.env, flow.continue, here)
  return renderPage(
    c,
    EmailCode({
      app: referrer,
      email: flow.email,
      expiresInMinutes: Math.max(1, Math.round((flow.expiresAt - Date.now()) / 60000)),
      action: `/login/code/${flowId}`,
      resendAction: `/login/code/${flowId}/resend`,
      // The flow cookie (SameSite=Strict, this flow only) is what binds these posts.
      csrf: '',
      differentEmailHref: differentEmailHref(flow.continue, here),
      code: opts.code && /^\d{6}$/.test(opts.code) ? opts.code : undefined,
      resendIn: Math.max(0, Math.ceil((sentAt + RESEND_AFTER_SECONDS * 1000 - Date.now()) / 1000)),
      error: opts.error,
      linkInEmail: false,
    }),
    {
      title: 'Check your email · id.org.ai',
      scripts: ['submit.js', 'code-input.js', 'countdown.js'],
      status: opts.status,
      formActionOrigins: continueOrigins(flow.continue, here),
    },
  )
}

const expired = (c: C) => renderErrorPage(c, 'expired', { requestId: c.get('requestId'), expired: { what: 'code' } }, 410)

app.get('/login/code/:flow', async (c) => {
  const flowId = c.req.param('flow')
  const flow = await boundFlow(c, flowId)
  if (!flow) return expired(c)
  return renderCode(c, flowId, flow, { code: c.req.query('code') })
})

app.post('/login/code/:flow', async (c) => {
  if (!c.env.WORKOS_API_KEY || !c.env.WORKOS_CLIENT_ID) {
    return errorResponse(c, 503, ErrorCode.ServiceUnavailable, 'WorkOS is not configured')
  }
  const flowId = c.req.param('flow')
  const flow = await boundFlow(c, flowId)
  if (!flow) return expired(c)
  // Six boxes, each named `code` (or one field with all six): joined.
  let code = ''
  try {
    code = (await c.req.raw.formData()).getAll('code').filter((v): v is string => typeof v === 'string').join('').replace(/\s+/g, '')
  } catch {
    code = ''
  }
  if (!/^\d{6}$/.test(code)) return renderCode(c, flowId, flow, { error: 'wrong-code', status: 400 })

  const outcome = await verifyFlowCode(c, flowId, flow, code)
  if (outcome.kind === 'expired') return expired(c)
  if (outcome.kind === 'wrong-code') return renderCode(c, flowId, flow, { error: 'wrong-code', status: 400 })
  if (outcome.kind === 'too-many') {
    const res = await renderCode(c, flowId, flow, { error: 'too-many-tries', status: 429 })
    res.headers.set('Retry-After', String(outcome.retryAfterSec))
    return res
  }
  if (outcome.kind === 'unavailable') return renderCode(c, flowId, flow, { error: 'wrong-code', status: 502 })
  const out = new Response(outcome.response.body, outcome.response)
  out.headers.append('Set-Cookie', flowCookie(c, null))
  return out
})

app.post('/login/code/:flow/resend', async (c) => {
  const apiKey = c.env.WORKOS_API_KEY
  if (!apiKey || !c.env.WORKOS_CLIENT_ID) return errorResponse(c, 503, ErrorCode.ServiceUnavailable, 'WorkOS is not configured')
  const flowId = c.req.param('flow')
  const flow = await boundFlow(c, flowId)
  if (!flow) return expired(c)
  const sentAt = flow.sentAt ?? flow.createdAt
  // Too soon, or the address's send budget is spent: back to 1b, which shows the countdown.
  if (Date.now() < sentAt + RESEND_AFTER_SECONDS * 1000) return c.redirect(`/login/code/${flowId}`, 303)
  const reserved = await reserveCodeSend(c.env, flow.email, 'web')
  if (!reserved.ok) return renderCode(c, flowId, flow, { error: 'too-many-tries', status: 429 })
  try {
    const sent = await createWorkOSMagicAuth(apiKey, flow.email)
    if (sent.ok) await resetCodeGuesses(c.env, flow.email, 'web')
  } catch (err) {
    console.error('[login/code] resend failed:', err instanceof Error ? err.message : err)
  }
  // A new code: a new 10 minutes and a new countdown, on the same flow (its guess count carries on).
  const now = Date.now()
  await flowStorage(c.env).put(`magic-flow:${flowId}`, { ...flow, sentAt: now, expiresAt: now + FLOW_TTL_MS } satisfies MagicFlow)
  return c.redirect(`/login/code/${flowId}`, 303)
})

export { app as loginEmailRoutes }
