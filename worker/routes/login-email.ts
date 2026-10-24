/**
 * The sign-in page (1a) and its own email path (docs/product-update/spec/backend.md#b4,
 * phase 7 tasks 1–2 without SSO discovery):
 *
 *   GET  /login                    1a (rendered by worker/routes/auth.ts through
 *                                  renderSignIn below): "Continue with Google"
 *                                  first, the email form, then Microsoft, GitHub
 *                                  and Apple. With a login_hint that isn't
 *                                  Google's, the email form comes first,
 *                                  filled in.
 *   POST /login/email              { email, continue, csrf } → a 6-digit code
 *                                  to that address (WorkOS Magic Auth, the
 *                                  'web' budget path) → 303 /login/code/:flow
 *   GET  /login/code/:flow         1b; ?code= prefills the boxes and never
 *                                  submits
 *   POST /login/code/:flow         checks the code (verifyFlowCode), signs the
 *                                  person in and continues
 *   POST /login/code/:flow/resend  a new code, under the same send budgets
 *
 * The form's CSRF is a double-submit token: 1a sets it as a host-only cookie
 * (__Host- on https) and in the form, and the POST needs both, equal. The flow
 * is bound to the browser that asked for the code: POST /login/email sets the
 * flow's cookie (SameSite=Strict, this path only) and every later step needs
 * it, so a code someone else asked for can't sign this browser in.
 *
 * WorkOS sends the email, and its Magic Auth email holds only the code (a
 * link would need id.org.ai to send the email itself, which means turning
 * WorkOS's emails off for the whole environment), so 1b leaves out "open the
 * link in the email". The ?code= prefill is ready for when it does.
 */
import { Hono, type Context } from 'hono'
import type { Env, Variables } from '../types'
import { bareOrigin, renderPage } from '../ui/render'
import { renderErrorPage } from '../ui/errors'
import { SignIn, type ProviderLink } from '../ui/screens/SignIn'
import { EmailCode, type EmailCodeError } from '../ui/screens/EmailCode'
import type { TileContent } from '../ui/components'
import { errorResponse, ErrorCode } from '../../src/sdk/errors'
import { createWorkOSMagicAuth } from '../../src/sdk/workos/upstream'
import { resolveBrowserRedirect, requestOriginOf } from '../utils/relying-parties'
import { parseCookieValue } from '../utils/cookies'
import { generateCSRFToken } from '../../src/sdk/csrf'
import { clientIpOf, reserveCodeSend, resetCodeGuesses } from '../utils/code-guard'
import { FLOW_TTL_MS, flowStorage, isPlausibleEmail, loadFlow, normalizeEmail, startMagicLink, verifyFlowCode, type MagicFlow } from './magic-link'

type C = Context<{ Bindings: Env; Variables: Variables }>

const app = new Hono<{ Bindings: Env; Variables: Variables }>()

const DEFAULT_CONTINUE = '/dash/profile'
const CSRF_TTL_SECONDS = 30 * 60
/** Seconds after a send before 1b offers another code. */
const RESEND_AFTER_SECONDS = 30
const ID_ORG_AI: { name: string; tile: TileContent } = { name: 'id.org.ai', tile: { kind: 'org' } }

const isHttps = (c: C) => new URL(c.req.url).protocol === 'https:'
/** __Host- on https (host-only, Secure, Path=/: no sibling host can plant it); plain on http://localhost. */
const csrfCookieName = (c: C) => (isHttps(c) ? '__Host-id_login' : 'id_login')
const flowCookieName = (c: C) => (isHttps(c) ? '__Host-id_code' : 'id_code')

function csrfCookie(c: C, token: string): string {
  return `${csrfCookieName(c)}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${CSRF_TTL_SECONDS}${isHttps(c) ? '; Secure' : ''}`
}

/** The flow cookie: the browser that asked for the code. Path=/ because __Host- requires it; the value is the flow. */
function flowCookie(c: C, flowId: string | null): string {
  return `${flowCookieName(c)}=${flowId ?? ''}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${flowId ? FLOW_TTL_MS / 1000 : 0}${isHttps(c) ? '; Secure' : ''}`
}

function checkCsrf(c: C, submitted: string | undefined): boolean {
  const cookie = parseCookieValue(c.req.header('cookie') || '', csrfCookieName(c))
  return !!submitted && !!cookie && /^[A-Za-z0-9_-]{16,128}$/.test(submitted) && cookie === submitted
}

// ── 1a ──────────────────────────────────────────────────────────────────────

export interface SignInPageOptions {
  /** Already resolved under /login's continue policy. */
  continueUrl: string
  loginHint?: string
  promptLogin?: boolean
  /** Lead with Google (no login_hint), or with the email form, filled in (a hint that isn't Google's). */
  lead: 'google' | 'email'
  emailError?: string
  status?: number
}

/** The provider links: today's GET /login?provider=… flow, with continue, login_hint and prompt forwarded. */
function providerLinks(o: SignInPageOptions): { google: ProviderLink; others: ProviderLink[] } {
  const href = (provider: string) => {
    const q = new URLSearchParams({ provider, continue: o.continueUrl })
    if (o.loginHint) q.set('login_hint', o.loginHint)
    if (o.promptLogin) q.set('prompt', 'login')
    return `/login?${q.toString()}`
  }
  return {
    google: { provider: 'google', href: href('GoogleOAuth') },
    // Microsoft and Apple stay on hosted AuthKit until they're enabled as
    // direct WorkOS providers (an owner step; WorkOS answers 404 for MicrosoftOAuth today).
    others: [
      { provider: 'microsoft', href: href('authkit') },
      { provider: 'github', href: href('GitHubOAuth') },
      { provider: 'apple', href: href('authkit') },
    ],
  }
}

/** 1a, with a fresh CSRF token in its cookie and form. */
export async function renderSignIn(c: C, o: SignInPageOptions): Promise<Response> {
  const csrf = generateCSRFToken()
  const { google, others } = providerLinks(o)
  const element = SignIn({
    action: '/login/email',
    csrf,
    continueUrl: o.continueUrl,
    email: o.loginHint,
    emailError: o.emailError,
    ...(o.lead === 'google' ? { lead: google, providers: others } : { providers: [google, ...others] }),
  })
  return renderPage(c, element, {
    title: 'Sign in · id.org.ai',
    scripts: ['submit.js'],
    status: o.status,
    headers: { 'Set-Cookie': csrfCookie(c, csrf) },
  })
}

// ── POST /login/email ───────────────────────────────────────────────────────

async function readForm(c: C): Promise<Record<string, string>> {
  try {
    const form = await c.req.raw.formData()
    const out: Record<string, string> = {}
    for (const [k, v] of form.entries()) if (typeof v === 'string' && !(k in out)) out[k] = v
    return out
  } catch {
    return {}
  }
}

const minutes = (seconds: number) => Math.max(1, Math.ceil(seconds / 60))

app.post('/login/email', async (c) => {
  if (!c.env.WORKOS_API_KEY || !c.env.WORKOS_CLIENT_ID) {
    return errorResponse(c, 503, ErrorCode.ServiceUnavailable, 'WorkOS is not configured')
  }
  const form = await readForm(c)
  // The same continue policy as GET /login (the form carries what it resolved; it is checked again).
  const decision = await resolveBrowserRedirect(c.env, form.continue || undefined, { requestOrigin: requestOriginOf(c.req.url) })
  const continueUrl = decision.url ?? DEFAULT_CONTINUE
  const email = normalizeEmail(form.email || '')
  const again = (emailError: string, status: number) =>
    renderSignIn(c, { continueUrl, loginHint: isPlausibleEmail(email) ? email : undefined, lead: 'email', emailError, status })

  if (!checkCsrf(c, form.csrf)) return again('This page expired. Try again.', 403)
  if (!isPlausibleEmail(email)) return again('Enter your email address.', 400)

  const result = await startMagicLink(c.env, { email, continue: continueUrl }, { kind: 'web', ip: clientIpOf(c.req.raw) })
  if (!result.ok) {
    if (result.status === 429) {
      const wait = minutes(result.retryAfterSec ?? 60)
      return again(`Too many codes sent. Try again in ${wait} minute${wait === 1 ? '' : 's'}.`, 429)
    }
    if (result.status === 400) return again('Enter your email address.', 400)
    return again('We couldn’t send the code. Try again.', 502)
  }
  const flowId = new URL(result.verify_url).pathname.split('/').pop()!
  return new Response(null, { status: 303, headers: { Location: `/login/code/${flowId}`, 'Set-Cookie': flowCookie(c, flowId) } })
})

// ── 1b ──────────────────────────────────────────────────────────────────────

/** The live 'web' flow this browser asked for, or null. */
async function boundFlow(c: C, flowId: string): Promise<MagicFlow | null> {
  const flow = await loadFlow(c.env, flowId, 'web')
  if (!flow) return null
  return parseCookieValue(c.req.header('cookie') || '', flowCookieName(c)) === flowId ? flow : null
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

function renderCode(c: C, flowId: string, flow: MagicFlow, opts: { code?: string; error?: EmailCodeError; status?: number } = {}): Promise<Response> {
  const sentAt = flow.sentAt ?? flow.createdAt
  const q = new URLSearchParams({ continue: flow.continue })
  return renderPage(
    c,
    EmailCode({
      app: ID_ORG_AI,
      email: flow.email,
      expiresInMinutes: Math.max(1, Math.round((flow.expiresAt - Date.now()) / 60000)),
      action: `/login/code/${flowId}`,
      resendAction: `/login/code/${flowId}/resend`,
      // The flow cookie (SameSite=Strict, this flow only) is what binds these posts.
      csrf: '',
      differentEmailHref: `/login?${q.toString()}`,
      code: opts.code && /^\d{6}$/.test(opts.code) ? opts.code : undefined,
      resendIn: Math.max(0, Math.ceil((sentAt + RESEND_AFTER_SECONDS * 1000 - Date.now()) / 1000)),
      error: opts.error,
      linkInEmail: false,
    }),
    {
      title: 'Check your email · id.org.ai',
      scripts: ['submit.js', 'code-input.js', 'countdown.js'],
      status: opts.status,
      formActionOrigins: continueOrigins(flow.continue, requestOriginOf(c.req.url)),
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
