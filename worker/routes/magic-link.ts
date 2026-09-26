/**
 * Magic-link sign-in for relying parties (a Startup's waitlist, api.sb, …).
 *
 * Two ways to ask for one; both end in `startMagicLink` below:
 *
 *   POST /api/magic-link { email, continue, client_id }
 *     Caller: a confidential client (client_secret_basic or
 *     client_secret_post) whose id is listed in MAGIC_LINK_CLIENTS, and
 *     nobody else. An unauthenticated caller gets 401; an authenticated but
 *     unlisted client gets 403 (registration is open, so otherwise anyone
 *     could register a client and relay id.org.ai's sign-in emails to any
 *     address). No trust is inferred from the request's host: public traffic
 *     arrives on `id.org.ai.` as well as `id.org.ai`, so a host outside a
 *     list proves nothing.
 *
 *   env.OAUTH.sendMagicLink({ email, continue, clientId, origin })
 *     Caller: a worker in the account with a service binding to the
 *     AuthService entrypoint (worker/index.ts). An RPC method is reachable
 *     only through a binding, never from the public internet, so the binding
 *     itself is the credential. `origin` is the calling worker's own origin,
 *     on which `continue` may also land.
 *
 *   Either asks WorkOS Magic Auth to email the person a one-time sign-in code
 *   and opens a 10-minute sign-in flow. The answer is { sent, verify_url,
 *   expires_in } (HTTP 202) whether or not an account exists for that address
 *   (WorkOS creates the user when it is new).
 *
 *   GET  /magic-link/:flow[?code=123456]   the sign-in page for that flow
 *   POST /magic-link/:flow  code=123456    checks the code with WorkOS, signs the
 *                                          person in (L2 session cookie on
 *                                          id.org.ai, amr ["magic_link"],
 *                                          idp "magic_link") and continues.
 *
 * The code travels only through the person's mailbox: the flow id alone signs
 * nobody in, so handing `verify_url` to the relying party is safe. `continue`
 * is held server-side with the flow and validated like /login?continue=
 * (worker/utils/relying-parties.ts), plus the calling client's own redirect
 * origins.
 *
 * Limits: 5 sends per email per hour (the magic-link path's own counter,
 * `code-send:ml:<email>`, shared by listed clients and service bindings but
 * not with the public /federation/email/send, worker/utils/code-guard.ts), 100 per client (or
 * binding) per hour, 300 in all per hour, 5 code attempts per flow. Every
 * counter is incremented and checked in one Durable Object call
 * (IdentityDO.consumeBudget), before the send or the WorkOS check it guards,
 * so parallel requests cannot overrun a budget. Every guess also spends this
 * path's per-address guess budget and the per-IP guess budget; a code sent
 * here starts this path's guess budget afresh (never the federation path's).
 */
import { Hono } from 'hono'
import type { Env, Variables } from '../types'
import { getStubForIdentity } from '../middleware/tenant'
import { errorResponse, ErrorCode } from '../../src/sdk/errors'
import { constantTimeEqual } from '../../src/sdk/oauth/pkce'
import {
  createWorkOSMagicAuth,
  authenticateWorkOSMagicAuth,
  encodeLoginState,
} from '../../src/sdk/workos/upstream'
import type { OrgSelectionError, WorkOSAuthResult } from '../../src/sdk/workos/upstream'
import { resolveContinue, getRegisteredClient, canonicalOrigin, requestOriginOf } from '../utils/relying-parties'
import { finishWorkOSSignIn, loginCsrfRecord } from './auth'
import { renderOrgPickerPage } from '../views/org-picker'
import { escapeHtml } from '../utils/html'
import { parseCookieValue } from '../utils/cookies'
import { reserveCodeGuess, resetCodeGuesses, reserveCodeSend, clientIpOf } from '../utils/code-guard'

const app = new Hono<{ Bindings: Env; Variables: Variables }>()

/** Where the person completes the sign-in. */
const CANONICAL_ORIGIN = 'https://id.org.ai'
const DEFAULT_CONTINUE = '/dash/profile'
const FLOW_TTL_MS = 10 * 60 * 1000
const MAX_CODE_ATTEMPTS = 5
const CLIENT_LIMIT = { max: 100, windowMs: 60 * 60 * 1000 }
/** Every caller together: bounds what id.org.ai's WorkOS account sends per hour. */
const GLOBAL_LIMIT = { max: 300, windowMs: 60 * 60 * 1000 }
const GLOBAL_LIMIT_KEY = 'magiclink-rl:global'

/** MAGIC_LINK_CLIENTS: the client ids allowed to call POST /api/magic-link. */
export function magicLinkClients(env: Env): Set<string> {
  return new Set(
    (env.MAGIC_LINK_CLIENTS ?? '')
      .split(',')
      .map((id) => id.trim())
      .filter(Boolean),
  )
}
const FLOW_COOKIE = '__mlf'

interface MagicFlow {
  email: string
  continue: string
  clientId?: string
  createdAt: number
  expiresAt: number
}

export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase()
}

export function isPlausibleEmail(email: string): boolean {
  return email.length <= 320 && /^[^\s@<>"']+@[^\s@<>".]+(\.[^\s@<>".]+)+$/.test(email)
}

function storage(env: Env) {
  const stub = getStubForIdentity(env, 'oauth')
  return {
    get: async <T>(key: string) => (await stub.oauthStorageOp({ op: 'get', key })).value as T | undefined,
    put: async (key: string, value: unknown) => {
      await stub.oauthStorageOp({ op: 'put', key, value })
    },
    delete: async (key: string) => {
      await stub.oauthStorageOp({ op: 'delete', key })
    },
  }
}

/**
 * Fixed-window counter. Returns the seconds to wait when over budget, else 0.
 * Increment and check happen in one call inside the oauth Durable Object, so
 * concurrent callers cannot both pass on a stale count.
 */
async function consumeBudget(env: Env, key: string, limit: { max: number; windowMs: number }): Promise<number> {
  const r = await getStubForIdentity(env, 'oauth').consumeBudget({ key, max: limit.max, windowMs: limit.windowMs })
  return r.allowed ? 0 : r.retryAfterSec
}

const attemptsKey = (flowId: string) => `magic-flow-attempts:${flowId}`

/** End a flow: the flow record and its attempt counter. */
async function endFlow(env: Env, flowId: string): Promise<void> {
  await storage(env).delete(`magic-flow:${flowId}`)
  await storage(env).delete(attemptsKey(flowId))
}

function parseBasicAuth(header: string | undefined): { clientId: string; clientSecret: string } | null {
  if (!header?.startsWith('Basic ')) return null
  try {
    const decoded = atob(header.slice(6))
    const i = decoded.indexOf(':')
    if (i < 0) return null
    return { clientId: decodeURIComponent(decoded.slice(0, i)), clientSecret: decodeURIComponent(decoded.slice(i + 1)) }
  } catch {
    return null
  }
}

async function readBody(request: Request): Promise<Record<string, string>> {
  const type = request.headers.get('content-type') || ''
  try {
    if (type.includes('application/json')) {
      const json = (await request.json()) as Record<string, unknown>
      return Object.fromEntries(Object.entries(json).filter(([, v]) => typeof v === 'string')) as Record<string, string>
    }
    const form = await request.formData()
    const out: Record<string, string> = {}
    for (const [k, v] of form.entries()) if (typeof v === 'string') out[k] = v
    return out
  } catch {
    return {}
  }
}

function randomFlowId(): string {
  const bytes = new Uint8Array(24)
  crypto.getRandomValues(bytes)
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

function maskEmail(email: string): string {
  const [local = '', domain = ''] = email.split('@')
  const shown = local.length <= 2 ? local.slice(0, 1) : local.slice(0, 2)
  return `${shown}${'•'.repeat(Math.max(1, Math.min(6, local.length - shown.length)))}@${domain}`
}

// ── Starting a flow (shared by the HTTP route and the RPC method) ─────────

/** Who is asking. Authentication has already happened by the time this exists. */
export type MagicLinkCaller =
  /** A confidential client that proved its secret and is in MAGIC_LINK_CLIENTS. */
  | { kind: 'client'; clientId: string }
  /**
   * A worker calling AuthService.sendMagicLink over a service binding. It may
   * name a registered client (for its redirect origins) and its own origin
   * (where `continue` may land); neither is needed.
   */
  | { kind: 'binding'; clientId?: string; origin?: string }

export interface MagicLinkRequest {
  email: string
  /** Where the browser goes after signing in (validated; default /dash/profile). */
  continue?: string
}

export type MagicLinkResult =
  | { ok: true; sent: true; verify_url: string; expires_in: number }
  | {
      ok: false
      status: 400 | 429 | 502 | 503
      error: 'invalid_request' | 'invalid_client' | 'rate_limited' | 'temporarily_unavailable'
      error_description: string
      retryAfterSec?: number
    }

/**
 * Validate the request, spend the budgets, have WorkOS email the code and
 * open the flow. The caller must already be authenticated: a listed
 * confidential client (HTTP) or a service binding (RPC).
 */
export async function startMagicLink(env: Env, req: MagicLinkRequest, caller: MagicLinkCaller): Promise<MagicLinkResult> {
  const apiKey = env.WORKOS_API_KEY!

  // A binding may name a client for its redirect origins; it must exist.
  const client = caller.clientId ? await getRegisteredClient(env, caller.clientId) : null
  if (caller.clientId && !client) {
    return { ok: false, status: 400, error: 'invalid_client', error_description: 'Unknown client_id' }
  }
  const bindingOrigin = caller.kind === 'binding' && caller.origin ? canonicalOrigin(caller.origin) : null
  if (caller.kind === 'binding' && caller.origin && (!bindingOrigin || !/^https?:\/\//.test(bindingOrigin))) {
    return { ok: false, status: 400, error: 'invalid_request', error_description: 'origin must be an http(s) origin' }
  }

  // ── Input ─────────────────────────────────────────────────────────────
  const email = normalizeEmail(typeof req.email === 'string' ? req.email : '')
  if (!isPlausibleEmail(email)) {
    return { ok: false, status: 400, error: 'invalid_request', error_description: 'email must be an email address' }
  }

  const rawContinue = typeof req.continue === 'string' ? req.continue : ''
  let continueUrl = DEFAULT_CONTINUE
  if (rawContinue) {
    let accepted = await resolveContinue(env, rawContinue, { requestOrigin: CANONICAL_ORIGIN, clientId: client?.id })
    // A binding may also continue to its own origin.
    if (!accepted && bindingOrigin && !rawContinue.startsWith('/')) {
      accepted = await resolveContinue(env, rawContinue, { requestOrigin: bindingOrigin })
    }
    if (!accepted) {
      return {
        ok: false,
        status: 400,
        error: 'invalid_request',
        error_description: "continue must be a relative path, an id.org.ai origin, or one of the client's registered redirect origins",
      }
    }
    continueUrl = accepted
  }

  // ── Rate limits: per address (this path's own), then per caller, then for everyone ──
  const callerKey = client?.id ?? `binding:${bindingOrigin ? new URL(bindingOrigin).host : 'rpc'}`
  const byEmail = await reserveCodeSend(env, email, 'ml')
  const emailWait = byEmail.ok ? 0 : byEmail.retryAfterSec
  const clientWait = emailWait ? 0 : await consumeBudget(env, `magiclink-rl:client:${callerKey}`, CLIENT_LIMIT)
  const globalWait = emailWait || clientWait ? 0 : await consumeBudget(env, GLOBAL_LIMIT_KEY, GLOBAL_LIMIT)
  const wait = emailWait || clientWait || globalWait
  if (wait) {
    const why = emailWait ? 'for this address' : clientWait ? 'from this client' : 'right now'
    if (globalWait) console.warn(JSON.stringify({ event: 'magic-link.global-cap', client: callerKey }))
    return { ok: false, status: 429, error: 'rate_limited', error_description: `Too many sign-in emails ${why}; try later`, retryAfterSec: wait }
  }

  // ── Send (WorkOS emails the code) ────────────────────────────────────
  // The answer never depends on whether an account exists: WorkOS creates the
  // user for a new address, and any per-address refusal (4xx) is logged and
  // answered exactly like a send.
  let sent: Awaited<ReturnType<typeof createWorkOSMagicAuth>>
  try {
    sent = await createWorkOSMagicAuth(apiKey, email)
  } catch (err) {
    console.error('[magic-link] WorkOS unreachable:', err instanceof Error ? err.message : err)
    return { ok: false, status: 502, error: 'temporarily_unavailable', error_description: 'Could not send the sign-in email; try again' }
  }
  if (!sent.ok) {
    if (sent.status >= 500 || sent.status === 429) {
      console.error(`[magic-link] WorkOS magic_auth failed: ${sent.status}`)
      return { ok: false, status: 502, error: 'temporarily_unavailable', error_description: 'Could not send the sign-in email; try again' }
    }
    console.warn(JSON.stringify({ event: 'magic-link.send.refused', status: sent.status, client: callerKey }))
  } else {
    // A new code is out: this path's guess budget for the address starts
    // afresh. Bounded by this path's send budget reserved above.
    await resetCodeGuesses(env, email, 'ml')
  }

  const flowId = randomFlowId()
  const now = Date.now()
  await storage(env).put(`magic-flow:${flowId}`, {
    email,
    continue: continueUrl,
    ...(client ? { clientId: client.id } : {}),
    createdAt: now,
    expiresAt: now + FLOW_TTL_MS,
  } satisfies MagicFlow)

  return { ok: true, sent: true, verify_url: `${CANONICAL_ORIGIN}/magic-link/${flowId}`, expires_in: FLOW_TTL_MS / 1000 }
}

// ── POST /api/magic-link ─────────────────────────────────────────────────────

app.post('/api/magic-link', async (c) => {
  if (!c.env.WORKOS_API_KEY || !c.env.WORKOS_CLIENT_ID) {
    return errorResponse(c, 503, ErrorCode.ServiceUnavailable, 'WorkOS is not configured')
  }

  const body = await readBody(c.req.raw)
  const basic = parseBasicAuth(c.req.header('authorization'))
  const clientId = basic?.clientId || body.client_id || ''
  const clientSecret = basic?.clientSecret || body.client_secret || ''

  // ── Caller authentication: a confidential client, by its secret ──────
  // Only that. Callers inside the account use AuthService.sendMagicLink.
  const client = clientId ? await getRegisteredClient(c.env, clientId) : null
  const confidential = !!client?.secret && client.tokenEndpointAuthMethod !== 'none'
  if (!client || !confidential || !clientSecret || !(await constantTimeEqual(clientSecret, client.secret!))) {
    return c.json(
      { error: 'invalid_client', error_description: 'A registered confidential client (client_id + client_secret) is required' },
      401,
      { 'WWW-Authenticate': 'Basic realm="id.org.ai"' },
    )
  }
  // ...and it must be listed: registration is open.
  if (!magicLinkClients(c.env).has(client.id)) {
    console.warn(JSON.stringify({ event: 'magic-link.client.refused', client: client.id }))
    return c.json({ error: 'unauthorized_client', error_description: 'This client is not enabled for magic-link sign-in' }, 403)
  }

  const result = await startMagicLink(
    c.env,
    { email: body.email || '', continue: body.continue || body.continue_url || '' },
    { kind: 'client', clientId: client.id },
  )
  if (!result.ok) {
    const headers: Record<string, string> = result.retryAfterSec ? { 'Retry-After': String(result.retryAfterSec) } : {}
    return c.json({ error: result.error, error_description: result.error_description }, result.status, headers)
  }
  return c.json({ sent: result.sent, verify_url: result.verify_url, expires_in: result.expires_in }, 202)
})

// ── The sign-in page ────────────────────────────────────────────────────────

async function loadFlow(env: Env, flowId: string): Promise<MagicFlow | null> {
  if (!/^[0-9a-f]{48}$/.test(flowId)) return null
  const flow = await storage(env).get<MagicFlow>(`magic-flow:${flowId}`)
  if (!flow) return null
  if (flow.expiresAt < Date.now()) {
    await endFlow(env, flowId)
    return null
  }
  return flow
}

function page(title: string, inner: string, status = 200, cookie?: string): Response {
  const html = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)} — id.org.ai</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,-apple-system,'Segoe UI',sans-serif;background:#000;color:#fff;min-height:100vh;display:flex;align-items:center;justify-content:center}
.c{width:100%;max-width:420px;padding:24px}
.b{font-size:14px;color:#666;margin-bottom:24px}
h1{font-size:26px;font-weight:600;margin-bottom:8px}
p{color:#999;line-height:1.5;margin-bottom:24px}
input{width:100%;padding:14px 16px;font-size:24px;letter-spacing:8px;text-align:center;background:#111;border:1px solid #333;border-radius:10px;color:#fff;margin-bottom:16px}
button,a.btn{display:block;width:100%;padding:14px;font-size:16px;font-weight:500;background:#fff;color:#000;border:0;border-radius:10px;cursor:pointer;text-align:center;text-decoration:none}
.e{color:#f87171;margin-bottom:16px}
</style></head><body><div class="c"><div class="b">id.org.ai</div>${inner}</div></body></html>`
  const headers = new Headers({ 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' })
  if (cookie) headers.append('Set-Cookie', cookie)
  return new Response(html, { status, headers })
}

function expiredPage(): Response {
  return page(
    'Link expired',
    `<h1>This sign-in link has expired</h1><p>Sign-in links last 10 minutes and work once. Ask for a new one, or sign in another way.</p><a class="btn" href="/login">Sign in</a>`,
    410,
  )
}

function codeForm(flowId: string, flow: MagicFlow, opts: { code?: string; error?: string } = {}): string {
  const code = opts.code && /^\d{6}$/.test(opts.code) ? opts.code : ''
  return `<h1>Check your email</h1>
<p>We sent a 6-digit sign-in code to <strong>${escapeHtml(maskEmail(flow.email))}</strong>. Enter it to continue.</p>
${opts.error ? `<div class="e">${escapeHtml(opts.error)}</div>` : ''}
<form method="POST" action="/magic-link/${escapeHtml(flowId)}">
<input name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required autofocus value="${escapeHtml(code)}" aria-label="Sign-in code">
<button type="submit">Sign in</button>
</form>`
}

app.get('/magic-link/:flow', async (c) => {
  const flowId = c.req.param('flow')
  const flow = await loadFlow(c.env, flowId)
  if (!flow) return expiredPage()
  // Bind the form to this browser: the POST must come from the browser that
  // opened this page (login-CSRF guard on top of the Origin check).
  const secure = new URL(c.req.url).protocol === 'https:'
  const cookie = `${FLOW_COOKIE}=${flowId}; Path=/magic-link; HttpOnly; SameSite=Strict; Max-Age=600${secure ? '; Secure' : ''}`
  return page('Sign in', codeForm(flowId, flow, { code: c.req.query('code') }), 200, cookie)
})

app.post('/magic-link/:flow', async (c) => {
  const clientId = c.env.WORKOS_CLIENT_ID
  const apiKey = c.env.WORKOS_API_KEY
  if (!clientId || !apiKey) return errorResponse(c, 503, ErrorCode.ServiceUnavailable, 'WorkOS is not configured')

  const flowId = c.req.param('flow')
  const flow = await loadFlow(c.env, flowId)
  if (!flow) return expiredPage()

  if (parseCookieValue(c.req.header('cookie') || '', FLOW_COOKIE) !== flowId) {
    return page('Sign in', codeForm(flowId, flow, { error: 'Open the sign-in link again in this browser, then enter your code.' }), 403)
  }

  const body = await readBody(c.req.raw)
  const code = (body.code || '').replace(/\s+/g, '')
  if (!/^\d{6}$/.test(code)) {
    return page('Sign in', codeForm(flowId, flow, { error: 'Enter the 6-digit code from the email.' }), 400)
  }

  // Count the attempt before asking WorkOS, atomically: the Durable Object
  // increments and checks in one call, so of N parallel guesses at most
  // MAX_CODE_ATTEMPTS reach WorkOS; the rest end the flow unasked.
  const attempt = await getStubForIdentity(c.env, 'oauth').consumeBudget({
    key: attemptsKey(flowId),
    max: MAX_CODE_ATTEMPTS,
    windowMs: FLOW_TTL_MS,
  })
  if (!attempt.allowed) {
    await endFlow(c.env, flowId)
    return expiredPage()
  }
  // ...and against this path's guess budget for the address and this IP's
  // guess budget, so new flows cannot buy more guesses.
  const reservation = await reserveCodeGuess(c.env, flow.email, clientIpOf(c.req.raw), 'ml')
  if (!reservation.ok) {
    const res = page('Sign in', codeForm(flowId, flow, { error: 'Too many attempts for this address. Ask for a new sign-in code, or try again later.' }), 429)
    res.headers.set('Retry-After', String(reservation.retryAfterSec))
    return res
  }

  let authResult: WorkOSAuthResult
  try {
    authResult = await authenticateWorkOSMagicAuth(clientId, apiKey, flow.email, code, {
      userAgent: c.req.header('user-agent'),
      ipAddress: c.req.header('cf-connecting-ip') || undefined,
    })
  } catch (err) {
    if (err && typeof err === 'object' && (err as { code?: unknown }).code === 'organization_selection_required') {
      // Hand over to the regular org picker → /api/org-select → /api/callback,
      // with a login state that remembers this was a magic link.
      await endFlow(c.env, flowId)
      await resetCodeGuesses(c.env, flow.email, 'ml')
      const csrf = crypto.randomUUID()
      const origin = requestOriginOf(c.req.url)
      await getStubForIdentity(c.env, 'oauth').oauthStorageOp({
        op: 'put',
        key: `login-csrf:${csrf}`,
        value: loginCsrfRecord(csrf, flow.continue, origin, 'magic_link'),
        options: { expirationTtl: 300 },
      })
      const state = encodeLoginState(csrf, flow.continue, origin, 'magic_link')
      return renderOrgPickerPage(err as OrgSelectionError, state)
    }
    const status = (err as { status?: number }).status
    if (status === 400 || status === 401 || status === 403 || status === 404) {
      if (attempt.count >= MAX_CODE_ATTEMPTS) {
        await endFlow(c.env, flowId)
        return expiredPage()
      }
      return page('Sign in', codeForm(flowId, flow, { error: 'That code is not valid or has expired.' }), 400)
    }
    console.error('[magic-link] WorkOS authenticate failed:', err instanceof Error ? err.message : err)
    return page('Sign in', codeForm(flowId, flow, { error: 'Sign-in is temporarily unavailable. Try again.' }), 502)
  }

  // One use: the flow is gone once it signs someone in.
  await endFlow(c.env, flowId)
  await resetCodeGuesses(c.env, flow.email, 'ml')

  const response = await finishWorkOSSignIn(c, authResult, { requestedProvider: 'magic_link', continueUrl: flow.continue })
  const out = new Response(response.body, response)
  const secure = new URL(c.req.url).protocol === 'https:'
  out.headers.append('Set-Cookie', `${FLOW_COOKIE}=; Path=/magic-link; HttpOnly; SameSite=Strict; Max-Age=0${secure ? '; Secure' : ''}`)
  return out
})

export { app as magicLinkRoutes }
