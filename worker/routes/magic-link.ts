/**
 * Magic-link sign-in for relying parties (a Startup's waitlist, api.sb, …).
 *
 *   POST /api/magic-link { email, continue, client_id }
 *     Caller: a registered confidential client (client_secret_basic or
 *     client_secret_post) or a service binding. Asks WorkOS Magic Auth to email
 *     the person a one-time sign-in code and opens a 10-minute sign-in flow.
 *     Answers 202 { sent, verify_url, expires_in } whether or not an account
 *     exists for that address (WorkOS creates the user when it is new).
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
 * Limits: 5 sends per email per hour, 100 per client (or binding host) per
 * hour, 5 code attempts per flow. Every counter is incremented and checked in
 * one Durable Object call (IdentityDO.consumeBudget), before the send or the
 * WorkOS check it guards, so parallel requests cannot overrun a budget.
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
import { resolveContinue, isServiceBindingRequest, getRegisteredClient } from '../utils/relying-parties'
import { finishWorkOSSignIn, loginCsrfRecord } from './auth'
import { renderOrgPickerPage } from '../views/org-picker'
import { escapeHtml } from '../utils/html'
import { parseCookieValue } from '../utils/cookies'

const app = new Hono<{ Bindings: Env; Variables: Variables }>()

/** Where the person completes the sign-in. */
const CANONICAL_ORIGIN = 'https://id.org.ai'
const DEFAULT_CONTINUE = '/dash/profile'
const FLOW_TTL_MS = 10 * 60 * 1000
const MAX_CODE_ATTEMPTS = 5
const EMAIL_LIMIT = { max: 5, windowMs: 60 * 60 * 1000 }
const CLIENT_LIMIT = { max: 100, windowMs: 60 * 60 * 1000 }
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

// ── POST /api/magic-link ─────────────────────────────────────────────────────

app.post('/api/magic-link', async (c) => {
  const apiKey = c.env.WORKOS_API_KEY
  if (!apiKey || !c.env.WORKOS_CLIENT_ID) {
    return errorResponse(c, 503, ErrorCode.ServiceUnavailable, 'WorkOS is not configured')
  }

  const body = await readBody(c.req.raw)
  const basic = parseBasicAuth(c.req.header('authorization'))
  const clientId = basic?.clientId || body.client_id || ''
  const clientSecret = basic?.clientSecret || body.client_secret || ''
  const viaBinding = isServiceBindingRequest(c.req.raw)

  // ── Caller authentication ─────────────────────────────────────────────
  // A confidential client proves itself with its secret. A service binding is
  // already inside the account; it may name a client (for its redirect
  // origins) but needs no secret.
  const client = clientId ? await getRegisteredClient(c.env, clientId) : null
  if (!viaBinding) {
    const confidential = !!client?.secret && client.tokenEndpointAuthMethod !== 'none'
    if (!client || !confidential || !clientSecret || !(await constantTimeEqual(clientSecret, client.secret!))) {
      return c.json(
        { error: 'invalid_client', error_description: 'A registered confidential client (client_id + client_secret) or a service binding is required' },
        401,
        { 'WWW-Authenticate': 'Basic realm="id.org.ai"' },
      )
    }
  } else if (clientId && !client) {
    return c.json({ error: 'invalid_client', error_description: 'Unknown client_id' }, 400)
  }

  // ── Input ─────────────────────────────────────────────────────────────
  const email = normalizeEmail(body.email || '')
  if (!isPlausibleEmail(email)) {
    return c.json({ error: 'invalid_request', error_description: 'email must be an email address' }, 400)
  }

  const rawContinue = body.continue || body.continue_url || ''
  let continueUrl = DEFAULT_CONTINUE
  if (rawContinue) {
    let accepted = await resolveContinue(c.env, rawContinue, { requestOrigin: CANONICAL_ORIGIN, clientId: client?.id })
    // A service binding may also continue to its own host.
    if (!accepted && viaBinding && !rawContinue.startsWith('/')) {
      accepted = await resolveContinue(c.env, rawContinue, { requestOrigin: new URL(c.req.url).origin })
    }
    if (!accepted) {
      return c.json(
        {
          error: 'invalid_request',
          error_description: "continue must be a relative path, an id.org.ai origin, or one of the client's registered redirect origins",
        },
        400,
      )
    }
    continueUrl = accepted
  }

  // ── Rate limits: per email, then per caller ──────────────────────────
  const callerKey = client?.id ?? `binding:${new URL(c.req.url).host}`
  const emailWait = await consumeBudget(c.env, `magiclink-rl:email:${email}`, EMAIL_LIMIT)
  const clientWait = emailWait ? 0 : await consumeBudget(c.env, `magiclink-rl:client:${callerKey}`, CLIENT_LIMIT)
  const wait = emailWait || clientWait
  if (wait) {
    return c.json(
      { error: 'rate_limited', error_description: emailWait ? 'Too many sign-in emails for this address; try later' : 'Too many sign-in emails from this client; try later' },
      429,
      { 'Retry-After': String(wait) },
    )
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
    return c.json({ error: 'temporarily_unavailable', error_description: 'Could not send the sign-in email; try again' }, 502)
  }
  if (!sent.ok) {
    if (sent.status >= 500 || sent.status === 429) {
      console.error(`[magic-link] WorkOS magic_auth failed: ${sent.status}`)
      return c.json({ error: 'temporarily_unavailable', error_description: 'Could not send the sign-in email; try again' }, 502)
    }
    console.warn(JSON.stringify({ event: 'magic-link.send.refused', status: sent.status, client: callerKey }))
  }

  const flowId = randomFlowId()
  const now = Date.now()
  await storage(c.env).put(`magic-flow:${flowId}`, {
    email,
    continue: continueUrl,
    ...(client ? { clientId: client.id } : {}),
    createdAt: now,
    expiresAt: now + FLOW_TTL_MS,
  } satisfies MagicFlow)

  return c.json(
    {
      sent: true,
      verify_url: `${CANONICAL_ORIGIN}/magic-link/${flowId}`,
      expires_in: FLOW_TTL_MS / 1000,
    },
    202,
  )
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
      const csrf = crypto.randomUUID()
      const origin = new URL(c.req.url).origin
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

  const response = await finishWorkOSSignIn(c, authResult, { requestedProvider: 'magic_link', continueUrl: flow.continue })
  const out = new Response(response.body, response)
  const secure = new URL(c.req.url).protocol === 'https:'
  out.headers.append('Set-Cookie', `${FLOW_COOKIE}=; Path=/magic-link; HttpOnly; SameSite=Strict; Max-Age=0${secure ? '; Secure' : ''}`)
  return out
})

export { app as magicLinkRoutes }
