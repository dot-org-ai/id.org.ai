/**
 * The device flow's pages (docs/product-update/spec/backend.md#b3, screens 4b–4d):
 *
 *   GET  /device                       4c (enter a code); with ?code= (or ?user_code=), 4b
 *   POST /device                       4c's submit: CSRF, then 303 to /device?code=XXXX-XXXX
 *   POST /device/decision              approve or deny. CSRF from the X-CSRF-Token header
 *                                      (the page's fetch) or the csrf field (a form post).
 *                                      JSON for the page's own fetch, else 303 to 4d
 *   GET  /device/done | /cancelled     4d, the results without JS
 *   GET  /device/:family/revoke        "Sign this device out?"; POST signs it out
 *
 * Every page needs a session: without one, sign in and come back (the code
 * survives the round trip). The decision itself is the provider's decideDevice.
 * The POSTs carry a page token bound to the person (worker/utils/page-csrf.ts),
 * and looking codes up or deciding them spends a guess budget per person and
 * per IP (RFC 8628 §5.1, security.md "Codes and budgets").
 */
import { Hono, type Context } from 'hono'
import type { Env, Variables } from '../types'
import { errorResponse, ErrorCode } from '../../src/sdk/errors'
import { formatUserCode, type DeviceRequestView } from '../../src/sdk/oauth/provider'
import { getOAuthProvider } from './oauth'
import { checkPageCsrf, issuePageCsrf } from '../utils/page-csrf'
import { personAccount, personWorkspaces } from '../utils/person'
import { getStubForIdentity, readSessionOrgId } from '../middleware/tenant'
import { renderPage } from '../ui/render'
import { renderErrorPage } from '../ui/errors'
import { deviceClientName, deviceConfirmProps, deviceWhere } from '../ui/device-props'
import { DeviceConfirm } from '../ui/screens/DeviceConfirm'
import { DeviceEntry } from '../ui/screens/DeviceEntry'
import { DeviceDone } from '../ui/screens/DeviceDone'
import { DeviceSignOut } from '../ui/screens/DeviceSignOut'

type C = Context<{ Bindings: Env; Variables: Variables }>

export const deviceRoutes = new Hono<{ Bindings: Env; Variables: Variables }>()

const BAD_CODE = 'That code is invalid or has expired. Check your terminal for the current code.'
const TERMINAL = { kind: 'icon', icon: 'terminal' } as const

function identityOf(c: C): string | null {
  const auth = c.get('auth')
  return auth?.authenticated ? (auth.identityId ?? null) : null
}

/** Sign in, then come back here (a relative continue, so local development stays local). */
function signInFirst(c: C): Response {
  const u = new URL(c.req.url)
  return c.redirect(`/login?continue=${encodeURIComponent(u.pathname + u.search)}`, 302)
}

/** The page's own fetch (fetch-form) asks for JSON; only it may read the answer (as consent, phase 5 review S3). */
function wantsJson(c: C): boolean {
  return (c.req.header('accept') ?? '').includes('application/json') && c.req.header('sec-fetch-site') === 'same-origin'
}

async function formFields(c: C): Promise<{ get(name: string): string | undefined; all(name: string): string[] }> {
  const form = await c.req.raw
    .clone()
    .formData()
    .catch(() => new FormData())
  return {
    get: (name) => (typeof form.get(name) === 'string' ? (form.get(name) as string) : undefined),
    all: (name) => form.getAll(name).filter((v): v is string => typeof v === 'string'),
  }
}

async function withCsrf(c: C, identityId: string, render: (csrf: string) => Promise<Response>): Promise<Response> {
  return render(await issuePageCsrf(c, identityId))
}

/** The page token from the X-CSRF-Token header or the csrf field; both at once is refused (security.md: no duplicates). */
function submittedCsrf(c: C, field: string | undefined): string | undefined {
  const header = c.req.header('x-csrf-token')
  if (header && field) return undefined
  return header ?? field
}

const GUESS_WINDOW_MS = 15 * 60 * 1000

/**
 * Looking a code up or deciding one spends a guess budget, per person and per
 * IP (phase 6 review S3): user codes are short, so guessing must be slow.
 * Answers the seconds to wait when it's spent, else null.
 */
async function guessBudgetSpent(c: C, identityId: string): Promise<number | null> {
  const stub = getStubForIdentity(c.env, 'oauth')
  const ip = c.req.header('cf-connecting-ip') ?? 'no-ip'
  const [byPerson, byIp] = await Promise.all([
    stub.consumeBudget({ key: `device-guess:id:${identityId}`, max: 30, windowMs: GUESS_WINDOW_MS }),
    stub.consumeBudget({ key: `device-guess:ip:${ip}`, max: 60, windowMs: GUESS_WINDOW_MS }),
  ])
  if (byPerson.allowed && byIp.allowed) return null
  return Math.max(byPerson.retryAfterSec, byIp.retryAfterSec, 60)
}

function tooManyTries(c: C, retryAfterSeconds: number, json = false): Response | Promise<Response> {
  if (json) {
    c.header('Retry-After', String(retryAfterSeconds))
    return c.json({ ok: false, error: 'rate_limited' }, 429)
  }
  return renderErrorPage(c, 'rate_limited', { requestId: c.get('requestId'), retryAfterSeconds }, 429).then((res) => {
    res.headers.set('Retry-After', String(retryAfterSeconds))
    return res
  })
}

function entryPage(c: C, identityId: string, extra: { value?: string; error?: string } = {}): Promise<Response> {
  return withCsrf(c, identityId, (csrf) =>
    renderPage(c, DeviceEntry({ action: '/device', csrf, ...extra }), {
      title: 'Connect a device · id.org.ai',
      scripts: ['code-input.js', 'submit.js'],
      ...(extra.error && { status: 400 }),
    }),
  )
}

async function confirmPage(c: C, view: DeviceRequestView, identityId: string): Promise<Response> {
  const [account, workspaces, sessionOrg] = await Promise.all([personAccount(c.env, identityId), personWorkspaces(c.env, identityId), readSessionOrgId(c.req.raw, c.env)])
  const here = new URL(c.req.url)
  return withCsrf(c, identityId, (csrf) => {
    const props = deviceConfirmProps(view, {
      account,
      workspaces,
      ...(sessionOrg && workspaces.some((w) => w.id === sessionOrg) && { selectedOrgId: sessionOrg }),
      switchHref: `/login?prompt=login&continue=${encodeURIComponent(here.pathname + here.search)}`,
      requestId: c.get('requestId'),
      csrf,
      now: Date.now(),
    })
    return renderPage(c, DeviceConfirm(props), { title: `Confirm ${props.client.name} · id.org.ai`, scripts: ['fetch-form.js'] })
  })
}

function expiredPage(c: C, used = false): Promise<Response> {
  return renderErrorPage(c, used ? 'already_used' : 'expired', { requestId: c.get('requestId'), expired: { what: 'device code' }, startHref: '/device' }, used ? 409 : 410)
}

function codeParam(c: C): string | undefined {
  return c.req.query('code') || c.req.query('user_code') || undefined
}

// ── 4c / 4b ────────────────────────────────────────────────────────────────

deviceRoutes.get('/device', async (c) => {
  const identityId = identityOf(c)
  if (!identityId) return signInFirst(c)
  const code = codeParam(c)
  if (!code) return entryPage(c, identityId)
  const wait = await guessBudgetSpent(c, identityId)
  if (wait !== null) return tooManyTries(c, wait)
  const view = await getOAuthProvider(c).getDeviceRequest(code)
  if (!view) return entryPage(c, identityId, { value: code, error: BAD_CODE })
  if (view.status === 'expired') return expiredPage(c)
  if (view.status === 'pending') return confirmPage(c, view, identityId)
  // Decided already: the person who decided sees the result; anyone else, "already used".
  if (view.status === 'denied') return c.redirect(`/device/cancelled?code=${view.userCode}`, 303)
  if (view.identityId === identityId) return c.redirect(`/device/done?code=${view.userCode}`, 303)
  return expiredPage(c, true)
})

deviceRoutes.post('/device', async (c) => {
  const identityId = identityOf(c)
  if (!identityId) return signInFirst(c)
  const form = await formFields(c)
  if (!(await checkPageCsrf(c, submittedCsrf(c, form.get('csrf')), identityId))) return errorResponse(c, 403, ErrorCode.Forbidden, 'Invalid or expired CSRF token')
  const wait = await guessBudgetSpent(c, identityId)
  if (wait !== null) return tooManyTries(c, wait)
  const typed = form.all('code').join('')
  const view = await getOAuthProvider(c).getDeviceRequest(typed)
  if (!view) return entryPage(c, identityId, { value: typed, error: BAD_CODE })
  return c.redirect(`/device?code=${view.userCode}`, 303)
})

// ── The decision ───────────────────────────────────────────────────────────

deviceRoutes.post('/device/decision', async (c) => {
  const identityId = identityOf(c)
  const json = wantsJson(c)
  if (!identityId) return json ? c.json({ ok: false, error: 'unauthenticated' }, 401) : errorResponse(c, 401, ErrorCode.Unauthorized, 'Sign in to confirm a device')
  const form = await formFields(c)
  if (!(await checkPageCsrf(c, submittedCsrf(c, form.get('csrf')), identityId))) {
    return json ? c.json({ ok: false, error: 'csrf' }, 403) : errorResponse(c, 403, ErrorCode.Forbidden, 'Invalid or expired CSRF token')
  }
  const wait = await guessBudgetSpent(c, identityId)
  if (wait !== null) return tooManyTries(c, wait, json)
  const decision = form.get('decision')
  if (decision !== 'approve' && decision !== 'deny') {
    return json ? c.json({ ok: false, error: 'invalid_request' }, 400) : errorResponse(c, 400, ErrorCode.InvalidRequest, 'decision must be approve or deny')
  }
  const code = form.get('code') ?? ''
  const result = await getOAuthProvider(c).decideDevice({ code, identityId, decision, ...(form.get('org_id') && { orgId: form.get('org_id') }) })
  if (json) {
    c.header('Cache-Control', 'no-store')
    return result.ok ? c.json({ ok: true, state: result.state }) : c.json({ ok: false, error: result.error }, 400)
  }
  if (result.ok) return c.redirect(`/device/${result.state === 'approved' ? 'done' : 'cancelled'}?code=${formatUserCode(code.toUpperCase().replace(/[\s-]/g, ''))}`, 303)
  if (result.error === 'invalid_org') return errorResponse(c, 400, ErrorCode.InvalidRequest, 'That workspace isn’t one of yours')
  return expiredPage(c, result.error === 'already_used')
})

// ── 4d: the results without JS ─────────────────────────────────────────────

deviceRoutes.get('/device/done', async (c) => {
  const identityId = identityOf(c)
  if (!identityId) return signInFirst(c)
  const view = await getOAuthProvider(c).getDeviceRequest(codeParam(c) ?? '')
  if (!view) return expiredPage(c)
  if (view.status === 'pending') return c.redirect(`/device?code=${view.userCode}`, 303)
  // A reload re-reads the state (motion.md): a denied code shows its cancelled page.
  if (view.status === 'denied') return c.redirect(`/device/cancelled?code=${view.userCode}`, 303)
  if ((view.status !== 'approved' && view.status !== 'collected') || view.identityId !== identityId) return expiredPage(c, true)
  const [account, workspaces] = await Promise.all([personAccount(c.env, identityId), personWorkspaces(c.env, identityId)])
  const { name } = deviceClientName(view)
  const props = {
    client: { name, tile: TERMINAL },
    account: { email: account.email },
    workspace: { name: workspaces.find((w) => w.id === view.orgId)?.name ?? '' },
    device: deviceWhere(view.meta),
    revokeHref: `/device/${encodeURIComponent(view.family)}/revoke`,
  }
  return renderPage(c, DeviceDone(props), { title: `${name} is signed in · id.org.ai` })
})

deviceRoutes.get('/device/cancelled', async (c) => {
  const identityId = identityOf(c)
  if (!identityId) return signInFirst(c)
  const view = await getOAuthProvider(c).getDeviceRequest(codeParam(c) ?? '')
  if (!view) return expiredPage(c)
  if (view.status === 'pending') return c.redirect(`/device?code=${view.userCode}`, 303)
  if ((view.status === 'approved' || view.status === 'collected') && view.identityId === identityId) return c.redirect(`/device/done?code=${view.userCode}`, 303)
  if (view.status !== 'denied') return expiredPage(c, true)
  const { name, cliName } = deviceClientName(view)
  return renderPage(c, DeviceDone({ outcome: 'cancelled', client: { name, tile: TERMINAL }, cliName }), { title: 'Sign-in cancelled · id.org.ai' })
})

// ── Sign this device out ───────────────────────────────────────────────────

async function signOutPage(c: C, identityId: string, state: 'confirm' | 'done'): Promise<Response> {
  const family = c.req.param('family') ?? ''
  const grant = await getOAuthProvider(c).getDeviceGrant(family, identityId)
  if (!grant) return renderErrorPage(c, 'not_found', { requestId: c.get('requestId') }, 404)
  const name = grant.client.trusted ? grant.client.name : (grant.client.host ?? 'An unverified app')
  const device = deviceWhere(grant.meta) || undefined
  const base = { client: { name, tile: TERMINAL }, ...(device && { device }), action: `/device/${encodeURIComponent(family)}/revoke`, cancelHref: '/' }
  if (state === 'done') return renderPage(c, DeviceSignOut({ ...base, state, csrf: '' }), { title: 'Device signed out · id.org.ai' })
  return withCsrf(c, identityId, (csrf) => renderPage(c, DeviceSignOut({ ...base, state, csrf }), { title: 'Sign this device out · id.org.ai', scripts: ['submit.js'] }))
}

deviceRoutes.get('/device/:family/revoke', async (c) => {
  const identityId = identityOf(c)
  if (!identityId) return signInFirst(c)
  return signOutPage(c, identityId, 'confirm')
})

deviceRoutes.post('/device/:family/revoke', async (c) => {
  const identityId = identityOf(c)
  if (!identityId) return errorResponse(c, 401, ErrorCode.Unauthorized, 'Sign in to sign a device out')
  const form = await formFields(c)
  if (!(await checkPageCsrf(c, submittedCsrf(c, form.get('csrf')), identityId))) return errorResponse(c, 403, ErrorCode.Forbidden, 'Invalid or expired CSRF token')
  const page = await signOutPage(c, identityId, 'done')
  if (page.status !== 200) return page
  await getOAuthProvider(c).revokeDeviceGrant(c.req.param('family') ?? '', identityId)
  return page
})
