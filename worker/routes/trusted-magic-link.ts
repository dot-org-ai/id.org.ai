/**
 * Headless sign-in links for trusted-account apps (ADR-0007; the Fund I deck
 * at pitch.startups.studio first). Nothing of id.org.ai's is shown: no
 * picker, no email form, no consent, no page in between.
 *
 *   POST /oauth/magic-link   { email, client_id, redirect_uri, state,
 *                              code_challenge, code_challenge_method, scope?,
 *                              nonce? }   JSON or form
 *     Caller: the app's server (or a page of its own). The authorize
 *     parameters are checked as /oauth/authorize checks them, for the
 *     trusted-account client only (cid_trusted_account_v1, an allowlisted
 *     redirect_uri, S256 PKCE). id.org.ai emails the address a sign-in link
 *     from the app's sender, naming the app (TRUSTED_ACCOUNT_APPS), and
 *     answers 202 { sent, expires_in } whether or not an account exists.
 *
 *   GET /oauth/magic-link/:token
 *     The link. Once, within LINK_TTL_MS: finds or creates the person's
 *     account (the open link proves the address), issues the authorization
 *     code and redirects to the app's redirect_uri with code, state and iss.
 *     A used, expired or unknown link answers the app's redirect_uri with
 *     error=access_denied when the token still names one, else a plain 410:
 *     never an id.org.ai page.
 *
 * Binding: the link is not bound to the browser that asked. It is commonly
 * opened on a phone from a request made on a desktop, so it works on any
 * device; whoever opens it is signed in to the app as that address. The code
 * it carries is PKCE-bound: only the app holding the verifier for that
 * request's code_challenge can redeem it, and the app decides how its state
 * is kept (pitch seals the verifier into the state itself, so its callback
 * works on the phone too).
 *
 * Limits: the link lasts 15 minutes and works once (taken atomically, one
 * Durable Object call). Sends: 5 per address per hour (code-guard's 'tml'
 * path, apart from magic-link's), 100 per caller IP per hour, 300 per app host
 * per hour. The app limits its own readers by IP before it calls.
 *
 * Not covered: a link opened by a mail scanner before the person clicks it is
 * spent (the person asks for another). The sign-in is id.org.ai's own email
 * proof, so a WorkOS MFA or SSO requirement on the account is not applied to
 * it; the code it yields is only for the trusted app.
 */
import { Hono, type Context } from 'hono'
import type { Env, Variables } from '../types'
import { getStubForIdentity } from '../middleware/tenant'
import { getOAuthProvider } from './oauth'
import type { TrustedGrant } from '../../src/sdk/oauth/provider'
import { findOrCreateVerifiedWorkOSUser } from '../../src/sdk/workos/upstream'
import { ensureHumanIdentity } from './auth'
import { clientIpOf, reserveCodeSend } from '../utils/code-guard'
import { signInLinkEmail } from '../ui/emails/SignInLink'
import { renderEmail } from '../ui/emails/layout'
import { isLocalStubOrigin } from '../../src/sdk/workos/base'
import { requestOriginOf } from '../utils/relying-parties'

type C = Context<{ Bindings: Env; Variables: Variables }>

const app = new Hono<{ Bindings: Env; Variables: Variables }>()

const CANONICAL_ORIGIN = 'https://id.org.ai'
export const LINK_TTL_MS = 15 * 60 * 1000
const IP_LIMIT = { max: 100, windowMs: 60 * 60 * 1000 }
const HOST_LIMIT = { max: 300, windowMs: 60 * 60 * 1000 }

interface LinkRecord {
  email: string
  grant: TrustedGrant
  createdAt: number
  expiresAt: number
}

const normalizeEmail = (email: string) => email.trim().toLowerCase()
const isPlausibleEmail = (email: string) => email.length <= 320 && /^[^\s@<>"']+@[^\s@<>".]+(\.[^\s@<>".]+)+$/.test(email)

function randomToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32))
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** Stored under the token's hash, so a storage read never yields a working link. */
async function linkKey(token: string): Promise<string> {
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token)))
  return `trusted-link:${Array.from(hash, (b) => b.toString(16).padStart(2, '0')).join('')}`
}

async function readBody(c: C): Promise<Record<string, string>> {
  const type = c.req.header('content-type') || ''
  try {
    if (type.includes('application/json')) {
      const json = (await c.req.json()) as Record<string, unknown>
      return Object.fromEntries(Object.entries(json).filter(([, v]) => typeof v === 'string')) as Record<string, string>
    }
    const form = await c.req.raw.formData()
    const out: Record<string, string> = {}
    for (const [k, v] of form.entries()) if (typeof v === 'string') out[k] = v
    return out
  } catch {
    return {}
  }
}

const budget = async (env: Env, key: string, limit: { max: number; windowMs: number }) => {
  const r = await getStubForIdentity(env, 'oauth').consumeBudget({ key, max: limit.max, windowMs: limit.windowMs })
  return r.allowed ? 0 : Math.max(1, r.retryAfterSec ?? 1)
}

/** id.org.ai; or, in local development against the WorkOS stub, this server (as the OAuth issuer is). */
const linkOrigin = (c: C) => {
  const here = requestOriginOf(c.req.url)
  return isLocalStubOrigin(c.env, here) ? here : CANONICAL_ORIGIN
}

type TrustedApps = NonNullable<Env['TRUSTED_ACCOUNT_APPS']>
/** TRUSTED_ACCOUNT_APPS: an object in wrangler.jsonc, or the same as a JSON string (.dev.vars, --var). */
function trustedApps(env: Env): TrustedApps {
  const v = env.TRUSTED_ACCOUNT_APPS as TrustedApps | string | undefined
  if (!v) return {}
  if (typeof v !== 'string') return v
  try {
    return JSON.parse(v) as TrustedApps
  } catch {
    return {}
  }
}

const fail = (c: C, status: 400 | 429 | 502 | 503, error: string, description: string, retryAfter?: number) =>
  c.json({ error, error_description: description }, status, { 'Cache-Control': 'no-store', ...(retryAfter ? { 'Retry-After': String(retryAfter) } : {}) })

app.post('/oauth/magic-link', async (c) => {
  if (!c.env.WORKOS_API_KEY || !c.env.EMAIL) return fail(c, 503, 'temporarily_unavailable', 'Sign-in links are not configured')
  const body = await readBody(c)

  const provider = getOAuthProvider(c)
  const checked = await provider.checkTrustedAuthorize({
    clientId: body.client_id || '',
    redirectUri: body.redirect_uri || '',
    responseType: body.response_type,
    scope: body.scope,
    state: body.state,
    codeChallenge: body.code_challenge,
    codeChallengeMethod: body.code_challenge_method,
    nonce: body.nonce,
  })
  if (!checked.ok) return fail(c, 400, checked.error, checked.description)
  const { grant } = checked

  const email = normalizeEmail(body.email || '')
  if (!isPlausibleEmail(email)) return fail(c, 400, 'invalid_request', 'email must be an email address')

  // Per address (its own path), then per caller IP, then per app host.
  const byEmail = await reserveCodeSend(c.env, email, 'tml')
  const wait =
    (byEmail.ok ? 0 : byEmail.retryAfterSec) ||
    (await budget(c.env, `trusted-link-rl:ip:${clientIpOf(c.req.raw)}`, IP_LIMIT)) ||
    (await budget(c.env, `trusted-link-rl:host:${grant.host}`, HOST_LIMIT))
  if (wait) return fail(c, 429, 'rate_limited', 'Too many sign-in emails; try again later', wait)

  const token = randomToken()
  const key = await linkKey(token)
  const now = Date.now()
  const oauth = getStubForIdentity(c.env, 'oauth')
  await oauth.oauthStorageOp({ op: 'put', key, value: { email, grant, createdAt: now, expiresAt: now + LINK_TTL_MS } satisfies LinkRecord })

  const appInfo = trustedApps(c.env)[grant.host]
  const message = renderEmail(
    signInLinkEmail({
      url: `${linkOrigin(c)}/oauth/magic-link/${token}`,
      app: appInfo?.name ?? 'your app',
      email,
      expiresInMinutes: LINK_TTL_MS / 60000,
      ...(appInfo?.from ? { from: appInfo.from } : {}),
    }),
  )
  try {
    await c.env.EMAIL.send({ from: message.from, to: email, subject: message.subject, html: message.html, text: message.text })
  } catch (err) {
    await oauth.oauthStorageOp({ op: 'delete', key })
    console.error(JSON.stringify({ event: 'trusted-link.send.failed', host: grant.host, code: (err as { code?: unknown })?.code ?? String(err) }))
    return fail(c, 502, 'temporarily_unavailable', 'Could not send the sign-in email; try again')
  }
  return c.json({ sent: true, expires_in: LINK_TTL_MS / 1000 }, 202, { 'Cache-Control': 'no-store' })
})

/** The app's redirect_uri with an OAuth error (only an allowlisted one), or a plain 410. */
function refuse(c: C, grant: TrustedGrant | undefined, description: string): Response {
  const provider = getOAuthProvider(c)
  if (grant && provider.isTrustedRedirect(grant.redirectUri)) {
    const to = new URL(grant.redirectUri)
    to.searchParams.set('error', 'access_denied')
    to.searchParams.set('error_description', description)
    if (grant.state) to.searchParams.set('state', grant.state)
    to.searchParams.set('iss', CANONICAL_ORIGIN)
    return new Response(null, { status: 302, headers: { Location: to.toString(), 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' } })
  }
  return c.text('This sign-in link has expired or was already used. Ask for a new one.', 410, { 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' })
}

app.get('/oauth/magic-link/:token', async (c) => {
  const token = c.req.param('token')
  if (!/^[A-Za-z0-9_-]{43}$/.test(token)) return refuse(c, undefined, 'link_invalid')
  // Taken in one Durable Object call: a link works once, even opened twice at once.
  const { value } = await getStubForIdentity(c.env, 'oauth').takeOnce({ key: await linkKey(token) })
  const rec = value as LinkRecord | undefined
  if (!rec) return refuse(c, undefined, 'link_used_or_unknown')
  if (rec.expiresAt < Date.now()) return refuse(c, rec.grant, 'link_expired')
  if (!c.env.WORKOS_API_KEY) return refuse(c, rec.grant, 'temporarily_unavailable')

  let identityId: string
  try {
    const user = await findOrCreateVerifiedWorkOSUser(c.env.WORKOS_API_KEY, rec.email)
    const { shardKey } = await ensureHumanIdentity(c.env, user, { organizationId: user.organization_id })
    identityId = shardKey
  } catch (err) {
    console.error(JSON.stringify({ event: 'trusted-link.account.failed', host: rec.grant.host, error: err instanceof Error ? err.message : String(err) }))
    return refuse(c, rec.grant, 'temporarily_unavailable')
  }

  const issued = await getOAuthProvider(c).issueTrustedCode(identityId, rec.grant, {
    amr: ['magic_link'],
    idp: 'id.org.ai',
    authTime: Math.floor(Date.now() / 1000),
  })
  if (!issued) return refuse(c, undefined, 'app_not_trusted')
  const out = new Response(null, issued)
  out.headers.set('Cache-Control', 'no-store')
  out.headers.set('Referrer-Policy', 'no-referrer')
  return out
})

export { app as trustedMagicLinkRoutes }
