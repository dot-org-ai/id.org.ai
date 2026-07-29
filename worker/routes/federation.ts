/**
 * Upstream federation routes — id.org.ai as the broker.
 *
 * Two ways in, one way out:
 *
 *   GET  /federation/microsoft/start      → Entra (multi-tenant, PKCE)
 *   GET  /federation/microsoft/callback   ← Entra
 *   GET  /federation/email                → the fallback page
 *   POST /federation/email/send           → put a code in the mailbox
 *   POST /federation/email/verify         → check it
 *   GET  /federation/status               → which paths are live (JSON)
 *
 * "One way out" is the load-bearing part: both paths end at
 * `issueFederatedSession`, which writes/refreshes ONE identity row shape and
 * signs ONE id.org.ai JWT into the standard `auth` cookie. Downstream
 * consumers (the deck gate) verify an id.org.ai token via `POST /auth/verify`
 * and never learn which upstream was used, except through the honest
 * `fed.assurance` claim.
 *
 * Mounted BEFORE `authenticateRequest` — these routes establish auth, so they
 * cannot require it.
 */
import { Hono } from 'hono'
import type { Env, Variables } from '../types'
import { errorResponse, ErrorCode } from '../../src/sdk/errors'
import { getStubForIdentity, getSigningKeyManager } from '../middleware/tenant'
import { buildAuthCookieHeaders, getRootDomain } from '../utils/cookies'
import {
  startMicrosoftAuth,
  exchangeMicrosoftCode,
  verifyMicrosoftIdToken,
  microsoftPrincipal,
  classifyMicrosoftError,
  isMicrosoftConfigured,
  MICROSOFT_DEFAULT_TENANT,
} from '../../src/sdk/federation/microsoft'
import type { MicrosoftAuthState, MicrosoftConfig, MicrosoftVerifyDeps } from '../../src/sdk/federation/microsoft'
import {
  workosMagicAuthChannel,
  emailCodePrincipal,
  allowEmailCodeSend,
  isPlausibleEmail,
  isPlausibleCode,
  normalizeEmail,
} from '../../src/sdk/federation/email-code'
import type { ThrottleStore } from '../../src/sdk/federation/email-code'
import { FederationError, levelCeilingForAssurance } from '../../src/sdk/federation/types'
import type { FederatedPrincipal } from '../../src/sdk/federation/types'
import { renderEmailCodePage } from '../views/email-code'

/**
 * Injectable seams. Mirrors `createAuthVerifyApp(resolveJwks)` in
 * routes/auth-verify.ts — the same problem (a route that must reach an
 * external key set) gets the same shape of answer, so the callback can be
 * driven hermetically in tests while production uses the real JWKS.
 */
export interface FederationAppDeps {
  /** Overrides Microsoft JWKS resolution. Undefined = fetch the real one. */
  microsoftVerify?: MicrosoftVerifyDeps
}

/**
 * All federation transactions live in ONE DO shard. They are short-lived
 * (10 min), low-volume (a sign-in, not a request), and keeping them together
 * means the callback can find the transaction without knowing who the user is
 * yet — which it cannot, since that is what the callback is for.
 */
const FEDERATION_SHARD = 'federation'

/** Session lifetime for a federated viewer. Shorter than the 30-day WorkOS
 * cookie: a deck viewer is a guest, not a tenant member. */
const SESSION_TTL_SEC = 12 * 60 * 60

// ── Config ────────────────────────────────────────────────────────────────

/**
 * Build the Microsoft config for this request.
 *
 * The redirect URI is pinned to the CANONICAL origin, never the request's own
 * origin: Entra matches redirect URIs verbatim against the app registration,
 * so accepting whatever host the request arrived on would either fail or (with
 * a wildcard registration, which Entra does not allow anyway) be an open
 * redirect. Same discipline as the WorkOS callback in routes/auth.ts.
 */
const CANONICAL_ORIGINS = ['https://id.org.ai', 'https://oauth.dotdo.workers.dev']

export function microsoftConfigFor(env: Env, requestUrl: string): MicrosoftConfig | undefined {
  if (!env.MICROSOFT_CLIENT_ID) return undefined
  const requestOrigin = new URL(requestUrl).origin
  const origin = CANONICAL_ORIGINS.includes(requestOrigin) ? requestOrigin : 'https://id.org.ai'
  return {
    clientId: env.MICROSOFT_CLIENT_ID,
    clientSecret: env.MICROSOFT_CLIENT_SECRET,
    redirectUri: `${origin}/federation/microsoft/callback`,
    tenant: env.MICROSOFT_TENANT || MICROSOFT_DEFAULT_TENANT,
  }
}

function allowedTenants(env: Env): string[] | undefined {
  const raw = env.MICROSOFT_ALLOWED_TENANTS?.trim()
  if (!raw) return undefined
  const list = raw
    .split(',')
    .map((t) => t.trim())
    .filter(Boolean)
  return list.length ? list : undefined
}

/**
 * Where a completed sign-in may send the browser.
 *
 * Deliberately STRICTER than the shared `isSafeRedirectUrl`, which accepts any
 * http(s) URL. That is tolerable on `/login` (long-standing behaviour, and the
 * cookie is set on the id.org.ai root domain either way), but these routes are
 * the ones a stranger can drive with a crafted link: `.../start?continue=…`
 * followed by a real sign-in would bounce a genuinely-authenticated viewer to
 * an attacker's page with our brand on the referrer. So:
 *
 *   - relative paths (not protocol-relative `//evil`) — always fine
 *   - absolute URLs — only to an allow-listed host
 *   - anything else — silently becomes `/`
 *
 * The allow-list is `*.org.ai` plus whatever `FEDERATION_CONTINUE_HOSTS`
 * names, which is how a consumer surface (a deck gate on its own domain) opts
 * in. Adding a host is a config change, reviewable, not a code change.
 */
export function safeContinue(raw: string | undefined, env: Env): string {
  const url = (raw ?? '').trim()
  if (!url) return '/'
  if (url.startsWith('/') && !url.startsWith('//')) return url

  let parsed: URL
  try {
    parsed = new URL(url)
  } catch {
    return '/'
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return '/'

  const host = parsed.hostname.toLowerCase()
  const extra = (env.FEDERATION_CONTINUE_HOSTS ?? '')
    .split(',')
    .map((h) => h.trim().toLowerCase())
    .filter(Boolean)

  const allowed = host === 'org.ai' || host.endsWith('.org.ai') || extra.includes(host)
  return allowed ? url : '/'
}

function emailChannelFor(env: Env) {
  if (!env.WORKOS_API_KEY || !env.WORKOS_CLIENT_ID) return undefined
  return workosMagicAuthChannel({ apiKey: env.WORKOS_API_KEY, clientId: env.WORKOS_CLIENT_ID })
}

// ── Transaction + throttle storage (DO-backed) ────────────────────────────

/**
 * DO storage has no native TTL — `oauthStorageOp`'s `expirationTtl` is
 * accepted and ignored. So every stored transaction carries its own
 * `expiresAt` and is validated on read. Getting this wrong would leave PKCE
 * verifiers replayable forever.
 */
async function putTransaction(env: Env, state: string, tx: MicrosoftAuthState): Promise<void> {
  const stub = getStubForIdentity(env, FEDERATION_SHARD)
  await stub.oauthStorageOp({ op: 'put', key: `fed-ms-tx:${state}`, value: tx })
}

async function takeTransaction(env: Env, state: string): Promise<MicrosoftAuthState | null> {
  const stub = getStubForIdentity(env, FEDERATION_SHARD)
  const stored = await stub.oauthStorageOp({ op: 'get', key: `fed-ms-tx:${state}` })
  // Single-use: consumed whether or not it turns out to be valid, so a leaked
  // state value cannot be retried.
  await stub.oauthStorageOp({ op: 'delete', key: `fed-ms-tx:${state}` })
  const tx = stored.value as MicrosoftAuthState | undefined
  if (!tx) return null
  if (typeof tx.expiresAt !== 'number' || tx.expiresAt < Date.now()) return null
  return tx
}

function throttleStoreFor(env: Env): ThrottleStore {
  const stub = getStubForIdentity(env, FEDERATION_SHARD)
  return {
    async get(key) {
      const stored = await stub.oauthStorageOp({ op: 'get', key })
      return stored.value as { count: number; windowStartedAt: number } | undefined
    },
    async put(key, value) {
      await stub.oauthStorageOp({ op: 'put', key, value })
    },
  }
}

// ── The single exit: mint an id.org.ai identity + session ─────────────────

/**
 * Write (or refresh) the federated identity row and set the `auth` cookie.
 *
 * The JWT `sub` is the identity id WITHOUT its `human:` prefix, because
 * `resolveIdentityId` (worker/middleware/tenant.ts) reconstitutes the shard key
 * as `human:${sub}`. So `sub = 'ms:<tid>:<oid>'` round-trips to
 * `human:ms:<tid>:<oid>` — the DO shard the row actually lives in. Deviating
 * from this convention would mint tokens that verify but resolve to nothing.
 */
async function issueFederatedSession(
  env: Env,
  requestUrl: string,
  principal: FederatedPrincipal,
  continueUrl: string,
): Promise<Response> {
  const identityId = principal.identityId
  const stub = getStubForIdentity(env, identityId)
  const level = levelCeilingForAssurance(principal.provenance.assurance)

  const existing = await stub.getIdentity(identityId).catch(() => null)
  const row = {
    id: identityId,
    type: 'human' as const,
    name: principal.name,
    email: principal.email,
    // The email WAS verified — by the upstream IdP, or by the code round-trip.
    verified: true,
    level,
    claimStatus: 'claimed' as const,
    federation: principal.provenance,
    createdAt: (existing as { createdAt?: number } | null)?.createdAt ?? Date.now(),
    updatedAt: Date.now(),
  }
  // Written through raw storage rather than createIdentity/update because the
  // service enforces level monotonicity and email uniqueness — both correct for
  // tenant identities, both wrong here: a viewer who falls back from Entra to
  // email codes must be able to move DOWN a level, and the same mailbox
  // legitimately appears under two different principals (one per upstream).
  // The broker's assurance clamp is what keeps that honest at read time.
  await stub.oauthStorageOp({ op: 'put', key: `identity:${identityId}`, value: row })

  const signingManager = getSigningKeyManager(env)
  const jwt = await signingManager.sign(
    {
      sub: identityId.replace(/^human:/, ''),
      email: principal.email,
      name: principal.name,
      fed: {
        provider: principal.provenance.provider,
        assurance: principal.provenance.assurance,
        tenantId: principal.provenance.tenantId,
        emailDomain: principal.provenance.emailDomain,
        issuer: principal.provenance.issuer,
        verifiedAt: principal.provenance.verifiedAt,
      },
    },
    { issuer: 'https://id.org.ai', expiresIn: SESSION_TTL_SEC },
  )

  const reqUrl = new URL(requestUrl)
  const isSecure = reqUrl.protocol === 'https:'
  const domain = getRootDomain(reqUrl.hostname)
  const cookieHeaders = buildAuthCookieHeaders(jwt, { secure: isSecure, domain, maxAge: SESSION_TTL_SEC })

  const headers = new Headers({ Location: safeContinue(continueUrl, env) })
  for (const cookie of cookieHeaders) headers.append('Set-Cookie', cookie)
  return new Response(null, { status: 302, headers })
}

// ── The app ───────────────────────────────────────────────────────────────

export function createFederationApp(deps: FederationAppDeps = {}) {
  const app = new Hono<{ Bindings: Env; Variables: Variables }>()

// ── GET /federation/status ────────────────────────────────────────────────
// Lets a downstream gate (and the smoke test) discover which paths are live
// without attempting a sign-in. No secrets — booleans and the redirect URI the
// app registration must contain, which is the value most often mis-typed.

app.get('/federation/status', (c) => {
  const ms = microsoftConfigFor(c.env, c.req.url)
  return c.json({
    microsoft: {
      configured: isMicrosoftConfigured(ms),
      tenant: c.env.MICROSOFT_TENANT || MICROSOFT_DEFAULT_TENANT,
      redirectUri: ms?.redirectUri ?? `${new URL(c.req.url).origin}/federation/microsoft/callback`,
      allowedTenants: allowedTenants(c.env) ?? null,
      confidentialClient: !!c.env.MICROSOFT_CLIENT_SECRET,
    },
    emailCode: { configured: !!emailChannelFor(c.env) },
  })
})

// ── GET /federation/microsoft/start ───────────────────────────────────────

app.get('/federation/microsoft/start', async (c) => {
  const config = microsoftConfigFor(c.env, c.req.url)
  if (!isMicrosoftConfigured(config)) {
    // Not configured is not the viewer's problem — send them to the path that
    // does work rather than showing a 503 they cannot act on.
    const cont = c.req.query('continue') || '/'
    return c.redirect(`/federation/email?continue=${encodeURIComponent(cont)}&reason=not-configured`, 302)
  }

  const continueUrl = safeContinue(c.req.query('continue'), c.env)
  const loginHint = c.req.query('login_hint') || undefined

  const { authorizationUrl, state, transaction } = await startMicrosoftAuth(config, {
    continueUrl,
    loginHint,
  })
  await putTransaction(c.env, state, transaction)

  return c.redirect(authorizationUrl, 302)
})

// ── GET /federation/microsoft/callback ────────────────────────────────────

app.get('/federation/microsoft/callback', async (c) => {
  const config = microsoftConfigFor(c.env, c.req.url)
  if (!isMicrosoftConfigured(config)) {
    return errorResponse(c, 503, ErrorCode.ServiceUnavailable, 'Microsoft federation is not configured')
  }

  const state = c.req.query('state')
  const code = c.req.query('code')
  const error = c.req.query('error')
  const errorDescription = c.req.query('error_description')

  // State first, always — an error response without a valid state is not
  // something we should act on at all.
  if (!state) {
    return errorResponse(c, 400, ErrorCode.InvalidRequest, 'Missing state — please start the sign-in again')
  }
  const tx = await takeTransaction(c.env, state)
  if (!tx) {
    return errorResponse(c, 400, ErrorCode.InvalidRequest, 'This sign-in link has expired — please try again')
  }

  // ── Upstream said no ───────────────────────────────────────────────────
  if (error) {
    const classified = classifyMicrosoftError(error, errorDescription)
    return federationFailure(c, classified, tx.continueUrl, tx.loginHint)
  }

  if (!code) {
    return errorResponse(c, 400, ErrorCode.InvalidRequest, 'Microsoft returned no authorization code')
  }

  try {
    const tokens = await exchangeMicrosoftCode(config, code, tx.codeVerifier)
    const claims = await verifyMicrosoftIdToken(
      tokens.id_token,
      {
        clientId: config.clientId,
        nonce: tx.nonce,
        allowedTenants: allowedTenants(c.env),
      },
      deps.microsoftVerify,
    )
    const principal = microsoftPrincipal(claims)
    return await issueFederatedSession(c.env, c.req.url, principal, tx.continueUrl)
  } catch (err) {
    const classified =
      err instanceof FederationError ? err : new FederationError('upstream-error', (err as Error).message)
    return federationFailure(c, classified, tx.continueUrl, tx.loginHint)
  }
})

/**
 * Route a failed Microsoft sign-in.
 *
 * `consent-required` is NOT an error page. It is the expected behaviour of a
 * locked-down tenant and the exact reason the fallback exists, so the viewer is
 * handed straight to the email-code page with an explanation. Everything else
 * also lands there — a viewer who cannot get in has one useful next action, and
 * it is the same one — but with its own message so we can tell the cases apart
 * in logs.
 */
function federationFailure(
  c: { redirect: (url: string, status: 302) => Response },
  err: FederationError,
  continueUrl: string,
  loginHint?: string,
): Response {
  console.log(`[federation/microsoft] ${err.kind}${err.upstreamCode ? ` (${err.upstreamCode})` : ''}: ${err.message}`)
  const params = new URLSearchParams({ continue: continueUrl, reason: err.kind })
  if (loginHint) params.set('email', loginHint)
  return c.redirect(`/federation/email?${params.toString()}`, 302)
}

// ── GET /federation/email — the fallback page ─────────────────────────────

app.get('/federation/email', (c) => {
  const continueUrl = safeContinue(c.req.query('continue'), c.env)
  const microsoftAvailable = isMicrosoftConfigured(microsoftConfigFor(c.env, c.req.url))
  return renderEmailCodePage({
    continueUrl,
    reason: c.req.query('reason'),
    email: c.req.query('email'),
    microsoftAvailable,
  })
})

// ── POST /federation/email/send ───────────────────────────────────────────

app.post('/federation/email/send', async (c) => {
  const channel = emailChannelFor(c.env)
  if (!channel) {
    return errorResponse(c, 503, ErrorCode.ServiceUnavailable, 'Email verification is not configured')
  }

  const body = await readBody(c.req.raw)
  const email = typeof body.email === 'string' ? normalizeEmail(body.email) : ''
  if (!isPlausibleEmail(email)) {
    return errorResponse(c, 400, ErrorCode.InvalidRequest, 'Enter a valid work email address')
  }

  const allowed = await allowEmailCodeSend(throttleStoreFor(c.env), email)
  if (!allowed) {
    return errorResponse(c, 429, ErrorCode.RateLimitExceeded, 'Too many codes requested — try again later')
  }

  try {
    await channel.send(email)
  } catch (err) {
    const message = err instanceof FederationError ? err.message : 'Could not send the verification code'
    console.log(`[federation/email] send failed for ${email}: ${(err as Error).message}`)
    return errorResponse(c, 502, ErrorCode.ServerError, message)
  }

  // Deliberately does not reveal whether the address exists anywhere — the
  // response is identical for a real mailbox and a typo'd one.
  return c.json({ sent: true })
})

// ── POST /federation/email/verify ─────────────────────────────────────────

app.post('/federation/email/verify', async (c) => {
  const channel = emailChannelFor(c.env)
  if (!channel) {
    return errorResponse(c, 503, ErrorCode.ServiceUnavailable, 'Email verification is not configured')
  }

  const body = await readBody(c.req.raw)
  const email = typeof body.email === 'string' ? normalizeEmail(body.email) : ''
  const code = typeof body.code === 'string' ? body.code.trim() : ''
  const continueUrl = safeContinue(typeof body.continue === 'string' ? body.continue : undefined, c.env)

  if (!isPlausibleEmail(email)) {
    return errorResponse(c, 400, ErrorCode.InvalidRequest, 'Enter a valid work email address')
  }
  if (!isPlausibleCode(code)) {
    return errorResponse(c, 400, ErrorCode.InvalidRequest, 'Enter the 6-digit code from your email')
  }

  let verification
  try {
    verification = await channel.verify(email, code)
  } catch (err) {
    if (err instanceof FederationError && err.kind === 'access-denied') {
      return errorResponse(c, 401, ErrorCode.Unauthorized, err.message)
    }
    console.log(`[federation/email] verify failed for ${email}: ${(err as Error).message}`)
    return errorResponse(c, 502, ErrorCode.ServerError, 'Verification failed — please request a new code')
  }

  const principal = emailCodePrincipal(email, verification)
  const redirect = await issueFederatedSession(c.env, c.req.url, principal, continueUrl)

  // The page posts via fetch, so hand back JSON + the cookie rather than a 302
  // the browser would follow inside the fetch.
  const headers = new Headers({ 'Content-Type': 'application/json' })
  for (const cookie of redirect.headers.getSetCookie()) headers.append('Set-Cookie', cookie)
  return new Response(JSON.stringify({ ok: true, continue: continueUrl, assurance: 'email-code' }), {
    status: 200,
    headers,
  })
})

  return app
}

/** Production mount used by worker/index.ts. */
export const federationRoutes = createFederationApp()

/** Accept both JSON and form posts — the fallback page must work with JS off. */
async function readBody(req: Request): Promise<Record<string, unknown>> {
  const contentType = req.headers.get('content-type') || ''
  if (contentType.includes('application/json')) {
    return (await req.json().catch(() => ({}))) as Record<string, unknown>
  }
  const form = await req.formData().catch(() => null)
  if (!form) return {}
  const out: Record<string, unknown> = {}
  for (const [key, value] of form.entries()) out[key] = value
  return out
}
