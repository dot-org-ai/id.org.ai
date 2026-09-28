/**
 * Auth route module — login, callback, logout, session, widget-token
 * Extracted from worker/index.ts (Phase 6).
 * These routes do NOT require MCP authentication — they must be mounted
 * before the authenticateRequest middleware.
 */
import { Hono } from 'hono'
import * as jose from 'jose'
import type { Env, Variables } from '../types'
import { errorResponse, ErrorCode, errorMessage } from '../../src/sdk/errors'
import { parseCookieValue, buildAuthCookieHeaders, buildClearAuthCookieHeaders, getRootDomain } from '../utils/cookies'
import { getStubForIdentity, getSigningKeyManager, resolveIdentityId } from '../middleware/tenant'
import { renderProviderPicker } from '../views/provider-picker'
import { renderOrgPickerPage } from '../views/org-picker'
import {
  buildWorkOSAuthUrl,
  exchangeWorkOSCode,
  exchangeWorkOSOrgSelection,
  fetchWorkOSUser,
  extractGitHubId,
  fetchGitHubUsername,
  fetchOrgInfo,
  updateWorkOSUser,
  ensurePersonalOrg,
  encodeLoginState,
  decodeLoginState,
  listUserOrgMemberships,
} from '../../src/sdk/workos/upstream'
import type { OrgSelectionError, WorkOSAuthResult } from '../../src/sdk/workos/upstream'
import { isSafeRedirectUrl } from '../../src/sdk/csrf'
import { describeWorkOSSignIn } from '../../src/sdk/workos/upstream'
import { resolveBrowserRedirect, requestOriginOf, canonicalOrigin } from '../utils/relying-parties'

/** Where a sign-in lands when no acceptable `continue` was given. */
const DEFAULT_CONTINUE = '/dash/profile'

/** An OIDC login_hint we are willing to pass upstream: a plausible email, nothing else. */
export function sanitizeLoginHint(value: string | null | undefined): string | undefined {
  if (!value) return undefined
  const hint = value.trim()
  if (hint.length > 320 || !/^[^\s@<>"']+@[^\s@<>"']+\.[^\s@<>"']+$/.test(hint)) return undefined
  return hint
}

/**
 * What /login (and the magic-link org-selection hand-off) stores under
 * `login-csrf:<csrf>`. The login `state` is unsigned base64 JSON that anyone
 * can decode and re-encode, so the destination and the cookie-bounce origin
 * are bound HERE, server-side, and /api/callback uses these values. Taking
 * them from the state let a forged state (a real csrf from the attacker's own
 * /login, plus `origin: https://evil.example`) send the victim's one-time
 * `_auth_code` to the attacker's /callback, where it redeems for the victim's
 * session cookie.
 */
export interface LoginCsrfRecord {
  csrf: string
  createdAt: number
  continue: string
  origin: string
  provider?: string
}

export function loginCsrfRecord(csrf: string, continueUrl: string, origin: string, provider?: string): LoginCsrfRecord {
  return { csrf, createdAt: Date.now(), continue: continueUrl, origin, ...(provider ? { provider } : {}) }
}

/**
 * How long a login transaction stays redeemable. DO storage ignores
 * `expirationTtl`, so this is enforced on read. Generous enough for an AuthKit
 * sign-up with email verification plus the org picker.
 */
export const LOGIN_CSRF_MAX_AGE_MS = 30 * 60 * 1000

/** How long a cross-origin `_auth_code` stays redeemable (enforced on read). */
export const AUTH_CODE_MAX_AGE_MS = 60 * 1000

const app = new Hono<{ Bindings: Env; Variables: Variables }>()

// ── WorkOS Login Flow (no auth required) ─────────────────────────────────────
// Human authentication via WorkOS AuthKit (SSO, social login, MFA).
// GET /login → redirect to WorkOS → GET /callback → set cookie → redirect

app.get('/login', async (c) => {
  const clientId = c.env.WORKOS_CLIENT_ID
  if (!clientId || !c.env.WORKOS_API_KEY) {
    return errorResponse(c, 503, ErrorCode.ServiceUnavailable, 'WorkOS is not configured')
  }

  // Only relative paths, id.org.ai's own origins, trusted-account domains,
  // LOGIN_CONTINUE_HOSTS and registered clients' redirect origins are accepted
  // (worker/utils/relying-parties.ts). Anything else — //evil.com,
  // https://evil.com, javascript:, encoded tricks — falls back to the default
  // rather than becoming an open redirect. Under LOGIN_CONTINUE_POLICY=report
  // a syntactically safe absolute target outside the policy is still followed
  // and logged, so estate callers can be listed before enforcing.
  const reqOrigin = requestOriginOf(c.req.url)
  const rawContinue = c.req.query('continue') || c.req.query('redirect_uri')
  const continueDecision = await resolveBrowserRedirect(c.env, rawContinue, {
    requestOrigin: reqOrigin,
    clientId: c.req.query('client_id') || undefined,
  })
  if (continueDecision.outcome === 'refused' || continueDecision.outcome === 'unlisted') {
    console.warn(JSON.stringify({ event: `login.continue.${continueDecision.outcome}`, host: continueDecision.host }))
  }
  const continueUrl = continueDecision.url ?? DEFAULT_CONTINUE
  // OIDC login_hint (also forwarded by /oauth/authorize): prefill the email upstream.
  const loginHint = sanitizeLoginHint(c.req.query('login_hint'))

  // If the user already has a valid session, skip WorkOS and redirect to continue URL.
  // This prevents conflicts when e.g. CLI device flow redirects here while user is logged in,
  // or when WorkOS has its own active session that conflicts with a new auth request.
  const identityId = await resolveIdentityId(c.req.raw, c.env)
  if (identityId) {
    const redirectTo = continueUrl.startsWith('http') ? continueUrl : `${requestOriginOf(c.req.url)}${continueUrl}`
    return c.redirect(redirectTo, 302)
  }

  // Allow forcing a specific provider (e.g. ?provider=GitHubOAuth)
  const provider = c.req.query('provider') || undefined
  const VALID_PROVIDERS = ['authkit', 'GitHubOAuth', 'GoogleOAuth', 'MicrosoftOAuth', 'AppleOAuth']
  const safeProvider = provider && VALID_PROVIDERS.includes(provider) ? provider : undefined

  // No provider specified → show provider picker page
  // This avoids AuthKit's built-in org selection which causes a double sign-in
  // for users with multiple orgs. Direct providers return organization_selection_required
  // on code exchange, which our /api/callback handler catches and shows our own org picker.
  if (!safeProvider) {
    return renderProviderPicker(continueUrl, loginHint)
  }

  const csrf = crypto.randomUUID()

  // Capture the requesting origin so the callback can redirect back and set the cookie
  // on the correct domain (e.g. headless.ly, not id.org.ai).
  const requestOrigin = requestOriginOf(c.req.url)
  const state = encodeLoginState(csrf, continueUrl, requestOrigin, safeProvider)

  // Store the CSRF token for validation on callback, WITH the continue URL and
  // origin this request resolved. The state handed to WorkOS is unsigned
  // base64 JSON, so /api/callback takes these from here, never from the state
  // (see LoginCsrfRecord).
  const oauthStub = getStubForIdentity(c.env, 'oauth')
  await oauthStub.oauthStorageOp({
    op: 'put',
    key: `login-csrf:${csrf}`,
    value: loginCsrfRecord(csrf, continueUrl, requestOrigin, safeProvider),
    options: { expirationTtl: 300 },
  })

  // Always use the canonical id.org.ai callback URL for WorkOS redirect.
  // When the request comes from a different domain (e.g. headless.ly via service binding),
  // we can't use that domain's callback URL because it's not registered in WorkOS.
  // The requesting origin is stored in state.origin for the cross-origin bounce after auth.
  const CANONICAL_ORIGINS = ['https://id.org.ai', 'https://oauth.dotdo.workers.dev']
  const callbackOrigin = CANONICAL_ORIGINS.includes(requestOrigin) ? requestOrigin : 'https://id.org.ai'
  const redirectUri = `${callbackOrigin}/api/callback`
  const authUrl = buildWorkOSAuthUrl(clientId, redirectUri, state, safeProvider, loginHint)
  // Store state in cookie so we can recover it if WorkOS drops the state param
  // (happens during AuthKit's internal org selection flow)
  const reqUrl = new URL(c.req.url)
  const isSecure = reqUrl.protocol === 'https:'
  const stateFlags = `HttpOnly; Path=/api/callback; SameSite=Lax; Max-Age=300${isSecure ? '; Secure' : ''}`
  return new Response(null, {
    status: 302,
    headers: {
      Location: authUrl,
      'Set-Cookie': `_auth_state=${state}; ${stateFlags}`,
    },
  })
})

// ── /callback — Origin callback: exchange one-time auth code for JWT cookie ──
// When login is initiated from a different domain (e.g. apis.do), the server-side
// /api/callback creates a one-time code and redirects here so the cookie is set
// on the correct domain. This route is proxied via AUTH_HTTP from *.do domains.
// Without _auth_code, falls through to ASSETS for the SPA client-side callback.
app.get('/callback', async (c) => {
  const authCode = c.req.query('_auth_code')
  if (!authCode) {
    // No auth code — let the SPA handle it
    return c.env.ASSETS ? c.env.ASSETS.fetch(c.req.raw) : errorResponse(c, 400, ErrorCode.InvalidRequest, 'Missing _auth_code parameter')
  }

  const oauthStub = getStubForIdentity(c.env, 'oauth')
  const stored = await oauthStub.oauthStorageOp({ op: 'get', key: `auth-code:${authCode}` })
  if (!stored.value) {
    return errorResponse(c, 400, ErrorCode.InvalidGrant, 'Invalid or expired auth code')
  }
  // Consume one-time code
  await oauthStub.oauthStorageOp({ op: 'delete', key: `auth-code:${authCode}` })

  const { jwt, continueUrl, expiresAt } = stored.value as { jwt: string; continueUrl: string; expiresAt?: number }
  // DO storage ignores expirationTtl: enforce the one-minute lifetime here. A
  // code without expiresAt predates this check and is not honoured.
  if (typeof expiresAt !== 'number' || expiresAt < Date.now()) {
    return errorResponse(c, 400, ErrorCode.InvalidGrant, 'Invalid or expired auth code')
  }

  // Set cookie on the requesting domain (e.g. apis.do)
  const reqUrl = new URL(c.req.url)
  const isSecure = reqUrl.protocol === 'https:'
  const domain = getRootDomain(reqUrl.hostname)
  const cookieHeaders = buildAuthCookieHeaders(jwt, { secure: isSecure, domain, maxAge: 30 * 24 * 3600 })

  const redirectTo = isSafeRedirectUrl(continueUrl) ? continueUrl : '/'
  const headers = new Headers({ Location: redirectTo })
  for (const cookie of cookieHeaders) {
    headers.append('Set-Cookie', cookie)
  }
  return new Response(null, { status: 302, headers })
})

// ── /api/org-select — Org picker POST handler ───────────────────────────────
// After the user picks an org on the org picker page, this endpoint completes
// authentication with the chosen org and redirects back to /api/callback flow.
app.post('/api/org-select', async (c) => {
  const clientId = c.env.WORKOS_CLIENT_ID
  const apiKey = c.env.WORKOS_API_KEY
  if (!clientId || !apiKey) {
    return errorResponse(c, 503, ErrorCode.ServiceUnavailable, 'WorkOS is not configured')
  }

  const body = await c.req.parseBody()
  const pendingToken = body.pending_token as string
  const organizationId = body.organization_id as string
  const state = body.state as string

  if (!pendingToken || !organizationId || !state) {
    return errorResponse(c, 400, ErrorCode.InvalidRequest, 'Missing required fields')
  }

  // Exchange pending token + org selection for real auth result
  let authResult: WorkOSAuthResult
  try {
    authResult = await exchangeWorkOSOrgSelection(clientId, apiKey, pendingToken, organizationId, {
      userAgent: c.req.header('user-agent'),
      ipAddress: c.req.header('cf-connecting-ip') || c.req.header('x-forwarded-for'),
    })
  } catch (err: unknown) {
    return errorResponse(c, 502, ErrorCode.ServerError, errorMessage(err))
  }

  // Decode state to get CSRF + continue URL + origin
  const decoded = decodeLoginState(state)
  if (!decoded) {
    return errorResponse(c, 400, ErrorCode.InvalidRequest, 'Invalid state parameter')
  }

  const oauthStub = getStubForIdentity(c.env, 'oauth')

  // Build a synthetic callback URL with a special parameter to skip code exchange
  // and use the auth result directly. We'll store it in KV and pass a reference.
  const resultKey = `auth-result:${crypto.randomUUID()}`
  await oauthStub.oauthStorageOp({
    op: 'put',
    key: resultKey,
    value: authResult,
    options: { expirationTtl: 60 },
  })

  const requestOrigin = requestOriginOf(c.req.url)
  const callbackUrl = new URL(`${requestOrigin}/api/callback`)
  callbackUrl.searchParams.set('_auth_result', resultKey)
  callbackUrl.searchParams.set('state', state)

  return c.redirect(callbackUrl.toString(), 302)
})

// ── Landing Page Renderer ────────────────────────────────────────────────────
// ── /api/callback — Server-side WorkOS callback ─────────────────────────────
// WorkOS redirects the browser here after authentication (registered redirect_uri).
// Exchanges the code, signs a JWT, then either:
//   - Cross-origin: stores one-time code → redirects to origin's /callback
//   - Same-origin: sets cookie directly
app.get('/api/callback', async (c) => {
  const oauthStub = getStubForIdentity(c.env, 'oauth')
  const clientId = c.env.WORKOS_CLIENT_ID
  const apiKey = c.env.WORKOS_API_KEY
  if (!clientId || !apiKey) {
    return errorResponse(c, 503, ErrorCode.ServiceUnavailable, 'WorkOS is not configured')
  }

  const code = c.req.query('code')
  const error = c.req.query('error')
  const authResultKey = c.req.query('_auth_result')

  // Recover state from query param or cookie (WorkOS AuthKit drops state during org selection)
  const cookieHeader = c.req.header('cookie') || ''
  const state = c.req.query('state') || parseCookieValue(cookieHeader, '_auth_state')

  if (error) {
    const desc = c.req.query('error_description') || 'Authentication failed'
    return errorResponse(c, 400, ErrorCode.InvalidGrant, desc)
  }

  if (!state) {
    return errorResponse(c, 400, ErrorCode.InvalidRequest, 'Missing state parameter — please try logging in again')
  }

  // Decode and validate state (CSRF)
  const decoded = decodeLoginState(state)
  if (!decoded) {
    return errorResponse(c, 400, ErrorCode.InvalidRequest, 'Invalid state parameter')
  }

  // Validate CSRF but don't consume yet — org picker flow may need it again
  const csrfData = await oauthStub.oauthStorageOp({ op: 'get', key: `login-csrf:${decoded.csrf}` })
  const csrfRecord = csrfData.value as Partial<LoginCsrfRecord> | undefined
  if (!csrfRecord || typeof csrfRecord.createdAt !== 'number' || Date.now() - csrfRecord.createdAt > LOGIN_CSRF_MAX_AGE_MS) {
    return errorResponse(c, 403, ErrorCode.Forbidden, 'Invalid or expired CSRF token — please try logging in again')
  }
  // Destination and bounce origin come from the server-side record, never the
  // (unsigned) state. A record written before they were bound gets no
  // cross-origin bounce and a continue re-checked against the policy.
  const bound = typeof csrfRecord.continue === 'string' && typeof csrfRecord.origin === 'string'
  const boundContinue = bound
    ? csrfRecord.continue!
    : ((await resolveBrowserRedirect(c.env, decoded.continue, { requestOrigin: requestOriginOf(c.req.url) })).url ?? '/')
  const boundOrigin = bound ? csrfRecord.origin : undefined
  const boundProvider = bound ? csrfRecord.provider : decoded.provider

  // Exchange code with WorkOS (or retrieve stored auth result from org selection)
  let authResult: WorkOSAuthResult
  if (authResultKey) {
    // Coming back from org picker — retrieve stored auth result. Only keys
    // /api/org-select wrote: the parameter must not read arbitrary storage.
    if (!/^auth-result:[0-9a-f-]{36}$/.test(authResultKey)) {
      return errorResponse(c, 400, ErrorCode.InvalidRequest, 'Invalid org selection reference')
    }
    const stored = await oauthStub.oauthStorageOp({ op: 'get', key: authResultKey })
    if (!stored.value) {
      return errorResponse(c, 400, ErrorCode.InvalidRequest, 'Expired org selection — please try logging in again')
    }
    await oauthStub.oauthStorageOp({ op: 'delete', key: authResultKey })
    authResult = stored.value as any
  } else if (code) {
    try {
      authResult = await exchangeWorkOSCode(clientId, apiKey, code, {
        userAgent: c.req.header('user-agent'),
        ipAddress: c.req.header('cf-connecting-ip') || c.req.header('x-forwarded-for'),
      })
    } catch (err: unknown) {
      // User belongs to multiple orgs — show org picker (don't consume CSRF yet)
      if (err && typeof err === 'object' && 'code' in err && (err as { code?: unknown }).code === 'organization_selection_required') {
        return renderOrgPickerPage(err as OrgSelectionError, state)
      }
      return errorResponse(c, 502, ErrorCode.ServerError, errorMessage(err))
    }
  } else {
    return errorResponse(c, 400, ErrorCode.InvalidRequest, 'Missing code or _auth_result parameter')
  }

  // Now consume CSRF token (auth succeeded, no more retries needed)
  await oauthStub.oauthStorageOp({ op: 'delete', key: `login-csrf:${decoded.csrf}` })

  return finishWorkOSSignIn(c, authResult, {
    requestedProvider: boundProvider,
    continueUrl: isSafeRedirectUrl(boundContinue) ? boundContinue : '/',
    origin: boundOrigin,
  })
})

/**
 * Complete a WorkOS sign-in: provision or refresh the human identity, sign the
 * id.org.ai session JWT (with how they signed in: `amr`, `idp`, `auth_time`),
 * set the cookie (directly, or through the requesting origin's /callback) and
 * redirect to `continueUrl`. Shared by /api/callback and the magic-link flow.
 *
 * `continueUrl` must already have passed the caller's redirect policy.
 */
export async function finishWorkOSSignIn(
  c: any,
  authResult: WorkOSAuthResult,
  opts: { requestedProvider?: string; continueUrl: string; origin?: string },
): Promise<Response> {
  const oauthStub = getStubForIdentity(c.env, 'oauth')
  const apiKey = c.env.WORKOS_API_KEY as string
  const signInMethod = describeWorkOSSignIn(authResult.authentication_method, opts.requestedProvider)

  // Fetch full WorkOS user profile + org info in parallel
  let orgId = authResult.user.organization_id || authResult.organization_id
  const [workosUser, initialOrgInfo] = await Promise.all([
    fetchWorkOSUser(apiKey, authResult.user.id),
    orgId ? fetchOrgInfo(apiKey, orgId) : Promise.resolve(null),
  ])
  const githubIdFromWorkOS = workosUser ? extractGitHubId(workosUser) : null

  // Fetch GitHub username from numeric ID (public API, no auth needed)
  const githubUsername = githubIdFromWorkOS ? await fetchGitHubUsername(githubIdFromWorkOS) : null

  // Ensure user has a personal org (required for API key management).
  // If they already have an org from WorkOS, use that. Otherwise create one.
  let orgInfo = initialOrgInfo
  if (!orgId) {
    const fullName = [authResult.user.first_name, authResult.user.last_name].filter(Boolean).join(' ')
    const orgName = githubUsername || fullName || undefined
    const result = await ensurePersonalOrg(apiKey, authResult.user.id, orgName, authResult.user.email)
    if (result) {
      orgId = result.orgId
      orgInfo = result.created ? { name: orgName || authResult.user.email.split('@')[0] || 'Personal', domains: [] } : await fetchOrgInfo(apiKey, result.orgId)
    } else {
      console.error(`[callback] ensurePersonalOrg returned null for user=${authResult.user.id} email=${authResult.user.email}`)
    }
  }

  // Create or find identity for this human user
  const shardKey = `human:${authResult.user.id}`
  const stub = getStubForIdentity(c.env, shardKey)

  let identity = await stub.getIdentity(shardKey)
  if (!identity) {
    // Create new human identity
    const fullName = [authResult.user.first_name, authResult.user.last_name].filter(Boolean).join(' ')
    identity = await stub.provisionAnonymous(shardKey).then((r) => r.identity)
    // Upgrade to human type + level 2 (claimed via WorkOS)
    await stub.oauthStorageOp({
      op: 'put',
      key: `identity:${shardKey}`,
      value: {
        id: shardKey,
        type: 'human',
        name: fullName || authResult.user.email,
        email: authResult.user.email,
        verified: true,
        level: 2,
        claimStatus: 'claimed',
        workosUserId: authResult.user.id,
        organizationId: authResult.user.organization_id || authResult.organization_id,
        ...(githubIdFromWorkOS ? { githubUserId: githubIdFromWorkOS } : {}),
        createdAt: Date.now(),
      },
    })
    identity = await stub.getIdentity(shardKey)
  } else if (githubIdFromWorkOS && !identity.githubUserId) {
    // Existing identity without GitHub ID — backfill from WorkOS profile
    const stored = await stub.oauthStorageOp({ op: 'get', key: `identity:${shardKey}` })
    if (stored.value) {
      await stub.oauthStorageOp({
        op: 'put',
        key: `identity:${shardKey}`,
        value: { ...(stored.value as object), githubUserId: githubIdFromWorkOS },
      })
      identity = await stub.getIdentity(shardKey)
    }
  }

  // Store WorkOS refresh token for later widget token exchange
  if (authResult.refresh_token) {
    try {
      await stub.storeWorkOSRefreshToken(authResult.refresh_token)
    } catch (err) {
      console.error('[callback] Failed to store WorkOS refresh token:', err)
    }
  }

  // Resolve GitHub ID: prefer identity record (from claim flow), then WorkOS profile
  const githubId = identity?.githubUserId || githubIdFromWorkOS || undefined

  // Persist GitHub ID + username to WorkOS as external_id + metadata.
  // Fire-and-forget — don't block the login flow.
  if (githubId) {
    c.executionCtx.waitUntil(
      updateWorkOSUser(apiKey, authResult.user.id, {
        external_id: githubId,
        metadata: {
          github_id: githubId,
          ...(githubUsername ? { github_username: githubUsername } : {}),
        },
      }),
    )
  }

  // Sign our own JWT for the auth cookie (camelCase claims, nested org object)
  const platformOrgId = c.env.PLATFORM_ORG_ID
  const isSuperadmin = !!(platformOrgId && orgId && orgId === platformOrgId)
  const signingManager = getSigningKeyManager(c.env)
  const jwt = await signingManager.sign(
    {
      sub: authResult.user.id,
      email: authResult.user.email,
      name: [authResult.user.first_name, authResult.user.last_name].filter(Boolean).join(' ') || undefined,
      githubId: githubId,
      githubUsername: githubUsername || undefined,
      org: orgId ? { id: orgId, name: orgInfo?.name, domains: orgInfo?.domains?.length ? orgInfo.domains : undefined } : undefined,
      roles: authResult.user.roles,
      permissions: authResult.user.permissions,
      ...(isSuperadmin ? { platformRole: 'superadmin' } : {}),
      // How they signed in, for relying parties (OIDC amr / idp / auth_time)
      ...(signInMethod.amr ? { amr: signInMethod.amr } : {}),
      ...(signInMethod.idp ? { idp: signInMethod.idp } : {}),
      auth_time: Math.floor(Date.now() / 1000),
    },
    { issuer: 'https://id.org.ai', expiresIn: 30 * 24 * 3600 },
  )

  const continueUrl = opts.continueUrl

  // ── Cross-origin redirect: bounce to the requesting domain to set cookie ─
  // If the login was initiated from a different domain (e.g. apis.do), we can't
  // set the cookie from oauth.do. Store a one-time code and redirect to the
  // origin's /callback so the cookie is set on the correct domain.
  // Both origins in canonical spelling (lowercase host, no trailing dot).
  const currentOrigin = requestOriginOf(c.req.url)
  const bounceOrigin = opts.origin ? canonicalOrigin(opts.origin) : null
  if (bounceOrigin && bounceOrigin !== currentOrigin) {
    const oneTimeCode = crypto.randomUUID()
    await oauthStub.oauthStorageOp({
      op: 'put',
      key: `auth-code:${oneTimeCode}`,
      value: { jwt, continueUrl, expiresAt: Date.now() + AUTH_CODE_MAX_AGE_MS },
      options: { expirationTtl: 60 },
    })

    const callbackUrl = new URL('/callback', bounceOrigin)
    callbackUrl.searchParams.set('_auth_code', oneTimeCode)
    return c.redirect(callbackUrl.toString(), 302)
  }

  // ── Same-origin (id.org.ai or oauth.do direct login): set cookie directly ─
  const reqUrl = new URL(c.req.url)
  const isSecure = reqUrl.protocol === 'https:'
  const domain = getRootDomain(reqUrl.hostname)
  const cookieHeaders = buildAuthCookieHeaders(jwt, { secure: isSecure, domain, maxAge: 30 * 24 * 3600 })

  const headers = new Headers({ Location: continueUrl })
  for (const cookie of cookieHeaders) {
    headers.append('Set-Cookie', cookie)
  }
  return new Response(null, { status: 302, headers })
}

// ── Logout ────────────────────────────────────────────────────────────────────

app.get('/logout', async (c) => {
  // Clear WorkOS refresh token (non-fatal)
  try {
    const identityId = await resolveIdentityId(c.req.raw, c.env)
    if (identityId) {
      const identityStub = getStubForIdentity(c.env, identityId)
      await identityStub.clearWorkOSRefreshToken()
    }
  } catch {
    // Non-fatal — proceed with cookie clearing
  }

  // Same destination policy as /login?continue= (worker/utils/relying-parties.ts):
  // a sign-out must not be a redirector either. Refused targets land on `/`.
  const reqUrl = new URL(c.req.url)
  const returnDecision = await resolveBrowserRedirect(c.env, c.req.query('return_url'), { requestOrigin: requestOriginOf(c.req.url) })
  if (returnDecision.outcome === 'refused' || returnDecision.outcome === 'unlisted') {
    console.warn(JSON.stringify({ event: `logout.return.${returnDecision.outcome}`, host: returnDecision.host }))
  }
  const returnUrl = returnDecision.url ?? '/'
  const isSecure = reqUrl.protocol === 'https:'
  const domain = getRootDomain(reqUrl.hostname)
  const clearCookies = buildClearAuthCookieHeaders({ secure: isSecure, domain })

  const headers = new Headers({ Location: returnUrl })
  for (const cookie of clearCookies) {
    headers.append('Set-Cookie', cookie)
  }
  return new Response(null, { status: 302, headers })
})

app.post('/logout', async (c) => {
  // Clear WorkOS refresh token (non-fatal)
  try {
    const identityId = await resolveIdentityId(c.req.raw, c.env)
    if (identityId) {
      const identityStub = getStubForIdentity(c.env, identityId)
      await identityStub.clearWorkOSRefreshToken()
    }
  } catch {
    // Non-fatal — proceed with cookie clearing
  }

  const reqUrl = new URL(c.req.url)
  const isSecure = reqUrl.protocol === 'https:'
  const domain = getRootDomain(reqUrl.hostname)
  const clearCookies = buildClearAuthCookieHeaders({ secure: isSecure, domain })

  const headers = new Headers({ 'Content-Type': 'application/json' })
  for (const cookie of clearCookies) {
    headers.append('Set-Cookie', cookie)
  }
  return new Response(JSON.stringify({ ok: true }), { status: 200, headers })
})

// ── /api/me — Current user info from JWT cookie ─────────────────────────────

app.get('/api/me', async (c) => {
  const cookie = c.req.header('cookie')
  if (!cookie) return c.json({ authenticated: false }, 200)

  const jwt = parseCookieValue(cookie, 'auth')
  if (!jwt) return c.json({ authenticated: false }, 200)

  try {
    const manager = getSigningKeyManager(c.env)
    const jwks = await manager.getJWKS()
    const localJwks = jose.createLocalJWKSet(jwks)
    const { payload } = await jose.jwtVerify(jwt, localJwks, { issuer: 'https://id.org.ai' })

    return c.json({
      authenticated: true,
      user: {
        id: payload.sub,
        email: payload.email,
        name: payload.name,
        githubId: payload.githubId,
        githubUsername: payload.githubUsername,
        org: payload.org,
      },
    })
  } catch {
    return c.json({ authenticated: false }, 200)
  }
})

// ── /api/session — Session endpoint for @id.org.ai/react SDK ─────────────────
// Returns the current user mapped to WorkOS-compatible AuthUser shape.

app.get('/api/session', async (c) => {
  const cookie = c.req.header('cookie')
  if (!cookie) return c.json({ error: 'Unauthorized' }, 401)

  const jwt = parseCookieValue(cookie, 'auth')
  if (!jwt) return c.json({ error: 'Unauthorized' }, 401)

  try {
    const manager = getSigningKeyManager(c.env)
    const jwks = await manager.getJWKS()
    const localJwks = jose.createLocalJWKSet(jwks)
    const { payload } = await jose.jwtVerify(jwt, localJwks, { issuer: 'https://id.org.ai' })

    const fullName = (payload.name as string) || ''
    const nameParts = fullName.trim().split(/\s+/)
    const firstName = nameParts[0] || null
    const lastName = nameParts.length > 1 ? nameParts.slice(1).join(' ') : null

    const org = payload.org as { id?: string } | undefined
    const organizationId = org?.id || (payload.org_id as string | undefined) || null
    const roles = (payload.roles as string[]) || []
    const permissions = (payload.permissions as string[]) || []

    // Roll cookie for sliding expiry
    const reqUrl = new URL(c.req.url)
    const isSecure = reqUrl.protocol === 'https:'
    const domain = getRootDomain(reqUrl.hostname)
    const cookieHeaders = buildAuthCookieHeaders(jwt, { secure: isSecure, domain, maxAge: 30 * 24 * 3600 })

    const headers = new Headers({ 'Content-Type': 'application/json' })
    for (const ch of cookieHeaders) {
      headers.append('Set-Cookie', ch)
    }

    const user = {
      id: payload.sub || '',
      email: (payload.email as string) || '',
      firstName,
      lastName,
      profilePictureUrl: (payload.image as string) || null,
      emailVerified: true,
      organizationId,
      role: roles[0] || null,
      permissions,
      createdAt: payload.iat ? new Date(payload.iat * 1000).toISOString() : new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    }

    return new Response(JSON.stringify({ user, organizationId }), { status: 200, headers })
  } catch {
    return c.json({ error: 'Unauthorized' }, 401)
  }
})

// ── /api/widget-token — Widget token for @id.org.ai/react SDK ────────────────
// Returns an access token for WorkOS widgets.

app.get('/api/widget-token', async (c) => {
  const cookie = c.req.header('cookie')
  if (!cookie) return c.json({ error: 'Unauthorized' }, 401)

  const jwt = parseCookieValue(cookie, 'auth')
  if (!jwt) return c.json({ error: 'Unauthorized' }, 401)

  try {
    const manager = getSigningKeyManager(c.env)
    const jwks = await manager.getJWKS()
    const localJwks = jose.createLocalJWKSet(jwks)
    const { payload } = await jose.jwtVerify(jwt, localJwks, { issuer: 'https://id.org.ai' })

    if (!payload.sub) return c.json({ error: 'Unauthorized' }, 401)

    const identityId = `human:${payload.sub}`
    const identityStub = getStubForIdentity(c.env, identityId)
    const org = payload.org as { id?: string } | undefined
    const organizationId = org?.id || (payload.org_id as string) || undefined

    const token = await identityStub.refreshWorkOSToken({ clientId: c.env.WORKOS_CLIENT_ID!, apiKey: c.env.WORKOS_API_KEY! }, organizationId)

    return c.json({ token })
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    console.error('[widget-token] Failed for identity:', msg)
    return c.json({ error: msg.includes('re-authenticate') ? 'No refresh token — re-login required' : 'Unauthorized' }, 401)
  }
})

// ── /api/session/organization — Switch active org for @id.org.ai/react SDK ───
// Re-mints the JWT with a new organizationId claim.

app.post('/api/session/organization', async (c) => {
  const cookie = c.req.header('cookie')
  if (!cookie) return c.json({ error: 'Unauthorized' }, 401)

  const jwt = parseCookieValue(cookie, 'auth')
  if (!jwt) return c.json({ error: 'Unauthorized' }, 401)

  const body = await c.req.json<{ organizationId: string }>().catch(() => null)
  if (!body?.organizationId) {
    return c.json({ error: 'organizationId is required' }, 400)
  }

  try {
    const manager = getSigningKeyManager(c.env)
    const jwks = await manager.getJWKS()
    const localJwks = jose.createLocalJWKSet(jwks)
    const { payload } = await jose.jwtVerify(jwt, localJwks, { issuer: 'https://id.org.ai' })

    // Validate the user is a member of the target org
    const apiKey = c.env.WORKOS_API_KEY
    if (apiKey && payload.sub) {
      const memberships = await listUserOrgMemberships(apiKey, payload.sub)
      const isMember = memberships.some((m) => m.organization_id === body.organizationId)
      if (!isMember) {
        return c.json({ error: 'User is not a member of this organization' }, 403)
      }
    }

    // Fetch org info for the new org
    const orgInfo = apiKey ? await fetchOrgInfo(apiKey, body.organizationId) : null

    // Re-mint JWT with new organizationId
    const platformOrgId = c.env.PLATFORM_ORG_ID
    const isSuperadmin = !!(platformOrgId && body.organizationId === platformOrgId)
    const newJwt = await manager.sign(
      {
        sub: payload.sub || '',
        email: payload.email as string | undefined,
        name: payload.name as string | undefined,
        image: payload.image as string | undefined,
        githubId: payload.githubId as string | undefined,
        githubUsername: payload.githubUsername as string | undefined,
        org: { id: body.organizationId, name: orgInfo?.name, domains: orgInfo?.domains?.length ? orgInfo.domains : undefined },
        roles: payload.roles as string[] | undefined,
        permissions: payload.permissions as string[] | undefined,
        ...(isSuperadmin ? { platformRole: 'superadmin' } : {}),
        // Switching org is not a new sign-in: keep how and when they signed in
        ...(Array.isArray(payload.amr) ? { amr: payload.amr as string[] } : {}),
        ...(typeof payload.idp === 'string' ? { idp: payload.idp } : {}),
        ...(typeof payload.auth_time === 'number' ? { auth_time: payload.auth_time } : {}),
      },
      { issuer: 'https://id.org.ai', expiresIn: 30 * 24 * 3600 },
    )

    // Set updated cookie
    const reqUrl = new URL(c.req.url)
    const isSecure = reqUrl.protocol === 'https:'
    const domain = getRootDomain(reqUrl.hostname)
    const cookieHeaders = buildAuthCookieHeaders(newJwt, { secure: isSecure, domain, maxAge: 30 * 24 * 3600 })

    const headers = new Headers({ 'Content-Type': 'application/json' })
    for (const ch of cookieHeaders) {
      headers.append('Set-Cookie', ch)
    }

    // Return updated session in same shape as GET /api/session
    const fullName = (payload.name as string) || ''
    const nameParts = fullName.trim().split(/\s+/)
    const firstName = nameParts[0] || null
    const lastName = nameParts.length > 1 ? nameParts.slice(1).join(' ') : null
    const roles = (payload.roles as string[]) || []
    const permissions = (payload.permissions as string[]) || []

    const user = {
      id: payload.sub || '',
      email: (payload.email as string) || '',
      firstName,
      lastName,
      profilePictureUrl: (payload.image as string) || null,
      emailVerified: true,
      organizationId: body.organizationId,
      role: roles[0] || null,
      permissions,
      createdAt: payload.iat ? new Date(payload.iat * 1000).toISOString() : new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    }

    return new Response(JSON.stringify({ user, organizationId: body.organizationId }), { status: 200, headers })
  } catch {
    return c.json({ error: 'Unauthorized' }, 401)
  }
})

// ── /api/logout — Clear session for @id.org.ai/react SDK ─────────────────────
// Clears all auth cookies (single + chunked).

app.post('/api/logout', async (c) => {
  // Clear WorkOS refresh token (non-fatal)
  try {
    const identityId = await resolveIdentityId(c.req.raw, c.env)
    if (identityId) {
      const identityStub = getStubForIdentity(c.env, identityId)
      await identityStub.clearWorkOSRefreshToken()
    }
  } catch {
    // Non-fatal — proceed with cookie clearing
  }

  const reqUrl = new URL(c.req.url)
  const isSecure = reqUrl.protocol === 'https:'
  const domain = getRootDomain(reqUrl.hostname)
  const clearCookies = buildClearAuthCookieHeaders({ secure: isSecure, domain })

  const headers = new Headers({ 'Content-Type': 'application/json' })
  for (const cookie of clearCookies) {
    headers.append('Set-Cookie', cookie)
  }
  return new Response(JSON.stringify({ success: true }), { status: 200, headers })
})

export { app as authRoutes }
