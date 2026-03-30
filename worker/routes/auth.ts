/**
 * Auth route module — login, callback, logout, session, widget-token
 * Extracted from worker/index.ts (Phase 6).
 * These routes do NOT require MCP authentication — they must be mounted
 * before the authenticateRequest middleware.
 */
import { Hono } from 'hono'
import * as jose from 'jose'
import type { Env, Variables } from '../types'
import { errorResponse, ErrorCode } from '../../src/errors'
import { parseCookieValue, buildAuthCookieHeaders, buildClearAuthCookieHeaders, getRootDomain } from '../utils/cookies'
import { getStubForIdentity, resolveIdentityId } from '../middleware/tenant'
import { renderProviderPicker } from '../views/provider-picker'
import { renderOrgPickerPage } from '../views/org-picker'
import { SigningKeyManager } from '../../src/jwt/signing'
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
} from '../../src/workos/upstream'
import type { OrgSelectionError } from '../../src/workos/upstream'
import { isSafeRedirectUrl } from '../../src/csrf'

const app = new Hono<{ Bindings: Env; Variables: Variables }>()

// ── WorkOS Login Flow (no auth required) ─────────────────────────────────────
// Human authentication via WorkOS AuthKit (SSO, social login, MFA).
// GET /login → redirect to WorkOS → GET /callback → set cookie → redirect

app.get('/login', async (c) => {
  const clientId = c.env.WORKOS_CLIENT_ID
  if (!clientId || !c.env.WORKOS_API_KEY) {
    return errorResponse(c, 503, ErrorCode.ServiceUnavailable, 'WorkOS is not configured')
  }

  const rawContinue = c.req.query('continue') || c.req.query('redirect_uri') || '/dash/profile'
  const continueUrl = isSafeRedirectUrl(rawContinue) ? rawContinue : '/dash/profile'

  // If the user already has a valid session, skip WorkOS and redirect to continue URL.
  // This prevents conflicts when e.g. CLI device flow redirects here while user is logged in,
  // or when WorkOS has its own active session that conflicts with a new auth request.
  const identityId = await resolveIdentityId(c.req.raw, c.env)
  if (identityId) {
    const redirectTo = continueUrl.startsWith('http') ? continueUrl : `${new URL(c.req.url).origin}${continueUrl}`
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
    return renderProviderPicker(continueUrl)
  }

  const csrf = crypto.randomUUID()

  // Capture the requesting origin so the callback can redirect back and set the cookie
  // on the correct domain (e.g. headless.ly, not id.org.ai).
  const requestOrigin = new URL(c.req.url).origin
  const state = encodeLoginState(csrf, continueUrl, requestOrigin)

  // Store CSRF token for validation on callback (5 min TTL)
  const oauthStub = getStubForIdentity(c.env, 'oauth')
  await oauthStub.oauthStorageOp({
    op: 'put',
    key: `login-csrf:${csrf}`,
    value: { csrf, createdAt: Date.now() },
    options: { expirationTtl: 300 },
  })

  // Always use the canonical id.org.ai callback URL for WorkOS redirect.
  // When the request comes from a different domain (e.g. headless.ly via service binding),
  // we can't use that domain's callback URL because it's not registered in WorkOS.
  // The requesting origin is stored in state.origin for the cross-origin bounce after auth.
  const CANONICAL_ORIGINS = ['https://id.org.ai', 'https://oauth.dotdo.workers.dev']
  const callbackOrigin = CANONICAL_ORIGINS.includes(requestOrigin) ? requestOrigin : 'https://id.org.ai'
  const redirectUri = `${callbackOrigin}/api/callback`
  const authUrl = buildWorkOSAuthUrl(clientId, redirectUri, state, safeProvider)
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

  const { jwt, continueUrl } = stored.value as { jwt: string; continueUrl: string }

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
  let authResult
  try {
    authResult = await exchangeWorkOSOrgSelection(clientId, apiKey, pendingToken, organizationId, {
      userAgent: c.req.header('user-agent'),
      ipAddress: c.req.header('cf-connecting-ip') || c.req.header('x-forwarded-for'),
    })
  } catch (err: any) {
    return errorResponse(c, 502, ErrorCode.ServerError, err.message)
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

  const requestOrigin = new URL(c.req.url).origin
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
  if (!csrfData.value) {
    return errorResponse(c, 403, ErrorCode.Forbidden, 'Invalid or expired CSRF token — please try logging in again')
  }

  // Exchange code with WorkOS (or retrieve stored auth result from org selection)
  let authResult
  if (authResultKey) {
    // Coming back from org picker — retrieve stored auth result
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
    } catch (err: any) {
      // User belongs to multiple orgs — show org picker (don't consume CSRF yet)
      if (err.code === 'organization_selection_required') {
        const orgErr = err as OrgSelectionError
        return renderOrgPickerPage(orgErr, state)
      }
      return errorResponse(c, 502, ErrorCode.ServerError, err.message)
    }
  } else {
    return errorResponse(c, 400, ErrorCode.InvalidRequest, 'Missing code or _auth_result parameter')
  }

  // Now consume CSRF token (auth succeeded, no more retries needed)
  await oauthStub.oauthStorageOp({ op: 'delete', key: `login-csrf:${decoded.csrf}` })

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
  const signingManager = new SigningKeyManager((op) => oauthStub.oauthStorageOp(op))
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
    },
    { issuer: 'https://id.org.ai', expiresIn: 30 * 24 * 3600 },
  )

  const continueUrl = isSafeRedirectUrl(decoded.continue || '/') ? decoded.continue || '/' : '/'

  // ── Cross-origin redirect: bounce to the requesting domain to set cookie ─
  // If the login was initiated from a different domain (e.g. apis.do), we can't
  // set the cookie from oauth.do. Store a one-time code and redirect to the
  // origin's /callback so the cookie is set on the correct domain.
  const currentOrigin = new URL(c.req.url).origin
  if (decoded.origin && decoded.origin !== currentOrigin) {
    const oneTimeCode = crypto.randomUUID()
    await oauthStub.oauthStorageOp({
      op: 'put',
      key: `auth-code:${oneTimeCode}`,
      value: { jwt, continueUrl },
      options: { expirationTtl: 60 },
    })

    const callbackUrl = new URL('/callback', decoded.origin)
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
})

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

  const rawReturnUrl = c.req.query('return_url') || '/'
  const returnUrl = isSafeRedirectUrl(rawReturnUrl) ? rawReturnUrl : '/'
  const reqUrl = new URL(c.req.url)
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
    const oauthStub = getStubForIdentity(c.env, 'oauth')
    const manager = new SigningKeyManager((op) => oauthStub.oauthStorageOp(op))
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
    const oauthStub = getStubForIdentity(c.env, 'oauth')
    const manager = new SigningKeyManager((op) => oauthStub.oauthStorageOp(op))
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
    const oauthStub = getStubForIdentity(c.env, 'oauth')
    const manager = new SigningKeyManager((op) => oauthStub.oauthStorageOp(op))
    const jwks = await manager.getJWKS()
    const localJwks = jose.createLocalJWKSet(jwks)
    const { payload } = await jose.jwtVerify(jwt, localJwks, { issuer: 'https://id.org.ai' })

    if (!payload.sub) return c.json({ error: 'Unauthorized' }, 401)

    const identityId = `human:${payload.sub}`
    const identityStub = getStubForIdentity(c.env, identityId)
    const org = payload.org as { id?: string } | undefined
    const organizationId = org?.id || (payload.org_id as string) || undefined

    const token = await identityStub.refreshWorkOSToken(
      { clientId: c.env.WORKOS_CLIENT_ID, apiKey: c.env.WORKOS_API_KEY },
      organizationId,
    )

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
    const oauthStub = getStubForIdentity(c.env, 'oauth')
    const manager = new SigningKeyManager((op) => oauthStub.oauthStorageOp(op))
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
