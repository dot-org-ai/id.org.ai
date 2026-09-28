/**
 * OAuth 2.1 route module — register, authorize, token, device, userinfo, introspect, revoke
 * Extracted from worker/index.ts (Phase 7).
 * The /oauth/authorize and /device routes require authentication (mounted in worker/index.ts).
 */
import { Hono } from 'hono'
import type { Env, Variables } from '../types'
import { errorResponse, ErrorCode } from '../../src/sdk/errors'
import { getStubForIdentity, getSigningKeyManager, readSessionSignIn } from '../middleware/tenant'
import { authenticateRequest } from '../middleware/auth'
import { parseCookieValue } from '../utils/cookies'
import { extractApiKey, extractSessionToken } from '../utils/extract'
import { OAuthProvider, applySignInClaims } from '../../src/sdk/oauth/provider'
import {
  generateCSRFToken,
  buildCSRFCookie,
  encodeStateWithCSRF,
  decodeStateWithCSRF,
  extractCSRFFromCookie,
  canonicalHostname,
} from '../../src/sdk/csrf'
import { AUDIT_EVENTS } from '../../src/sdk/audit'
import { indexClientOrigins } from '../utils/relying-parties'
import { mentionsSbScope } from '../../src/sdk/oauth/delegation'
import { fetchClientMetadataDocument } from '../utils/client-metadata'

const app = new Hono<{ Bindings: Env; Variables: Variables }>()

// ── Trusted-Account OAuth (ADR-0007) ────────────────────────────────────────
//
// Canonical shared client_id for in-Cloudflare-account consumers. Any request
// using this client_id is validated against the TRUSTED_ACCOUNT_DOMAINS env
// allowlist instead of a per-app DCR `redirect_uris` array.
//
// We pick option (b) from ADR-0007: bypass the DCR lookup entirely rather
// than provisioning a real `client:cid_trusted_account_v1` record. This keeps
// the diff small (no one-time bootstrap endpoint, no seeding step) and the
// virtual client's metadata is fully derivable from env config.
export const TRUSTED_ACCOUNT_CLIENT_ID = 'cid_trusted_account_v1'

/** Uncached Client ID Metadata Document fetches allowed per caller IP per window. */
const CIMD_FETCHES_PER_IP = 30
const CIMD_FETCH_WINDOW_MS = 10 * 60 * 1000

/** Parse a comma-separated env value into a Set of bare hostnames. */
export function parseTrustedAccountDomains(value: string | undefined): Set<string> {
  const set = new Set<string>()
  if (!value) return set
  for (const raw of value.split(',')) {
    // Canonical spelling (lowercase, no trailing dot), as every host compared
    // against this set is.
    const host = canonicalHostname(raw.trim())
    if (!host) continue
    // Defensive: reject obvious mistakes (schemes, paths) so a typo in
    // the env doesn't silently widen the trust boundary.
    if (host.includes('/') || host.includes(':') || host.includes(' ')) continue
    set.add(host)
  }
  return set
}

// ── Helper ──────────────────────────────────────────────────────────────────

export function getOAuthProvider(c: any): OAuthProvider {
  return createOAuthProvider(c.env, c.req.raw)
}

/**
 * The OAuth provider over the shared 'oauth' Durable Object shard. `request`
 * (optional) supplies the IP and user agent for audit events; RPC callers
 * (AuthService.exchangeToken) have none.
 */
export function createOAuthProvider(env: Env, request?: Request): OAuthProvider {
  // OAuth state (clients, tokens, consent) lives in a dedicated 'oauth' shard.
  // This is separate from identity sharding — OAuth is a system-level concern.
  const stub = getStubForIdentity(env, 'oauth')
  const signingKeyManager = getSigningKeyManager(env)
  const base = 'https://id.org.ai'
  const allowedDomains = parseTrustedAccountDomains(env.TRUSTED_ACCOUNT_DOMAINS)
  // ADR-0007 (BLOCKER 2): wire audit emission through the existing
  // IdentityDO RPC. The DO routes to AuditService which writes immutable
  // `audit:*` rows. Fire-and-forget on the provider side — the request
  // flow never blocks on audit success. We layer the request's IP and UA
  // onto the metadata-only event the provider constructs.
  const reqIp = request?.headers.get('cf-connecting-ip') ?? undefined
  const reqUa = request?.headers.get('user-agent') ?? undefined
  return new OAuthProvider({
    storage: {
      async get<T = unknown>(key: string): Promise<T | undefined> {
        const result = await stub.oauthStorageOp({ op: 'get', key })
        return result.value as T | undefined
      },
      async put(key: string, value: unknown, options?: { expirationTtl?: number }): Promise<void> {
        await stub.oauthStorageOp({ op: 'put', key, value, options })
      },
      async delete(key: string): Promise<boolean> {
        const result = await stub.oauthStorageOp({ op: 'delete', key })
        return !!result.deleted
      },
      async list<T = unknown>(options?: { prefix?: string; limit?: number }): Promise<Map<string, T>> {
        const result = await stub.oauthStorageOp({ op: 'list', options })
        return new Map(result.entries as Array<[string, T]>)
      },
      // Read-and-delete in one Durable Object call: authorization codes are
      // redeemed through this, so a code works exactly once.
      async take<T = unknown>(key: string): Promise<T | undefined> {
        const result = await stub.takeOnce({ key })
        return (result?.value ?? undefined) as T | undefined
      },
      // Atomic first claim (the DO's increment-and-check budget with max 1):
      // a refresh token rotates for exactly one of N parallel refreshes.
      async claimOnce(key: string, ttlMs: number): Promise<boolean> {
        const result = await stub.consumeBudget({ key, max: 1, windowMs: ttlMs })
        return result.allowed
      },
    },
    config: {
      issuer: base,
      authorizationEndpoint: `${base}/oauth/authorize`,
      tokenEndpoint: `${base}/oauth/token`,
      userinfoEndpoint: `${base}/oauth/userinfo`,
      registrationEndpoint: `${base}/oauth/register`,
      deviceAuthorizationEndpoint: `${base}/oauth/device`,
      revocationEndpoint: `${base}/oauth/revoke`,
      introspectionEndpoint: `${base}/oauth/introspect`,
      jwksUri: `${base}/.well-known/jwks.json`,
    },
    getIdentity: async (id: string) => {
      // Identity data lives in the identity's own shard, not in the oauth shard
      const identityStub = getStubForIdentity(env, id)
      const identity = await identityStub.getIdentity(id)
      if (!identity) return null
      // The stored Identity says `verified`; the provider reads `emailVerified`
      // for the id_token's email_verified claim. Without this mapping the
      // id_token never carried email_verified at all.
      const record = identity as unknown as { verified?: boolean; emailVerified?: boolean }
      return {
        ...(identity as unknown as { id: string; name?: string; handle?: string; email?: string; image?: string; level?: number }),
        emailVerified: record.emailVerified ?? record.verified ?? false,
      }
    },
    signingKeyManager,
    // Client ID Metadata Documents: an https client_id is fetched (SSRF-guarded),
    // at most CIMD_FETCHES_PER_IP uncached documents per caller IP per window,
    // so the unauthenticated authorize endpoint is not an open fetch relay.
    fetchClientMetadata: async (url: string) => {
      const ip = request?.headers.get('cf-connecting-ip') ?? 'no-ip'
      const budget = await stub.consumeBudget({ key: `cimd-fetch:${ip}`, max: CIMD_FETCHES_PER_IP, windowMs: CIMD_FETCH_WINDOW_MS })
      if (!budget.allowed) return { ok: false, error: 'too many client metadata fetches from this address; try again later', transient: true }
      return fetchClientMetadataDocument(url)
    },
    // ADR-0007: enable trusted-account mode only when the allowlist is non-empty.
    ...(allowedDomains.size > 0 && {
      trustedAccount: {
        clientId: TRUSTED_ACCOUNT_CLIENT_ID,
        allowedDomains,
      },
    }),
    // ADR-0007 (BLOCKER 2): trusted-account audit emission. The provider
    // only invokes this for trusted-account flows; DCR'd clients are
    // intentionally untouched.
    auditEmit: async (event) => {
      // logFireAndForget on the DO swallows errors; we add one more layer
      // here so even an RPC-level failure can't break /oauth/token.
      try {
        await stub.auditEvent({
          ...event,
          ip: event.ip ?? reqIp,
          userAgent: event.userAgent ?? reqUa,
        })
      } catch {
        // fire-and-forget
      }
    },
  })
}

// ── Auth Middleware for OAuth routes ─────────────────────────────────────────
app.use('/oauth/authorize', authenticateRequest)
app.use('/device', authenticateRequest)

// ── Dynamic Client Registration (RFC 7591) ──────────────────────────────────
app.post('/oauth/register', async (c) => {
  const provider = getOAuthProvider(c)
  const response = await provider.handleRegister(c.req.raw)
  // Remember the client's redirect origins so /login?continue= may return there
  // (worker/utils/relying-parties.ts). Best effort: registration never fails on it.
  if (response.status === 201) {
    try {
      const registered = (await response.clone().json()) as { client_id?: string; redirect_uris?: string[] }
      if (registered.client_id && Array.isArray(registered.redirect_uris)) {
        await indexClientOrigins(c.env, registered.client_id, registered.redirect_uris)
      }
    } catch (err) {
      console.error('[oauth/register] origin index failed:', err instanceof Error ? err.message : err)
    }
  }
  return response
})

// Authorization Endpoint — CSRF protected
// On GET: when (and only when) a consent page is shown, generate a CSRF token,
// set it as a cookie, and embed it in the consent form's state parameter.
// On POST (consent submission): validate the CSRF token from cookie + form body,
// then hand the provider the client's ORIGINAL state.
//
// The client must always get back exactly the `state` it sent. The wrapped
// value is internal to the consent round-trip; it never leaves in a redirect.
app.get('/oauth/authorize', async (c) => {
  const auth = c.get('auth')
  const identityId = auth?.authenticated ? (auth.identityId ?? null) : null
  const oauthStub = getStubForIdentity(c.env, 'oauth')
  // Lazily seed web OAuth clients on first authorize request
  await oauthStub.ensureWebClients()
  // How the browser session was established → amr / idp / auth_time on the tokens
  const signIn = identityId ? await readSessionSignIn(c.req.raw, c.env) : undefined

  // Skip CSRF wrapping for service binding callers — the proxy handles its own security
  const isServiceBinding = !!c.req.header('X-Issuer')
  // ADR-0007: also skip for the canonical trusted-account client. Trusted-
  // account clients have `client.trusted === true`, which makes provider.ts
  // (handleAuthorize, ~line 582) bypass the consent page and call
  // issueAuthorizationCode directly — there's no consent POST round-trip
  // where a wrapped state would be unwrapped, so the wrapped value would
  // leak straight through to the consumer's better-auth callback and fail
  // CSRF on that side. better-auth (and any standards-conformant OAuth
  // client) compares the returned `state` against the one it sent and
  // rejects on mismatch. Same failure mode as 08abc13 fixed for ChatGPT
  // via the X-Issuer path; same fix shape.
  const clientIdParam = new URL(c.req.url).searchParams.get('client_id') || ''
  const isTrustedAccount = clientIdParam === TRUSTED_ACCOUNT_CLIENT_ID

  // A request that asks for (or imitates) an sb scope never takes the
  // X-Issuer shortcut: X-Issuer is only a header, so its consent must carry the
  // CSRF binding like any browser consent (and the POST checks it).
  const asksSb = mentionsSbScope(new URL(c.req.url).searchParams.getAll('scope').join(' '))
  if ((isServiceBinding && !asksSb) || isTrustedAccount) {
    const provider = getOAuthProvider(c)
    return provider.handleAuthorize(c.req.raw, identityId, signIn)
  }

  // Resolve the request with the client's state untouched first. Only a consent
  // page needs the CSRF-bound state; a login redirect, an error redirect or an
  // issued code (consent already on record) must carry the client's own state.
  // Wrapping before this point leaked `base64url({csrf, s})` to every
  // registered client that had already consented, and double-wrapped the state
  // across the /login round-trip.
  const direct = await getOAuthProvider(c).handleAuthorize(c.req.raw, identityId, signIn)
  const isConsentPage = direct.status === 200 && (direct.headers.get('content-type') || '').includes('text/html')
  if (!isConsentPage) {
    return direct
  }

  // Consent page: generate a CSRF token for the consent form (browser-direct requests only)
  const csrfToken = generateCSRFToken()
  // Store the CSRF token in the oauth DO's storage via RPC
  await oauthStub.oauthStorageOp({
    op: 'put',
    key: `csrf:${csrfToken}`,
    value: { token: csrfToken, createdAt: Date.now(), expiresAt: Date.now() + 30 * 60 * 1000 },
  })

  // Inject the CSRF token into the state parameter
  const url = new URL(c.req.url)
  const originalState = url.searchParams.get('state') ?? undefined
  const stateWithCSRF = encodeStateWithCSRF(csrfToken, originalState)
  url.searchParams.set('state', stateWithCSRF)

  // Create a modified request with the CSRF-enhanced state
  const modifiedRequest = new Request(url.toString(), {
    method: c.req.raw.method,
    headers: c.req.raw.headers,
  })

  const provider = getOAuthProvider(c)
  const response = await provider.handleAuthorize(modifiedRequest, identityId, signIn)

  // Set the CSRF cookie on the response
  const isSecure = new URL(c.req.url).protocol === 'https:'
  const newResponse = new Response(response.body, response)
  newResponse.headers.append('Set-Cookie', buildCSRFCookie(csrfToken, isSecure))
  return newResponse
})

// Authorization Consent Submission — CSRF validated (skipped for service binding)
app.post('/oauth/authorize', async (c) => {
  const auth = c.get('auth')
  if (!auth?.authenticated || !auth.identityId) {
    return errorResponse(c, 401, ErrorCode.AuthenticationRequired, 'Authentication required to submit authorization consent')
  }

  const signIn = await readSessionSignIn(c.req.raw, c.env)

  // Read the posted form once (a clone): the scope decides which rules apply,
  // the state carries the CSRF token.
  const clonedRequest = c.req.raw.clone()
  const contentType = c.req.raw.headers.get('content-type') || ''
  let formState: string | undefined
  let formScope: string | undefined
  if (contentType.includes('application/json')) {
    const body = (await clonedRequest.json().catch(() => ({}))) as Record<string, unknown>
    formState = typeof body.state === 'string' ? body.state : undefined
    formScope = typeof body.scope === 'string' ? body.scope : undefined
  } else {
    const form = await clonedRequest.formData()
    formState = (form.get('state') as string | null) ?? undefined
    // Every value: this is only the route's early screen; the provider
    // enforces the same rule on the scopes it actually grants.
    formScope = form.getAll('scope').filter((v): v is string => typeof v === 'string').join(' ')
  }
  const asksSb = mentionsSbScope(formScope)

  // Delegating api.sb authority is a Person's act in their browser: the sb
  // consent is accepted only from the id.org.ai `auth` cookie session, never
  // from a bearer credential (an API key or session token held by an agent
  // must not be able to hand a client sb:do).
  // Tenant resolution takes an API key (header, X-API-Key, ?api_key=) or a
  // session token before the cookie, so any of those present means the
  // identity did not come from the browser session.
  const authCookie = parseCookieValue(c.req.header('cookie') ?? '', 'auth')
  const viaBrowserSession =
    !extractApiKey(c.req.raw) &&
    !extractSessionToken(c.req.raw) &&
    !c.req.header('authorization') &&
    !!authCookie &&
    isSessionCookieJwt(authCookie)
  if (asksSb && !viaBrowserSession) {
    return errorResponse(c, 403, ErrorCode.Forbidden, 'api.sb access can only be granted from a signed-in browser session')
  }

  // Skip CSRF validation for service binding callers — the proxy handles its own security.
  // Never for an sb consent (X-Issuer is only a header).
  const isServiceBinding = !!c.req.header('X-Issuer')
  if (isServiceBinding && !asksSb) {
    const provider = getOAuthProvider(c)
    // No CSRF check on this path, so never interactive: no sb scopes.
    return provider.handleAuthorizeConsent(c.req.raw, auth.identityId, signIn, { interactive: false })
  }

  // Extract CSRF token from cookie
  const cookieCSRF = extractCSRFFromCookie(c.req.raw)

  let formCSRF: string | null = null
  let originalState: string | undefined
  if (formState) {
    const decoded = decodeStateWithCSRF(formState)
    if (decoded) {
      formCSRF = decoded.csrf
      originalState = decoded.originalState
    }
  }

  // Validate CSRF double-submit: cookie token must match state-embedded token
  if (!cookieCSRF || !formCSRF || cookieCSRF !== formCSRF) {
    // Log the CSRF failure
    const auditStub = getStubForIdentity(c.env, 'oauth')
    await auditStub.oauthStorageOp({
      op: 'put',
      key: `audit:${new Date().toISOString()}:csrf.validation.failed:${crypto.randomUUID().slice(0, 8)}`,
      value: {
        event: AUDIT_EVENTS.CSRF_VALIDATION_FAILED,
        actor: auth.identityId,
        ip: c.req.raw.headers.get('cf-connecting-ip') ?? undefined,
        userAgent: c.req.raw.headers.get('user-agent') ?? undefined,
        timestamp: new Date().toISOString(),
      },
    })

    return errorResponse(c, 403, ErrorCode.Forbidden, 'CSRF token mismatch or missing')
  }

  // Validate the CSRF token server-side (check it exists and is not expired)
  const oauthStub = getStubForIdentity(c.env, 'oauth')
  const csrfData = await oauthStub.oauthStorageOp({ op: 'get', key: `csrf:${cookieCSRF}` })

  const csrfValue = csrfData.value as { expiresAt?: number } | undefined
  if (!csrfValue || (csrfValue.expiresAt && Date.now() > csrfValue.expiresAt)) {
    return errorResponse(c, 403, ErrorCode.Forbidden, csrfValue ? 'CSRF token expired' : 'Unknown CSRF token')
  }
  // Consume the token (one-time use)
  await oauthStub.oauthStorageOp({ op: 'delete', key: `csrf:${cookieCSRF}` })

  // Hand the provider the client's ORIGINAL state, so the redirect back to the
  // client carries exactly the state it sent (not the CSRF wrapper).
  const provider = getOAuthProvider(c)
  // CSRF verified above; interactive when the identity is the browser session.
  return provider.handleAuthorizeConsent(await withOriginalState(c.req.raw, contentType, originalState), auth.identityId, signIn, {
    interactive: viaBrowserSession,
  })
})

/**
 * Is the `auth` cookie shaped like an id.org.ai browser-session JWT (what
 * /api/callback and magic link sign), rather than some other
 * id.org.ai-signed JWT placed there? Tenant resolution has already verified
 * its signature and issuer; this looks at its shape. A session JWT carries no
 * `aud`, `nonce` or `at_hash`; an id_token (issued to a relying party) always
 * carries `aud` and `at_hash`; an access token is typ at+jwt. So an RP that
 * holds a Person's id_token cannot pose as that Person's browser to grant
 * sb scopes.
 */
function isSessionCookieJwt(jwt: string): boolean {
  const parts = jwt.split('.')
  if (parts.length !== 3) return false
  try {
    const dec = (s: string) => JSON.parse(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4)))
    const header = dec(parts[0]!) as Record<string, unknown>
    const payload = dec(parts[1]!) as Record<string, unknown>
    if (typeof header.typ === 'string' && header.typ.toLowerCase().replace(/^application\//, '') !== 'jwt') return false
    if ('crit' in header) return false
    return !('aud' in payload) && !('nonce' in payload) && !('at_hash' in payload)
  } catch {
    return false
  }
}

/** Rebuild a consent POST with `state` replaced by the client's original state. */
async function withOriginalState(request: Request, contentType: string, originalState: string | undefined): Promise<Request> {
  const headers = new Headers(request.headers)
  headers.delete('content-length')
  if (contentType.includes('application/json')) {
    const body = (await request.json()) as Record<string, unknown>
    if (originalState === undefined) delete body.state
    else body.state = originalState
    return new Request(request.url, { method: 'POST', headers, body: JSON.stringify(body) })
  }
  const form = await request.formData()
  const params = new URLSearchParams()
  for (const [key, value] of form.entries()) {
    if (key !== 'state' && typeof value === 'string') params.append(key, value)
  }
  if (originalState !== undefined) params.set('state', originalState)
  headers.set('content-type', 'application/x-www-form-urlencoded')
  return new Request(request.url, { method: 'POST', headers, body: params.toString() })
}

// Token Endpoint
app.post('/oauth/token', async (c) => {
  const provider = getOAuthProvider(c)
  return provider.handleToken(c.req.raw)
})

// Device Authorization (RFC 8628)
app.post('/oauth/device', async (c) => {
  // Lazily seed CLI clients on first device-flow request
  const oauthStub = getStubForIdentity(c.env, 'oauth')
  await oauthStub.ensureCliClient()
  await oauthStub.ensureOAuthDoClient()
  const provider = getOAuthProvider(c)
  return provider.handleDeviceAuthorization(c.req.raw)
})

// Device Verification (browser-side)
app.all('/device', async (c) => {
  const auth = c.get('auth')
  const identityId = auth?.authenticated ? (auth.identityId ?? null) : null
  const provider = getOAuthProvider(c)
  return provider.handleDeviceVerification(c.req.raw, identityId)
})

// UserInfo Endpoint (OIDC Core)
// Handled at the worker level (not delegated to OAuthProvider) because
// the identity lives in a sharded DO, not in the OAuth provider's storage.
app.get('/oauth/userinfo', async (c) => {
  const authHeader = c.req.header('authorization')
  if (!authHeader?.startsWith('Bearer ')) {
    return c.json({ error: 'invalid_token' }, 401)
  }

  const tokenId = authHeader.slice(7)

  // Look up the access token in the OAuth DO storage
  const oauthStub = getStubForIdentity(c.env, 'oauth')
  const tokenResult = await oauthStub.oauthStorageOp({ op: 'get', key: `access:${tokenId}` })
  const tokenData = tokenResult.value as
    | { identityId?: string; clientId?: string; expiresAt?: number; createdAt?: number; grantedAt?: number; family?: string; scopes?: string[]; signIn?: { amr?: string[]; idp?: string; authTime?: number } }
    | undefined

  if (!tokenData) {
    return c.json({ error: 'invalid_token' }, 401)
  }
  if (
    await getOAuthProvider(c).isTokenRevoked({
      identityId: tokenData.identityId,
      clientId: tokenData.clientId ?? '',
      createdAt: tokenData.createdAt ?? 0,
      grantedAt: tokenData.grantedAt,
      family: tokenData.family,
    })
  ) {
    return c.json({ error: 'invalid_token', error_description: 'Token has been revoked' }, 401)
  }

  if (tokenData.expiresAt && tokenData.expiresAt < Date.now()) {
    return c.json({ error: 'invalid_token', error_description: 'Token has expired' }, 401)
  }

  if (!tokenData.identityId) {
    return c.json({ error: 'invalid_token', error_description: 'No identity associated' }, 401)
  }

  // Resolve identity from the correct DO shard
  const identityStub = getStubForIdentity(c.env, tokenData.identityId)
  const identity = await identityStub.getIdentity(tokenData.identityId)

  if (!identity) {
    return c.json({ error: 'invalid_token', error_description: 'Identity not found' }, 401)
  }

  const claims: Record<string, unknown> = {
    sub: identity.id || tokenData.identityId,
    name: identity.name,
    email: identity.email,
    email_verified: identity.verified ?? false,
    org_id: identity.organizationId,
  }
  // How the person signed in (amr / idp / auth_time), when the token carries it
  applySignInClaims(claims, tokenData.signIn)
  return c.json(claims)
})

// Token Introspection (RFC 7662)
app.post('/oauth/introspect', async (c) => {
  const provider = getOAuthProvider(c)
  return provider.handleIntrospect(c.req.raw)
})

// Token Revocation (RFC 7009)
app.post('/oauth/revoke', async (c) => {
  const provider = getOAuthProvider(c)
  return provider.handleRevoke(c.req.raw)
})

// Fallback for unhandled /oauth/* routes
app.all('/oauth/*', async (c) => {
  return errorResponse(c, 404, ErrorCode.NotFound, 'OAuth endpoint not found')
})

export { app as oauthRoutes }
