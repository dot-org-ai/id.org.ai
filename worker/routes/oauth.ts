/**
 * OAuth 2.1 route module — register, authorize, token, device, userinfo, introspect, revoke
 * Extracted from worker/index.ts (Phase 7).
 * The /oauth/authorize and /device routes require authentication (mounted in worker/index.ts).
 */
import { Hono } from 'hono'
import type { Env, Variables } from '../types'
import { errorResponse, ErrorCode } from '../../src/sdk/errors'
import { getStubForIdentity } from '../middleware/tenant'
import { authenticateRequest } from '../middleware/auth'
import { OAuthProvider } from '../../src/sdk/oauth/provider'
import {
  generateCSRFToken,
  buildCSRFCookie,
  encodeStateWithCSRF,
  decodeStateWithCSRF,
  extractCSRFFromCookie,
} from '../../src/sdk/csrf'
import { AUDIT_EVENTS } from '../../src/sdk/audit'
import { SigningKeyManager } from '../../src/sdk/jwt/signing'

const app = new Hono<{ Bindings: Env; Variables: Variables }>()

// ── Helper ──────────────────────────────────────────────────────────────────

export function getOAuthProvider(c: any): OAuthProvider {
  // OAuth state (clients, tokens, consent) lives in a dedicated 'oauth' shard.
  // This is separate from identity sharding — OAuth is a system-level concern.
  const stub = getStubForIdentity(c.env, 'oauth')
  const signingKeyManager = new SigningKeyManager((op) => stub.oauthStorageOp(op))
  const base = 'https://id.org.ai'
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
      const identityStub = getStubForIdentity(c.env, id)
      const identity = await identityStub.getIdentity(id)
      if (!identity) return null
      return identity as unknown as { id: string; name?: string; handle?: string; email?: string; emailVerified?: boolean; image?: string; level?: number }
    },
    signingKeyManager,
  })
}

// ── Auth Middleware for OAuth routes ─────────────────────────────────────────
app.use('/oauth/authorize', authenticateRequest)
app.use('/device', authenticateRequest)

// ── Dynamic Client Registration (RFC 7591) ──────────────────────────────────
app.post('/oauth/register', async (c) => {
  const provider = getOAuthProvider(c)
  return provider.handleRegister(c.req.raw)
})

// Authorization Endpoint — CSRF protected
// On GET: generate a CSRF token, set it as a cookie, and embed it in the state parameter.
// On POST (consent submission): validate the CSRF token from cookie + form body.
app.get('/oauth/authorize', async (c) => {
  const auth = c.get('auth')
  const identityId = auth?.authenticated ? (auth.identityId ?? null) : null
  const oauthStub = getStubForIdentity(c.env, 'oauth')
  // Lazily seed web OAuth clients on first authorize request
  await oauthStub.ensureWebClients()

  // Skip CSRF wrapping for service binding callers — the proxy handles its own security
  const isServiceBinding = !!c.req.header('X-Issuer')

  if (isServiceBinding) {
    const provider = getOAuthProvider(c)
    return provider.handleAuthorize(c.req.raw, identityId)
  }

  // Generate CSRF token for the consent form (browser-direct requests only)
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
  const response = await provider.handleAuthorize(modifiedRequest, identityId)

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

  // Skip CSRF validation for service binding callers — the proxy handles its own security
  const isServiceBinding = !!c.req.header('X-Issuer')
  if (isServiceBinding) {
    const provider = getOAuthProvider(c)
    return provider.handleAuthorizeConsent(c.req.raw, auth.identityId)
  }

  // Extract CSRF token from cookie
  const cookieCSRF = extractCSRFFromCookie(c.req.raw)

  // Extract CSRF token from the state parameter in the form body
  const clonedRequest = c.req.raw.clone()
  const contentType = c.req.raw.headers.get('content-type') || ''
  let formState: string | undefined
  if (contentType.includes('application/json')) {
    const body = (await clonedRequest.json()) as Record<string, string>
    formState = body.state
  } else {
    const form = await clonedRequest.formData()
    formState = form.get('state') as string | undefined
  }

  let formCSRF: string | null = null
  if (formState) {
    const decoded = decodeStateWithCSRF(formState)
    if (decoded) {
      formCSRF = decoded.csrf
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

  const provider = getOAuthProvider(c)
  return provider.handleAuthorizeConsent(c.req.raw, auth.identityId)
})

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
  const tokenData = tokenResult.value as { identityId?: string; expiresAt?: number; scopes?: string[] } | undefined

  if (!tokenData) {
    return c.json({ error: 'invalid_token' }, 401)
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

  return c.json({
    sub: identity.id || tokenData.identityId,
    name: identity.name,
    email: identity.email,
    email_verified: identity.verified ?? false,
    org_id: identity.organizationId,
  })
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
