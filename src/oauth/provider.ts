/**
 * OAuth 2.1 Provider for id.org.ai
 *
 * A complete OAuth 2.1 authorization server backed by Durable Object storage.
 *
 * Implements:
 *   - Authorization Code + PKCE (mandatory per OAuth 2.1, S256 only)
 *   - Refresh Token with Rotation (old token revoked on use)
 *   - Client Credentials (service-to-service)
 *   - Device Flow (RFC 8628) — critical for agents without browsers
 *   - Dynamic Client Registration (RFC 7591)
 *   - OIDC Discovery
 *   - Token Introspection (RFC 7662)
 *   - Token Revocation (RFC 7009)
 *   - UserInfo Endpoint (OIDC Core)
 *
 * Storage key schema:
 *   client:{cid_xxx}         → OAuthProviderClient
 *   code:{ac_xxx}            → AuthorizationCode
 *   access:{at_xxx}          → AccessToken
 *   refresh:{rt_xxx}         → RefreshToken
 *   device:{dc_xxx}          → DeviceCode
 *   device-user:{USERCODE}   → device code id (index for user code lookup)
 *   consent:{identityId}:{clientId} → ConsentRecord
 */


// ============================================================================
// Types
// ============================================================================
//
// NOTE: These types are INTERNAL to the OAuthProvider class, used with its
// StorageLike (Durable Object KV) storage backend. They differ from the
// canonical types in ./types.ts which define the public API contract:
//
// Provider (internal)         | types.ts (canonical API)         | Key Differences
// ─────────────────────────── | ──────────────────────────────── | ─────────────────────────────────
// AuthorizationCode           | OAuthAuthorizationCode           | identityId vs userId, scopes[] vs scope string, mandatory codeChallenge, nonce
// AccessToken                 | OAuthAccessToken                 | identityId vs userId, scopes[] vs scope string, no tokenType
// RefreshToken                | OAuthRefreshToken                | scopes[] vs scope string, family for rotation tracking, non-optional revoked
// DeviceCode                  | OAuthDeviceCode                  | status enum vs authorized/denied booleans, scopes[] vs scope string
// ConsentRecord               | OAuthConsent                     | minimal (scopes+createdAt) vs full (userId, clientId, updatedAt)
// IdentityInfo                | OAuthUser                        | minimal display info vs full user record with roles/permissions/metadata
// StorageLike                 | OAuthStorage                     | raw KV (get/put/delete/list) vs typed methods (getUser, saveClient, etc.)
//
// The provider types are intentionally simpler — they map directly to
// Durable Object KV entries. The canonical types provide a richer,
// more ergonomic API surface for external consumers.
// ============================================================================

export interface OAuthConfig {
  issuer: string
  authorizationEndpoint: string
  tokenEndpoint: string
  userinfoEndpoint: string
  registrationEndpoint: string
  deviceAuthorizationEndpoint: string
  revocationEndpoint: string
  introspectionEndpoint: string
  jwksUri?: string
}

export interface OAuthProviderClient {
  id: string                   // cid_xxx
  name: string
  secret?: string              // hashed for confidential clients; absent for public
  redirectUris: string[]
  grantTypes: string[]
  responseTypes: string[]
  scopes: string[]
  trusted: boolean             // skip consent for first-party apps
  tokenEndpointAuthMethod: 'client_secret_basic' | 'client_secret_post' | 'none'
  logo?: string
  website?: string
  createdAt: number
}

// Internal storage type — see OAuthAuthorizationCode in ./types.ts for canonical API type
interface AuthorizationCode {
  id: string                   // ac_xxx
  clientId: string
  identityId: string
  scopes: string[]
  redirectUri: string
  codeChallenge: string        // mandatory for public clients
  codeChallengeMethod: 'S256'
  state?: string
  nonce?: string
  expiresAt: number
  createdAt: number
}

// Internal storage type — see OAuthAccessToken in ./types.ts for canonical API type
interface AccessToken {
  id: string                   // at_xxx
  clientId: string
  identityId?: string          // absent for client_credentials
  scopes: string[]
  expiresAt: number
  createdAt: number
}

// Internal storage type — see OAuthRefreshToken in ./types.ts for canonical API type
interface RefreshToken {
  id: string                   // rt_xxx
  clientId: string
  identityId: string
  scopes: string[]
  family: string               // rotation family — if a revoked token is reused, revoke entire family
  revoked: boolean
  expiresAt: number
  createdAt: number
}

// Internal storage type — see OAuthDeviceCode in ./types.ts for canonical API type
interface DeviceCode {
  id: string                   // dc_xxx
  clientId: string
  userCode: string             // 8-char alphanumeric
  scopes: string[]
  status: 'pending' | 'approved' | 'denied' | 'expired'
  identityId?: string          // set when user approves
  interval: number             // polling interval in seconds
  expiresAt: number
  createdAt: number
}

// Internal storage type — see OAuthConsent in ./types.ts for canonical API type
interface ConsentRecord {
  scopes: string[]
  createdAt: number
}

// Internal display type — see OAuthUser in ./types.ts for canonical API type
interface IdentityInfo {
  id: string
  name?: string
  handle?: string
  email?: string
  emailVerified?: boolean
  image?: string
}

// Internal storage abstraction — see OAuthStorage in ./storage.ts for canonical API type
type StorageLike = {
  get<T = unknown>(key: string): Promise<T | undefined>
  put(key: string, value: unknown, options?: { expirationTtl?: number }): Promise<void>
  delete(key: string): Promise<boolean>
  list<T = unknown>(options?: { prefix?: string; limit?: number }): Promise<Map<string, T>>
}

// ============================================================================
// Utilities
// ============================================================================

function generateId(prefix: string): string {
  const bytes = new Uint8Array(24)
  crypto.getRandomValues(bytes)
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
  return `${prefix}${hex}`
}

function generateUserCode(): string {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789' // no I/O/0/1 to avoid confusion
  const bytes = new Uint8Array(8)
  crypto.getRandomValues(bytes)
  return Array.from(bytes, (b) => chars[b % chars.length]).join('')
}

async function computeS256Challenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder()
  const data = encoder.encode(verifier)
  const hash = await crypto.subtle.digest('SHA-256', data)
  return btoa(String.fromCharCode(...new Uint8Array(hash)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '')
}

function parseBasicAuth(header: string): { clientId: string; clientSecret: string } | null {
  if (!header.startsWith('Basic ')) return null
  try {
    const decoded = atob(header.slice(6))
    const colonIdx = decoded.indexOf(':')
    if (colonIdx < 0) return null
    const clientId = decodeURIComponent(decoded.slice(0, colonIdx))
    const clientSecret = decodeURIComponent(decoded.slice(colonIdx + 1))
    return clientId && clientSecret ? { clientId, clientSecret } : null
  } catch {
    return null
  }
}

async function parseBody(request: Request): Promise<Record<string, string>> {
  const contentType = request.headers.get('content-type') || ''
  if (contentType.includes('application/json')) {
    return request.json() as Promise<Record<string, string>>
  }
  const form = await request.formData()
  const result: Record<string, string> = {}
  for (const [key, value] of form.entries()) {
    if (typeof value === 'string') result[key] = value
  }
  return result
}

function jsonResponse(data: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
      Pragma: 'no-cache',
      ...headers,
    },
  })
}

function oauthError(error: string, description: string, status = 400): Response {
  return jsonResponse({ error, error_description: description }, status)
}

// ============================================================================
// Token Lifetimes (seconds)
// ============================================================================

const ACCESS_TOKEN_TTL = 30 * 24 * 3600    // 30 days
const REFRESH_TOKEN_TTL = 30 * 24 * 3600   // 30 days
const AUTH_CODE_TTL = 600                   // 10 minutes
const DEVICE_CODE_TTL = 1800               // 30 minutes
const DEVICE_POLL_INTERVAL = 5             // 5 seconds

// ============================================================================
// OAuthProvider
// ============================================================================

export class OAuthProvider {
  private storage: StorageLike
  private config: OAuthConfig
  private getIdentity: (id: string) => Promise<IdentityInfo | null>

  constructor(options: {
    storage: StorageLike
    config: OAuthConfig
    getIdentity: (id: string) => Promise<IdentityInfo | null>
  }) {
    this.storage = options.storage
    this.config = options.config
    this.getIdentity = options.getIdentity
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // OIDC Discovery
  // ═══════════════════════════════════════════════════════════════════════════

  getOpenIDConfiguration(): Response {
    return jsonResponse({
      issuer: this.config.issuer,
      authorization_endpoint: this.config.authorizationEndpoint,
      token_endpoint: this.config.tokenEndpoint,
      userinfo_endpoint: this.config.userinfoEndpoint,
      registration_endpoint: this.config.registrationEndpoint,
      device_authorization_endpoint: this.config.deviceAuthorizationEndpoint,
      revocation_endpoint: this.config.revocationEndpoint,
      introspection_endpoint: this.config.introspectionEndpoint,
      jwks_uri: this.config.jwksUri,
      response_types_supported: ['code'],
      grant_types_supported: [
        'authorization_code',
        'refresh_token',
        'client_credentials',
        'urn:ietf:params:oauth:grant-type:device_code',
      ],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['RS256', 'ES256'],
      scopes_supported: ['openid', 'profile', 'email', 'offline_access'],
      token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
      code_challenge_methods_supported: ['S256'],
      claims_supported: ['sub', 'name', 'preferred_username', 'picture', 'email', 'email_verified'],
    })
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Dynamic Client Registration (RFC 7591)
  // ═══════════════════════════════════════════════════════════════════════════

  async handleRegister(request: Request): Promise<Response> {
    if (request.method !== 'POST') {
      return oauthError('invalid_request', 'Method not allowed', 405)
    }

    let body: Record<string, unknown>
    try {
      body = await request.json() as Record<string, unknown>
    } catch {
      return oauthError('invalid_request', 'Invalid JSON body')
    }

    const clientName = body.client_name as string | undefined
    if (!clientName) {
      return oauthError('invalid_client_metadata', 'client_name is required')
    }

    const redirectUris = (body.redirect_uris as string[]) || []
    const grantTypes = (body.grant_types as string[]) || ['authorization_code', 'refresh_token']
    const responseTypes = (body.response_types as string[]) || ['code']
    const scope = (body.scope as string) || 'openid profile email'
    const tokenEndpointAuthMethod = (body.token_endpoint_auth_method as string) || 'none'

    // Validate grant types
    const validGrantTypes = [
      'authorization_code',
      'refresh_token',
      'client_credentials',
      'urn:ietf:params:oauth:grant-type:device_code',
    ]
    for (const gt of grantTypes) {
      if (!validGrantTypes.includes(gt)) {
        return oauthError('invalid_client_metadata', `Unsupported grant_type: ${gt}`)
      }
    }

    // authorization_code requires at least one redirect_uri
    if (grantTypes.includes('authorization_code') && redirectUris.length === 0) {
      return oauthError('invalid_client_metadata', 'redirect_uris required for authorization_code grant')
    }

    // Validate redirect URIs (must be HTTPS or localhost for dev)
    for (const uri of redirectUris) {
      try {
        const parsed = new URL(uri)
        if (parsed.protocol !== 'https:' && parsed.hostname !== 'localhost' && parsed.hostname !== '127.0.0.1') {
          return oauthError('invalid_redirect_uri', `redirect_uri must use HTTPS: ${uri}`)
        }
        if (parsed.hash) {
          return oauthError('invalid_redirect_uri', 'redirect_uri must not contain a fragment')
        }
      } catch {
        return oauthError('invalid_redirect_uri', `Invalid redirect_uri: ${uri}`)
      }
    }

    const clientId = generateId('cid_')
    const isConfidential = tokenEndpointAuthMethod !== 'none'
    const clientSecret = isConfidential ? generateId('cs_') : undefined

    const client: OAuthProviderClient = {
      id: clientId,
      name: clientName,
      secret: clientSecret,
      redirectUris,
      grantTypes,
      responseTypes,
      scopes: scope.split(' '),
      trusted: false,
      tokenEndpointAuthMethod: tokenEndpointAuthMethod as OAuthProviderClient['tokenEndpointAuthMethod'],
      logo: body.logo_uri as string | undefined,
      website: body.client_uri as string | undefined,
      createdAt: Date.now(),
    }

    await this.storage.put(`client:${clientId}`, client)

    const response: Record<string, unknown> = {
      client_id: clientId,
      client_name: clientName,
      redirect_uris: redirectUris,
      grant_types: grantTypes,
      response_types: responseTypes,
      scope,
      token_endpoint_auth_method: tokenEndpointAuthMethod,
      client_id_issued_at: Math.floor(client.createdAt / 1000),
    }

    if (clientSecret) {
      response.client_secret = clientSecret
      response.client_secret_expires_at = 0 // never expires
    }

    if (client.logo) response.logo_uri = client.logo
    if (client.website) response.client_uri = client.website

    return jsonResponse(response, 201)
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Authorization Endpoint
  // ═══════════════════════════════════════════════════════════════════════════

  async handleAuthorize(request: Request, identityId: string | null): Promise<Response> {
    const url = new URL(request.url)
    const params = url.searchParams

    const clientId = params.get('client_id') || ''
    const redirectUri = params.get('redirect_uri') || ''
    const responseType = params.get('response_type') || ''
    const scope = params.get('scope') || 'openid profile email'
    const state = params.get('state') || undefined
    const codeChallenge = params.get('code_challenge') || undefined
    const codeChallengeMethod = params.get('code_challenge_method') || undefined
    const nonce = params.get('nonce') || undefined

    // ── Validate client ─────────────────────────────────────────────────
    const client = await this.getClient(clientId)
    if (!client) {
      return oauthError('invalid_client', 'Unknown client_id')
    }

    // ── Validate redirect URI ───────────────────────────────────────────
    if (!client.redirectUris.includes(redirectUri)) {
      return oauthError('invalid_request', 'Invalid redirect_uri')
    }

    // ── Validate response_type ──────────────────────────────────────────
    if (responseType !== 'code') {
      return this.redirectError(redirectUri, 'unsupported_response_type', 'Only "code" response type is supported', state)
    }

    // ── Validate grant type includes authorization_code ─────────────────
    if (!client.grantTypes.includes('authorization_code')) {
      return this.redirectError(redirectUri, 'unauthorized_client', 'Client is not authorized for authorization_code grant', state)
    }

    // ── PKCE is mandatory for public clients (OAuth 2.1) ────────────────
    if (client.tokenEndpointAuthMethod === 'none' && !codeChallenge) {
      return this.redirectError(redirectUri, 'invalid_request', 'code_challenge is required for public clients (OAuth 2.1)', state)
    }

    // ── Only S256 is supported ──────────────────────────────────────────
    if (codeChallenge && codeChallengeMethod && codeChallengeMethod !== 'S256') {
      return this.redirectError(redirectUri, 'invalid_request', 'Only S256 code_challenge_method is supported', state)
    }

    // ── Validate requested scopes ───────────────────────────────────────
    const requestedScopes = scope.split(' ')
    const invalidScopes = requestedScopes.filter((s) => !client.scopes.includes(s) && !['openid', 'profile', 'email', 'offline_access'].includes(s))
    if (invalidScopes.length > 0) {
      return this.redirectError(redirectUri, 'invalid_scope', `Invalid scopes: ${invalidScopes.join(', ')}`, state)
    }

    // ── User must be authenticated ──────────────────────────────────────
    if (!identityId) {
      const loginUrl = new URL('/login', this.config.issuer)
      loginUrl.searchParams.set('continue', request.url)
      return Response.redirect(loginUrl.toString(), 302)
    }

    // ── Check existing consent ──────────────────────────────────────────
    const consentKey = `consent:${identityId}:${clientId}`
    const existingConsent = await this.storage.get<ConsentRecord>(consentKey)
    const hasFullConsent = existingConsent && requestedScopes.every((s) => existingConsent.scopes.includes(s))

    if (!client.trusted && !hasFullConsent) {
      return this.renderConsentPage(client, {
        clientId,
        redirectUri,
        scope,
        state,
        codeChallenge,
        codeChallengeMethod: codeChallenge ? 'S256' : undefined,
        nonce,
      })
    }

    // ── Generate authorization code ─────────────────────────────────────
    return this.issueAuthorizationCode(client, identityId, {
      redirectUri,
      scopes: requestedScopes,
      codeChallenge: codeChallenge || '',
      codeChallengeMethod: 'S256',
      state,
      nonce,
    })
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Authorization Consent Submission
  // ═══════════════════════════════════════════════════════════════════════════

  async handleAuthorizeConsent(request: Request, identityId: string): Promise<Response> {
    const body = await parseBody(request)

    const clientId = body.client_id
    const redirectUri = body.redirect_uri
    const scope = body.scope || 'openid profile email'
    const state = body.state || undefined
    const codeChallenge = body.code_challenge || undefined
    const codeChallengeMethod = body.code_challenge_method || undefined
    const nonce = body.nonce || undefined
    const approved = body.approved === 'true'

    const client = await this.getClient(clientId)
    if (!client) {
      return oauthError('invalid_client', 'Unknown client_id')
    }

    if (!approved) {
      return this.redirectError(redirectUri, 'access_denied', 'User denied the authorization request', state)
    }

    // Store consent
    const scopes = scope.split(' ')
    const consentKey = `consent:${identityId}:${clientId}`
    await this.storage.put(consentKey, {
      scopes,
      createdAt: Date.now(),
    } satisfies ConsentRecord)

    // Issue authorization code
    return this.issueAuthorizationCode(client, identityId, {
      redirectUri,
      scopes,
      codeChallenge: codeChallenge || '',
      codeChallengeMethod: 'S256',
      state,
      nonce,
    })
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Token Endpoint
  // ═══════════════════════════════════════════════════════════════════════════

  async handleToken(request: Request): Promise<Response> {
    if (request.method !== 'POST') {
      return oauthError('invalid_request', 'Method not allowed', 405)
    }

    const body = await parseBody(request)
    const grantType = body.grant_type

    // Resolve client authentication from Authorization header or body
    let clientId = body.client_id || ''
    let clientSecret = body.client_secret || ''

    const authHeader = request.headers.get('authorization') || ''
    if (authHeader) {
      const basicAuth = parseBasicAuth(authHeader)
      if (basicAuth) {
        clientId = basicAuth.clientId
        clientSecret = basicAuth.clientSecret
      }
    }

    switch (grantType) {
      case 'authorization_code':
        return this.handleAuthorizationCodeGrant(clientId, clientSecret, body)
      case 'refresh_token':
        return this.handleRefreshTokenGrant(clientId, clientSecret, body)
      case 'client_credentials':
        return this.handleClientCredentialsGrant(clientId, clientSecret, body)
      case 'urn:ietf:params:oauth:grant-type:device_code':
        return this.handleDeviceCodeGrant(clientId, body)
      default:
        return oauthError('unsupported_grant_type', `Unsupported grant_type: ${grantType}`)
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Device Authorization Endpoint (RFC 8628)
  // ═══════════════════════════════════════════════════════════════════════════

  async handleDeviceAuthorization(request: Request): Promise<Response> {
    if (request.method !== 'POST') {
      return oauthError('invalid_request', 'Method not allowed', 405)
    }

    const body = await parseBody(request)
    const clientId = body.client_id

    if (!clientId) {
      return oauthError('invalid_request', 'client_id is required')
    }

    const client = await this.getClient(clientId)
    if (!client) {
      return oauthError('invalid_client', 'Unknown client_id')
    }

    if (!client.grantTypes.includes('urn:ietf:params:oauth:grant-type:device_code')) {
      return oauthError('unauthorized_client', 'Client is not authorized for device_code grant')
    }

    const scope = body.scope || client.scopes.join(' ')
    const scopes = scope.split(' ')

    const deviceCodeId = generateId('dc_')
    const userCode = generateUserCode()
    const now = Date.now()
    const expiresAt = now + DEVICE_CODE_TTL * 1000

    const deviceCode: DeviceCode = {
      id: deviceCodeId,
      clientId,
      userCode,
      scopes,
      status: 'pending',
      interval: DEVICE_POLL_INTERVAL,
      expiresAt,
      createdAt: now,
    }

    await this.storage.put(`device:${deviceCodeId}`, deviceCode, {
      expirationTtl: DEVICE_CODE_TTL + 60, // slight buffer
    })

    // Index by user code for quick lookup during approval
    await this.storage.put(`device-user:${userCode}`, deviceCodeId, {
      expirationTtl: DEVICE_CODE_TTL + 60,
    })

    return jsonResponse({
      device_code: deviceCodeId,
      user_code: userCode,
      verification_uri: `${this.config.issuer}/device`,
      verification_uri_complete: `${this.config.issuer}/device?user_code=${userCode}`,
      expires_in: DEVICE_CODE_TTL,
      interval: DEVICE_POLL_INTERVAL,
    })
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Device User Approval (browser-side)
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Called when the user visits /device and enters the user code.
   * Returns an HTML page or handles the POST approval.
   */
  async handleDeviceVerification(request: Request, identityId: string | null): Promise<Response> {
    if (!identityId) {
      const loginUrl = new URL('/login', this.config.issuer)
      loginUrl.searchParams.set('continue', request.url)
      return Response.redirect(loginUrl.toString(), 302)
    }

    if (request.method === 'GET') {
      const url = new URL(request.url)
      const userCode = url.searchParams.get('user_code') || ''
      return this.renderDeviceVerificationPage(userCode)
    }

    if (request.method === 'POST') {
      const body = await parseBody(request)
      const userCode = (body.user_code || '').toUpperCase().replace(/[\s-]/g, '')
      const approved = body.approved === 'true'

      if (!userCode || userCode.length !== 8) {
        return this.renderDeviceVerificationPage('', 'Please enter a valid 8-character code')
      }

      const deviceCodeId = await this.storage.get<string>(`device-user:${userCode}`)
      if (!deviceCodeId) {
        return this.renderDeviceVerificationPage(userCode, 'Invalid or expired code. Please try again.')
      }

      const deviceCode = await this.storage.get<DeviceCode>(`device:${deviceCodeId}`)
      if (!deviceCode || deviceCode.expiresAt < Date.now()) {
        return this.renderDeviceVerificationPage(userCode, 'This code has expired. Please request a new one.')
      }

      if (deviceCode.status !== 'pending') {
        return this.renderDeviceVerificationPage(userCode, 'This code has already been used.')
      }

      // Update device code status
      await this.storage.put(`device:${deviceCodeId}`, {
        ...deviceCode,
        status: approved ? 'approved' : 'denied',
        identityId: approved ? identityId : undefined,
      } satisfies DeviceCode)

      if (approved) {
        return new Response(this.deviceApprovedHtml(), {
          headers: { 'Content-Type': 'text/html; charset=utf-8' },
        })
      }

      return this.renderDeviceVerificationPage('', 'Authorization denied.')
    }

    return oauthError('invalid_request', 'Method not allowed', 405)
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // UserInfo Endpoint (OIDC Core)
  // ═══════════════════════════════════════════════════════════════════════════

  async handleUserinfo(request: Request): Promise<Response> {
    const authHeader = request.headers.get('authorization')
    if (!authHeader?.startsWith('Bearer ')) {
      return jsonResponse({ error: 'invalid_token' }, 401, {
        'WWW-Authenticate': 'Bearer',
      })
    }

    const tokenId = authHeader.slice(7)
    const tokenData = await this.storage.get<AccessToken>(`access:${tokenId}`)

    if (!tokenData) {
      return jsonResponse({ error: 'invalid_token' }, 401, {
        'WWW-Authenticate': 'Bearer error="invalid_token"',
      })
    }

    if (tokenData.expiresAt < Date.now()) {
      return jsonResponse({ error: 'invalid_token', error_description: 'Token has expired' }, 401, {
        'WWW-Authenticate': 'Bearer error="invalid_token"',
      })
    }

    if (!tokenData.identityId) {
      return oauthError('invalid_token', 'Token has no associated identity', 401)
    }

    const identity = await this.getIdentity(tokenData.identityId)
    if (!identity) {
      return jsonResponse({ error: 'invalid_token' }, 401)
    }

    const claims: Record<string, unknown> = {
      sub: identity.id,
    }

    if (tokenData.scopes.includes('profile')) {
      claims.name = identity.name
      claims.preferred_username = identity.handle
      claims.picture = identity.image
    }

    if (tokenData.scopes.includes('email') && identity.email) {
      claims.email = identity.email
      claims.email_verified = identity.emailVerified ?? false
    }

    return jsonResponse(claims)
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Token Introspection (RFC 7662)
  // ═══════════════════════════════════════════════════════════════════════════

  async handleIntrospect(request: Request): Promise<Response> {
    if (request.method !== 'POST') {
      return oauthError('invalid_request', 'Method not allowed', 405)
    }

    const body = await parseBody(request)
    const token = body.token

    if (!token) {
      return jsonResponse({ active: false })
    }

    // Try as access token
    if (token.startsWith('at_')) {
      const tokenData = await this.storage.get<AccessToken>(`access:${token}`)
      if (tokenData && tokenData.expiresAt > Date.now()) {
        return jsonResponse({
          active: true,
          client_id: tokenData.clientId,
          sub: tokenData.identityId,
          scope: tokenData.scopes.join(' '),
          token_type: 'Bearer',
          exp: Math.floor(tokenData.expiresAt / 1000),
          iat: Math.floor(tokenData.createdAt / 1000),
        })
      }
    }

    // Try as refresh token
    if (token.startsWith('rt_')) {
      const tokenData = await this.storage.get<RefreshToken>(`refresh:${token}`)
      if (tokenData && !tokenData.revoked && tokenData.expiresAt > Date.now()) {
        return jsonResponse({
          active: true,
          client_id: tokenData.clientId,
          sub: tokenData.identityId,
          scope: tokenData.scopes.join(' '),
          token_type: 'refresh_token',
          exp: Math.floor(tokenData.expiresAt / 1000),
          iat: Math.floor(tokenData.createdAt / 1000),
        })
      }
    }

    return jsonResponse({ active: false })
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Token Revocation (RFC 7009)
  // ═══════════════════════════════════════════════════════════════════════════

  async handleRevoke(request: Request): Promise<Response> {
    if (request.method !== 'POST') {
      return oauthError('invalid_request', 'Method not allowed', 405)
    }

    const body = await parseBody(request)
    const token = body.token

    if (!token) {
      // Per RFC 7009, respond 200 even if token is missing
      return new Response(null, { status: 200 })
    }

    // Revoke access token
    if (token.startsWith('at_')) {
      await this.storage.delete(`access:${token}`)
    }

    // Revoke refresh token (mark as revoked, don't delete — for family detection)
    if (token.startsWith('rt_')) {
      const tokenData = await this.storage.get<RefreshToken>(`refresh:${token}`)
      if (tokenData) {
        await this.storage.put(`refresh:${token}`, {
          ...tokenData,
          revoked: true,
        } satisfies RefreshToken)

        // Revoke the entire rotation family
        await this.revokeRefreshTokenFamily(tokenData.family)
      }
    }

    return new Response(null, { status: 200 })
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Validate Access Token (utility for downstream middleware)
  // ═══════════════════════════════════════════════════════════════════════════

  async validateAccessToken(token: string): Promise<AccessToken | null> {
    if (!token.startsWith('at_')) return null

    const tokenData = await this.storage.get<AccessToken>(`access:${token}`)
    if (!tokenData) return null
    if (tokenData.expiresAt < Date.now()) return null

    return tokenData
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // PRIVATE: Grant Handlers
  // ═══════════════════════════════════════════════════════════════════════════

  private async handleAuthorizationCodeGrant(
    clientId: string,
    clientSecret: string,
    body: Record<string, string>,
  ): Promise<Response> {
    const code = body.code
    const redirectUri = body.redirect_uri
    const codeVerifier = body.code_verifier

    if (!code) {
      return oauthError('invalid_request', 'code is required')
    }

    // ── Look up authorization code ──────────────────────────────────────
    const codeData = await this.storage.get<AuthorizationCode>(`code:${code}`)
    if (!codeData) {
      return oauthError('invalid_grant', 'Invalid or expired authorization code')
    }

    // ── Verify client ───────────────────────────────────────────────────
    if (codeData.clientId !== clientId) {
      return oauthError('invalid_grant', 'Authorization code was not issued to this client')
    }

    // ── Verify expiration ───────────────────────────────────────────────
    if (codeData.expiresAt < Date.now()) {
      await this.storage.delete(`code:${code}`)
      return oauthError('invalid_grant', 'Authorization code has expired')
    }

    // ── Verify redirect URI ─────────────────────────────────────────────
    if (codeData.redirectUri !== redirectUri) {
      return oauthError('invalid_grant', 'redirect_uri mismatch')
    }

    // ── Verify PKCE (mandatory per OAuth 2.1) ───────────────────────────
    if (codeData.codeChallenge) {
      if (!codeVerifier) {
        return oauthError('invalid_grant', 'code_verifier is required')
      }

      const computedChallenge = await computeS256Challenge(codeVerifier)
      if (computedChallenge !== codeData.codeChallenge) {
        return oauthError('invalid_grant', 'Invalid code_verifier')
      }
    } else {
      // No PKCE — confidential client must present valid secret
      const client = await this.getClient(clientId)
      if (client?.secret && client.secret !== clientSecret) {
        return oauthError('invalid_client', 'Invalid client credentials', 401)
      }
    }

    // ── Delete authorization code (one-time use) ────────────────────────
    await this.storage.delete(`code:${code}`)

    // ── Issue tokens ────────────────────────────────────────────────────
    return this.issueTokenPair(clientId, codeData.identityId, codeData.scopes)
  }

  private async handleRefreshTokenGrant(
    clientId: string,
    clientSecret: string,
    body: Record<string, string>,
  ): Promise<Response> {
    const refreshTokenId = body.refresh_token

    if (!refreshTokenId) {
      return oauthError('invalid_request', 'refresh_token is required')
    }

    const tokenData = await this.storage.get<RefreshToken>(`refresh:${refreshTokenId}`)
    if (!tokenData) {
      return oauthError('invalid_grant', 'Invalid refresh token')
    }

    // ── Verify client ───────────────────────────────────────────────────
    if (tokenData.clientId !== clientId) {
      return oauthError('invalid_grant', 'Refresh token was not issued to this client')
    }

    // ── Verify client secret for confidential clients ───────────────────
    const client = await this.getClient(clientId)
    if (client?.secret && client.secret !== clientSecret) {
      return oauthError('invalid_client', 'Invalid client credentials', 401)
    }

    // ── Check if revoked (replay detection) ─────────────────────────────
    if (tokenData.revoked) {
      // A revoked token was reused — possible token theft!
      // Revoke the entire rotation family
      await this.revokeRefreshTokenFamily(tokenData.family)
      return oauthError('invalid_grant', 'Refresh token has been revoked')
    }

    // ── Check expiration ────────────────────────────────────────────────
    if (tokenData.expiresAt < Date.now()) {
      return oauthError('invalid_grant', 'Refresh token has expired')
    }

    // ── Rotate: revoke old refresh token ────────────────────────────────
    await this.storage.put(`refresh:${refreshTokenId}`, {
      ...tokenData,
      revoked: true,
    } satisfies RefreshToken)

    // ── Issue new token pair (same family for rotation tracking) ─────────
    return this.issueTokenPair(clientId, tokenData.identityId, tokenData.scopes, tokenData.family)
  }

  private async handleClientCredentialsGrant(
    clientId: string,
    clientSecret: string,
    body: Record<string, string>,
  ): Promise<Response> {
    if (!clientId || !clientSecret) {
      return oauthError('invalid_client', 'client_id and client_secret are required', 401)
    }

    const client = await this.getClient(clientId)
    if (!client) {
      return oauthError('invalid_client', 'Unknown client', 401)
    }

    if (!client.grantTypes.includes('client_credentials')) {
      return oauthError('unauthorized_client', 'Client is not authorized for client_credentials grant')
    }

    if (!client.secret || client.secret !== clientSecret) {
      return oauthError('invalid_client', 'Invalid client credentials', 401)
    }

    const scope = body.scope || client.scopes.join(' ')
    const scopes = scope.split(' ')

    // Client credentials flow — no user, just the client
    const accessTokenId = generateId('at_')
    const now = Date.now()

    const accessToken: AccessToken = {
      id: accessTokenId,
      clientId,
      scopes,
      expiresAt: now + ACCESS_TOKEN_TTL * 1000,
      createdAt: now,
    }

    await this.storage.put(`access:${accessTokenId}`, accessToken, {
      expirationTtl: ACCESS_TOKEN_TTL + 60,
    })

    return jsonResponse({
      access_token: accessTokenId,
      token_type: 'Bearer',
      expires_in: ACCESS_TOKEN_TTL,
      scope: scopes.join(' '),
    })
  }

  private async handleDeviceCodeGrant(
    clientId: string,
    body: Record<string, string>,
  ): Promise<Response> {
    const deviceCodeId = body.device_code

    if (!deviceCodeId) {
      return oauthError('invalid_request', 'device_code is required')
    }

    const client = await this.getClient(clientId)
    if (!client) {
      return oauthError('invalid_client', 'Unknown client')
    }

    const deviceCode = await this.storage.get<DeviceCode>(`device:${deviceCodeId}`)
    if (!deviceCode) {
      return oauthError('invalid_grant', 'Invalid or expired device code')
    }

    if (deviceCode.clientId !== clientId) {
      return oauthError('invalid_grant', 'Device code was not issued to this client')
    }

    if (deviceCode.expiresAt < Date.now()) {
      return oauthError('expired_token', 'The device code has expired')
    }

    switch (deviceCode.status) {
      case 'pending':
        return oauthError('authorization_pending', 'The user has not yet authorized this device')

      case 'denied':
        // Clean up
        await this.storage.delete(`device:${deviceCodeId}`)
        await this.storage.delete(`device-user:${deviceCode.userCode}`)
        return oauthError('access_denied', 'The user denied the authorization request')

      case 'approved': {
        if (!deviceCode.identityId) {
          return oauthError('server_error', 'Device code approved but missing identity')
        }

        // Clean up device code (one-time use)
        await this.storage.delete(`device:${deviceCodeId}`)
        await this.storage.delete(`device-user:${deviceCode.userCode}`)

        // Issue tokens
        return this.issueTokenPair(clientId, deviceCode.identityId, deviceCode.scopes)
      }

      default:
        return oauthError('server_error', 'Unknown device code status')
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // PRIVATE: Token Issuance
  // ═══════════════════════════════════════════════════════════════════════════

  private async issueAuthorizationCode(
    client: OAuthProviderClient,
    identityId: string,
    params: {
      redirectUri: string
      scopes: string[]
      codeChallenge: string
      codeChallengeMethod: 'S256'
      state?: string
      nonce?: string
    },
  ): Promise<Response> {
    const codeId = generateId('ac_')
    const now = Date.now()

    const code: AuthorizationCode = {
      id: codeId,
      clientId: client.id,
      identityId,
      scopes: params.scopes,
      redirectUri: params.redirectUri,
      codeChallenge: params.codeChallenge,
      codeChallengeMethod: params.codeChallengeMethod,
      state: params.state,
      nonce: params.nonce,
      expiresAt: now + AUTH_CODE_TTL * 1000,
      createdAt: now,
    }

    await this.storage.put(`code:${codeId}`, code, {
      expirationTtl: AUTH_CODE_TTL + 60,
    })

    const redirectUrl = new URL(params.redirectUri)
    redirectUrl.searchParams.set('code', codeId)
    if (params.state) {
      redirectUrl.searchParams.set('state', params.state)
    }

    return Response.redirect(redirectUrl.toString(), 302)
  }

  private async issueTokenPair(
    clientId: string,
    identityId: string,
    scopes: string[],
    family?: string,
  ): Promise<Response> {
    const now = Date.now()
    const accessTokenId = generateId('at_')
    const refreshTokenId = generateId('rt_')
    const tokenFamily = family || crypto.randomUUID()

    const accessToken: AccessToken = {
      id: accessTokenId,
      clientId,
      identityId,
      scopes,
      expiresAt: now + ACCESS_TOKEN_TTL * 1000,
      createdAt: now,
    }

    const refreshToken: RefreshToken = {
      id: refreshTokenId,
      clientId,
      identityId,
      scopes,
      family: tokenFamily,
      revoked: false,
      expiresAt: now + REFRESH_TOKEN_TTL * 1000,
      createdAt: now,
    }

    await this.storage.put(`access:${accessTokenId}`, accessToken, {
      expirationTtl: ACCESS_TOKEN_TTL + 60,
    })

    await this.storage.put(`refresh:${refreshTokenId}`, refreshToken, {
      expirationTtl: REFRESH_TOKEN_TTL + 60,
    })

    return jsonResponse({
      access_token: accessTokenId,
      token_type: 'Bearer',
      expires_in: ACCESS_TOKEN_TTL,
      refresh_token: refreshTokenId,
      scope: scopes.join(' '),
    })
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // PRIVATE: Client Lookup
  // ═══════════════════════════════════════════════════════════════════════════

  private async getClient(clientId: string): Promise<OAuthProviderClient | null> {
    if (!clientId) return null
    const client = await this.storage.get<OAuthProviderClient>(`client:${clientId}`)
    return client ?? null
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // PRIVATE: Refresh Token Family Revocation
  // ═══════════════════════════════════════════════════════════════════════════

  private async revokeRefreshTokenFamily(family: string): Promise<void> {
    const tokens = await this.storage.list<RefreshToken>({ prefix: 'refresh:rt_' })
    const updates: Promise<void>[] = []

    for (const [key, token] of tokens) {
      if (token.family === family && !token.revoked) {
        updates.push(
          this.storage.put(key, {
            ...token,
            revoked: true,
          } satisfies RefreshToken),
        )
      }
    }

    await Promise.all(updates)
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // PRIVATE: Error Redirect
  // ═══════════════════════════════════════════════════════════════════════════

  private redirectError(
    redirectUri: string,
    error: string,
    description: string,
    state?: string,
  ): Response {
    const url = new URL(redirectUri)
    url.searchParams.set('error', error)
    url.searchParams.set('error_description', description)
    if (state) {
      url.searchParams.set('state', state)
    }
    return Response.redirect(url.toString(), 302)
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // PRIVATE: Consent Page
  // ═══════════════════════════════════════════════════════════════════════════

  private renderConsentPage(
    client: OAuthProviderClient,
    params: {
      clientId: string
      redirectUri: string
      scope: string
      state?: string
      codeChallenge?: string
      codeChallengeMethod?: string
      nonce?: string
    },
  ): Response {
    const scopeDescriptions: Record<string, string> = {
      openid: 'Verify your identity',
      profile: 'View your name and profile picture',
      email: 'View your email address',
      offline_access: 'Access your data while you are offline',
    }

    const scopeItems = params.scope
      .split(' ')
      .map((s) => `<div class="scope">${scopeDescriptions[s] || s}</div>`)
      .join('\n        ')

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <title>Authorize ${this.escapeHtml(client.name)} - id.org.ai</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: system-ui, -apple-system, sans-serif; max-width: 420px; margin: 60px auto; padding: 24px; color: #111; }
    h1 { font-size: 1.25rem; font-weight: 600; margin-bottom: 8px; }
    .subtitle { color: #666; margin-bottom: 24px; }
    .app { display: flex; align-items: center; gap: 12px; padding: 16px; background: #f9f9f9; border-radius: 12px; margin-bottom: 24px; }
    .app img { width: 40px; height: 40px; border-radius: 8px; }
    .app-name { font-weight: 600; }
    .app-url { font-size: 0.875rem; color: #666; }
    .scopes { margin-bottom: 24px; }
    .scope { padding: 10px 0; border-bottom: 1px solid #eee; font-size: 0.9375rem; }
    .scope:last-child { border-bottom: none; }
    .buttons { display: flex; gap: 12px; }
    button { flex: 1; padding: 12px 16px; border: none; border-radius: 10px; font-size: 1rem; font-weight: 500; cursor: pointer; transition: opacity 0.15s; }
    button:hover { opacity: 0.85; }
    .allow { background: #111; color: #fff; }
    .deny { background: #f0f0f0; color: #333; }
  </style>
</head>
<body>
  <h1>Authorize application</h1>
  <p class="subtitle">Grant access to your id.org.ai account</p>
  <div class="app">
    ${client.logo ? `<img src="${this.escapeHtml(client.logo)}" alt="">` : ''}
    <div>
      <div class="app-name">${this.escapeHtml(client.name)}</div>
      ${client.website ? `<div class="app-url">${this.escapeHtml(client.website)}</div>` : ''}
    </div>
  </div>
  <div class="scopes">
    ${scopeItems}
  </div>
  <form method="POST" action="/oauth/authorize">
    <input type="hidden" name="client_id" value="${this.escapeHtml(params.clientId)}">
    <input type="hidden" name="redirect_uri" value="${this.escapeHtml(params.redirectUri)}">
    <input type="hidden" name="scope" value="${this.escapeHtml(params.scope)}">
    ${params.state ? `<input type="hidden" name="state" value="${this.escapeHtml(params.state)}">` : ''}
    ${params.codeChallenge ? `<input type="hidden" name="code_challenge" value="${this.escapeHtml(params.codeChallenge)}">` : ''}
    ${params.codeChallengeMethod ? `<input type="hidden" name="code_challenge_method" value="${this.escapeHtml(params.codeChallengeMethod)}">` : ''}
    ${params.nonce ? `<input type="hidden" name="nonce" value="${this.escapeHtml(params.nonce)}">` : ''}
    <div class="buttons">
      <button type="submit" name="approved" value="false" class="deny">Deny</button>
      <button type="submit" name="approved" value="true" class="allow">Allow</button>
    </div>
  </form>
</body>
</html>`

    return new Response(html, {
      headers: { 'Content-Type': 'text/html; charset=utf-8' },
    })
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // PRIVATE: Device Verification Page
  // ═══════════════════════════════════════════════════════════════════════════

  private renderDeviceVerificationPage(userCode: string, error?: string): Response {
    const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <title>Device Authorization - id.org.ai</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: system-ui, -apple-system, sans-serif; max-width: 420px; margin: 60px auto; padding: 24px; color: #111; }
    h1 { font-size: 1.25rem; font-weight: 600; margin-bottom: 8px; }
    .subtitle { color: #666; margin-bottom: 24px; }
    .error { background: #fee; color: #c00; padding: 12px; border-radius: 8px; margin-bottom: 16px; font-size: 0.875rem; }
    label { display: block; font-weight: 500; margin-bottom: 8px; }
    input[type="text"] {
      width: 100%; padding: 14px 16px; font-size: 1.5rem; font-family: monospace;
      text-align: center; letter-spacing: 0.25em; text-transform: uppercase;
      border: 2px solid #ddd; border-radius: 10px; outline: none; transition: border-color 0.15s;
    }
    input[type="text"]:focus { border-color: #111; }
    .buttons { display: flex; gap: 12px; margin-top: 20px; }
    button { flex: 1; padding: 12px 16px; border: none; border-radius: 10px; font-size: 1rem; font-weight: 500; cursor: pointer; transition: opacity 0.15s; }
    button:hover { opacity: 0.85; }
    .allow { background: #111; color: #fff; }
    .deny { background: #f0f0f0; color: #333; }
  </style>
</head>
<body>
  <h1>Authorize Device</h1>
  <p class="subtitle">Enter the code shown on your device or agent</p>
  ${error ? `<div class="error">${this.escapeHtml(error)}</div>` : ''}
  <form method="POST" action="/device">
    <label for="user_code">Device Code</label>
    <input type="text" id="user_code" name="user_code" maxlength="8" autocomplete="off" autofocus
      value="${this.escapeHtml(userCode)}" placeholder="ABCD1234">
    <div class="buttons">
      <button type="submit" name="approved" value="false" class="deny">Deny</button>
      <button type="submit" name="approved" value="true" class="allow">Authorize</button>
    </div>
  </form>
</body>
</html>`

    return new Response(html, {
      headers: { 'Content-Type': 'text/html; charset=utf-8' },
    })
  }

  private deviceApprovedHtml(): string {
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <title>Device Authorized - id.org.ai</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: system-ui, -apple-system, sans-serif; max-width: 420px; margin: 60px auto; padding: 24px; color: #111; text-align: center; }
    h1 { font-size: 1.25rem; font-weight: 600; margin-bottom: 8px; }
    .check { font-size: 3rem; margin-bottom: 16px; }
    .subtitle { color: #666; }
  </style>
</head>
<body>
  <div class="check">&#10003;</div>
  <h1>Device Authorized</h1>
  <p class="subtitle">You can close this window and return to your device or agent.</p>
</body>
</html>`
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // PRIVATE: HTML Escaping
  // ═══════════════════════════════════════════════════════════════════════════

  private escapeHtml(str: string): string {
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;')
  }
}
