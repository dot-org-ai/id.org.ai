/**
 * OAuth 2.1 Provider — Comprehensive Test Suite
 *
 * Tests all OAuth 2.1 flows implemented in src/oauth/provider.ts:
 *   - OIDC Discovery
 *   - Dynamic Client Registration (RFC 7591)
 *   - Authorization Endpoint
 *   - Token Endpoint (Authorization Code, Refresh Token, Client Credentials, Device Code)
 *   - Device Flow (RFC 8628)
 *   - Token Introspection (RFC 7662)
 *   - Token Revocation (RFC 7009)
 *   - UserInfo Endpoint (OIDC Core)
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { OAuthProvider, type OAuthConfig } from '../src/oauth/provider'

// ── Mock Storage ────────────────────────────────────────────────────────

class MockStorage {
  private store = new Map<string, unknown>()
  async get<T>(key: string) {
    return this.store.get(key) as T | undefined
  }
  async put(key: string, value: unknown) {
    this.store.set(key, value)
  }
  async delete(key: string) {
    return this.store.delete(key)
  }
  async list<T>(options?: { prefix?: string; limit?: number }) {
    const map = new Map<string, T>()
    for (const [k, v] of this.store) {
      if (options?.prefix && !k.startsWith(options.prefix)) continue
      map.set(k, v as T)
      if (options?.limit && map.size >= options.limit) break
    }
    return map
  }
}

// ── PKCE Helpers ────────────────────────────────────────────────────────

async function computeS256Challenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder()
  const data = encoder.encode(verifier)
  const hash = await crypto.subtle.digest('SHA-256', data)
  return btoa(String.fromCharCode(...new Uint8Array(hash)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '')
}

// ── Test Config & Fixtures ──────────────────────────────────────────────

const TEST_ISSUER = 'https://id.org.ai'

const testConfig: OAuthConfig = {
  issuer: TEST_ISSUER,
  authorizationEndpoint: `${TEST_ISSUER}/oauth/authorize`,
  tokenEndpoint: `${TEST_ISSUER}/oauth/token`,
  userinfoEndpoint: `${TEST_ISSUER}/oauth/userinfo`,
  registrationEndpoint: `${TEST_ISSUER}/oauth/register`,
  deviceAuthorizationEndpoint: `${TEST_ISSUER}/oauth/device`,
  revocationEndpoint: `${TEST_ISSUER}/oauth/revoke`,
  introspectionEndpoint: `${TEST_ISSUER}/oauth/introspect`,
  jwksUri: `${TEST_ISSUER}/.well-known/jwks.json`,
}

const testIdentities: Record<string, { id: string; name: string; handle: string; email: string; emailVerified: boolean; image: string }> = {
  'user-1': {
    id: 'user-1',
    name: 'Alice Test',
    handle: 'alice',
    email: 'alice@example.com',
    emailVerified: true,
    image: 'https://example.com/alice.png',
  },
  'user-2': {
    id: 'user-2',
    name: 'Bob Test',
    handle: 'bob',
    email: 'bob@example.com',
    emailVerified: false,
    image: 'https://example.com/bob.png',
  },
}

function createProvider(storage: MockStorage) {
  return new OAuthProvider({
    storage,
    config: testConfig,
    getIdentity: async (id: string) => testIdentities[id] ?? null,
  })
}

// ── Helper: Register a client ───────────────────────────────────────────

async function registerPublicClient(provider: OAuthProvider, overrides: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
  const body = {
    client_name: 'Test App',
    redirect_uris: ['https://app.example.com/callback'],
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    scope: 'openid profile email',
    token_endpoint_auth_method: 'none',
    ...overrides,
  }
  const request = new Request(`${TEST_ISSUER}/oauth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  const response = await provider.handleRegister(request)
  return response.json() as Promise<Record<string, unknown>>
}

async function registerConfidentialClient(provider: OAuthProvider, overrides: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
  return registerPublicClient(provider, {
    token_endpoint_auth_method: 'client_secret_post',
    grant_types: ['authorization_code', 'refresh_token', 'client_credentials'],
    ...overrides,
  })
}

// ── Helper: Get authorization code ──────────────────────────────────────

async function getAuthorizationCode(
  provider: OAuthProvider,
  clientId: string,
  redirectUri: string,
  codeChallenge: string,
  identityId: string,
  extraParams: Record<string, string> = {},
): Promise<string> {
  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: 'openid profile email',
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    ...extraParams,
  })
  const request = new Request(`${TEST_ISSUER}/oauth/authorize?${params}`)
  const response = await provider.handleAuthorize(request, identityId)
  const location = response.headers.get('location')!
  const url = new URL(location)
  return url.searchParams.get('code')!
}

// ── Helper: Exchange code for tokens ────────────────────────────────────

async function exchangeCode(
  provider: OAuthProvider,
  clientId: string,
  code: string,
  redirectUri: string,
  codeVerifier: string,
  extraBody: Record<string, string> = {},
): Promise<{ response: Response; data: Record<string, unknown> }> {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: clientId,
    code,
    redirect_uri: redirectUri,
    code_verifier: codeVerifier,
    ...extraBody,
  })
  const request = new Request(`${TEST_ISSUER}/oauth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  })
  const response = await provider.handleToken(request)
  const data = (await response.json()) as Record<string, unknown>
  return { response, data }
}

// ════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════

describe('OAuthProvider', () => {
  let storage: MockStorage
  let provider: OAuthProvider

  beforeEach(() => {
    storage = new MockStorage()
    provider = createProvider(storage)
  })

  // ────────────────────────────────────────────────────────────────────
  // OIDC Discovery
  // ────────────────────────────────────────────────────────────────────

  describe('OIDC Discovery', () => {
    it('returns correct issuer', async () => {
      const response = provider.getOpenIDConfiguration()
      const body = (await response.json()) as Record<string, unknown>
      expect(body.issuer).toBe(TEST_ISSUER)
    })

    it('returns all endpoints', async () => {
      const response = provider.getOpenIDConfiguration()
      const body = (await response.json()) as Record<string, unknown>
      expect(body.authorization_endpoint).toBe(testConfig.authorizationEndpoint)
      expect(body.token_endpoint).toBe(testConfig.tokenEndpoint)
      expect(body.userinfo_endpoint).toBe(testConfig.userinfoEndpoint)
      expect(body.registration_endpoint).toBe(testConfig.registrationEndpoint)
      expect(body.device_authorization_endpoint).toBe(testConfig.deviceAuthorizationEndpoint)
      expect(body.revocation_endpoint).toBe(testConfig.revocationEndpoint)
      expect(body.introspection_endpoint).toBe(testConfig.introspectionEndpoint)
      expect(body.jwks_uri).toBe(testConfig.jwksUri)
    })

    it('returns supported grant types', async () => {
      const response = provider.getOpenIDConfiguration()
      const body = (await response.json()) as Record<string, unknown>
      const grantTypes = body.grant_types_supported as string[]
      expect(grantTypes).toContain('authorization_code')
      expect(grantTypes).toContain('refresh_token')
      expect(grantTypes).toContain('client_credentials')
      expect(grantTypes).toContain('urn:ietf:params:oauth:grant-type:device_code')
    })

    it('returns supported scopes', async () => {
      const response = provider.getOpenIDConfiguration()
      const body = (await response.json()) as Record<string, unknown>
      const scopes = body.scopes_supported as string[]
      expect(scopes).toContain('openid')
      expect(scopes).toContain('profile')
      expect(scopes).toContain('email')
      expect(scopes).toContain('offline_access')
    })

    it('only supports S256 code challenge method', async () => {
      const response = provider.getOpenIDConfiguration()
      const body = (await response.json()) as Record<string, unknown>
      expect(body.code_challenge_methods_supported).toEqual(['S256'])
    })

    it('only supports code response type', async () => {
      const response = provider.getOpenIDConfiguration()
      const body = (await response.json()) as Record<string, unknown>
      expect(body.response_types_supported).toEqual(['code'])
    })

    it('returns supported claims', async () => {
      const response = provider.getOpenIDConfiguration()
      const body = (await response.json()) as Record<string, unknown>
      const claims = body.claims_supported as string[]
      expect(claims).toContain('sub')
      expect(claims).toContain('name')
      expect(claims).toContain('email')
      expect(claims).toContain('email_verified')
    })

    it('returns JSON content type with no-store cache', async () => {
      const response = provider.getOpenIDConfiguration()
      expect(response.headers.get('Content-Type')).toBe('application/json')
      expect(response.headers.get('Cache-Control')).toBe('no-store')
    })
  })

  // ────────────────────────────────────────────────────────────────────
  // Dynamic Client Registration (RFC 7591)
  // ────────────────────────────────────────────────────────────────────

  describe('Dynamic Client Registration (RFC 7591)', () => {
    it('registers a public client (no secret)', async () => {
      const result = await registerPublicClient(provider)
      expect(result.client_id).toBeDefined()
      expect(result.client_id).toMatch(/^cid_/)
      expect(result.client_name).toBe('Test App')
      expect(result.redirect_uris).toEqual(['https://app.example.com/callback'])
      expect(result.token_endpoint_auth_method).toBe('none')
      expect(result.client_secret).toBeUndefined()
    })

    it('registers a confidential client (with secret)', async () => {
      const result = await registerConfidentialClient(provider)
      expect(result.client_id).toBeDefined()
      expect(result.client_secret).toBeDefined()
      expect(result.client_secret).toMatch(/^cs_/)
      expect(result.client_secret_expires_at).toBe(0)
      expect(result.token_endpoint_auth_method).toBe('client_secret_post')
    })

    it('validates redirect_uris require HTTPS', async () => {
      const request = new Request(`${TEST_ISSUER}/oauth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_name: 'Bad App',
          redirect_uris: ['http://insecure.example.com/callback'],
        }),
      })
      const response = await provider.handleRegister(request)
      const body = (await response.json()) as Record<string, unknown>
      expect(body.error).toBe('invalid_redirect_uri')
    })

    it('allows localhost redirect_uris for development', async () => {
      const result = await registerPublicClient(provider, {
        redirect_uris: ['http://localhost:3000/callback'],
      })
      expect(result.client_id).toBeDefined()
      expect(result.redirect_uris).toEqual(['http://localhost:3000/callback'])
    })

    it('allows 127.0.0.1 redirect_uris for development', async () => {
      const result = await registerPublicClient(provider, {
        redirect_uris: ['http://127.0.0.1:3000/callback'],
      })
      expect(result.client_id).toBeDefined()
    })

    it('rejects redirect_uris with fragments', async () => {
      const request = new Request(`${TEST_ISSUER}/oauth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_name: 'Fragment App',
          redirect_uris: ['https://app.example.com/callback#bad'],
        }),
      })
      const response = await provider.handleRegister(request)
      const body = (await response.json()) as Record<string, unknown>
      expect(body.error).toBe('invalid_redirect_uri')
      expect(body.error_description).toContain('fragment')
    })

    it('rejects invalid redirect_uris (malformed URL)', async () => {
      const request = new Request(`${TEST_ISSUER}/oauth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_name: 'Malformed App',
          redirect_uris: ['not-a-url'],
        }),
      })
      const response = await provider.handleRegister(request)
      const body = (await response.json()) as Record<string, unknown>
      expect(body.error).toBe('invalid_redirect_uri')
    })

    it('validates grant_types', async () => {
      const request = new Request(`${TEST_ISSUER}/oauth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_name: 'Bad Grant App',
          redirect_uris: ['https://app.example.com/callback'],
          grant_types: ['implicit'],
        }),
      })
      const response = await provider.handleRegister(request)
      const body = (await response.json()) as Record<string, unknown>
      expect(body.error).toBe('invalid_client_metadata')
      expect(body.error_description).toContain('implicit')
    })

    it('requires client_name', async () => {
      const request = new Request(`${TEST_ISSUER}/oauth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          redirect_uris: ['https://app.example.com/callback'],
        }),
      })
      const response = await provider.handleRegister(request)
      const body = (await response.json()) as Record<string, unknown>
      expect(body.error).toBe('invalid_client_metadata')
      expect(body.error_description).toContain('client_name')
    })

    it('rejects invalid JSON body', async () => {
      const request = new Request(`${TEST_ISSUER}/oauth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: 'not json {{{',
      })
      const response = await provider.handleRegister(request)
      const body = (await response.json()) as Record<string, unknown>
      expect(body.error).toBe('invalid_request')
      expect(body.error_description).toContain('Invalid JSON')
    })

    it('rejects non-POST methods', async () => {
      const request = new Request(`${TEST_ISSUER}/oauth/register`, { method: 'GET' })
      const response = await provider.handleRegister(request)
      expect(response.status).toBe(405)
    })

    it('returns 201 status for successful registration', async () => {
      const request = new Request(`${TEST_ISSUER}/oauth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_name: 'Test App',
          redirect_uris: ['https://app.example.com/callback'],
        }),
      })
      const response = await provider.handleRegister(request)
      expect(response.status).toBe(201)
    })

    it('includes client_id_issued_at in response', async () => {
      const result = await registerPublicClient(provider)
      expect(result.client_id_issued_at).toBeDefined()
      expect(typeof result.client_id_issued_at).toBe('number')
    })

    it('requires redirect_uris for authorization_code grant', async () => {
      const request = new Request(`${TEST_ISSUER}/oauth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_name: 'No Redirect App',
          grant_types: ['authorization_code'],
          redirect_uris: [],
        }),
      })
      const response = await provider.handleRegister(request)
      const body = (await response.json()) as Record<string, unknown>
      expect(body.error).toBe('invalid_client_metadata')
      expect(body.error_description).toContain('redirect_uris required')
    })

    it('includes logo_uri and client_uri if provided', async () => {
      const result = await registerPublicClient(provider, {
        logo_uri: 'https://app.example.com/logo.png',
        client_uri: 'https://app.example.com',
      })
      expect(result.logo_uri).toBe('https://app.example.com/logo.png')
      expect(result.client_uri).toBe('https://app.example.com')
    })
  })

  // ────────────────────────────────────────────────────────────────────
  // Authorization Endpoint
  // ────────────────────────────────────────────────────────────────────

  describe('Authorization Endpoint', () => {
    it('returns error for unknown client_id', async () => {
      const params = new URLSearchParams({
        client_id: 'cid_unknown',
        redirect_uri: 'https://app.example.com/callback',
        response_type: 'code',
      })
      const request = new Request(`${TEST_ISSUER}/oauth/authorize?${params}`)
      const response = await provider.handleAuthorize(request, 'user-1')
      const body = (await response.json()) as Record<string, unknown>
      expect(body.error).toBe('invalid_client')
    })

    it('returns error for invalid redirect_uri', async () => {
      const client = await registerPublicClient(provider)
      const params = new URLSearchParams({
        client_id: client.client_id as string,
        redirect_uri: 'https://evil.example.com/callback',
        response_type: 'code',
      })
      const request = new Request(`${TEST_ISSUER}/oauth/authorize?${params}`)
      const response = await provider.handleAuthorize(request, 'user-1')
      const body = (await response.json()) as Record<string, unknown>
      expect(body.error).toBe('invalid_request')
      expect(body.error_description).toContain('redirect_uri')
    })

    it('returns error for response_type != code', async () => {
      const client = await registerPublicClient(provider)
      const codeChallenge = await computeS256Challenge('test-verifier')
      const params = new URLSearchParams({
        client_id: client.client_id as string,
        redirect_uri: 'https://app.example.com/callback',
        response_type: 'token',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      })
      const request = new Request(`${TEST_ISSUER}/oauth/authorize?${params}`)
      const response = await provider.handleAuthorize(request, 'user-1')
      // Should redirect with error
      expect(response.status).toBe(302)
      const location = new URL(response.headers.get('location')!)
      expect(location.searchParams.get('error')).toBe('unsupported_response_type')
    })

    it('requires PKCE for public clients (OAuth 2.1)', async () => {
      const client = await registerPublicClient(provider)
      const params = new URLSearchParams({
        client_id: client.client_id as string,
        redirect_uri: 'https://app.example.com/callback',
        response_type: 'code',
      })
      const request = new Request(`${TEST_ISSUER}/oauth/authorize?${params}`)
      const response = await provider.handleAuthorize(request, 'user-1')
      expect(response.status).toBe(302)
      const location = new URL(response.headers.get('location')!)
      expect(location.searchParams.get('error')).toBe('invalid_request')
      expect(location.searchParams.get('error_description')).toContain('code_challenge')
    })

    it('rejects non-S256 code_challenge_method', async () => {
      const client = await registerPublicClient(provider)
      const params = new URLSearchParams({
        client_id: client.client_id as string,
        redirect_uri: 'https://app.example.com/callback',
        response_type: 'code',
        code_challenge: 'some-challenge',
        code_challenge_method: 'plain',
      })
      const request = new Request(`${TEST_ISSUER}/oauth/authorize?${params}`)
      const response = await provider.handleAuthorize(request, 'user-1')
      expect(response.status).toBe(302)
      const location = new URL(response.headers.get('location')!)
      expect(location.searchParams.get('error')).toBe('invalid_request')
      expect(location.searchParams.get('error_description')).toContain('S256')
    })

    it('redirects to /login when user is not authenticated', async () => {
      const client = await registerPublicClient(provider)
      const codeChallenge = await computeS256Challenge('test-verifier')
      const params = new URLSearchParams({
        client_id: client.client_id as string,
        redirect_uri: 'https://app.example.com/callback',
        response_type: 'code',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      })
      const authorizeUrl = `${TEST_ISSUER}/oauth/authorize?${params}`
      const request = new Request(authorizeUrl)
      const response = await provider.handleAuthorize(request, null)
      expect(response.status).toBe(302)
      const location = new URL(response.headers.get('location')!)
      expect(location.pathname).toBe('/login')
      expect(location.searchParams.get('continue')).toBe(authorizeUrl)
    })

    it('shows consent page for untrusted clients', async () => {
      const client = await registerPublicClient(provider)
      const codeChallenge = await computeS256Challenge('test-verifier')
      const params = new URLSearchParams({
        client_id: client.client_id as string,
        redirect_uri: 'https://app.example.com/callback',
        response_type: 'code',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      })
      const request = new Request(`${TEST_ISSUER}/oauth/authorize?${params}`)
      const response = await provider.handleAuthorize(request, 'user-1')
      expect(response.headers.get('Content-Type')).toContain('text/html')
      const html = await response.text()
      expect(html).toContain('Authorize application')
      expect(html).toContain('Test App')
    })

    it('skips consent for trusted clients', async () => {
      const client = await registerPublicClient(provider)
      // Manually mark client as trusted in storage
      const storedClient = await storage.get<Record<string, unknown>>(`client:${client.client_id}`)
      await storage.put(`client:${client.client_id}`, { ...storedClient, trusted: true })

      const codeChallenge = await computeS256Challenge('test-verifier')
      const params = new URLSearchParams({
        client_id: client.client_id as string,
        redirect_uri: 'https://app.example.com/callback',
        response_type: 'code',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      })
      const request = new Request(`${TEST_ISSUER}/oauth/authorize?${params}`)
      const response = await provider.handleAuthorize(request, 'user-1')
      expect(response.status).toBe(302)
      const location = new URL(response.headers.get('location')!)
      expect(location.searchParams.get('code')).toBeDefined()
      expect(location.searchParams.get('code')).toMatch(/^ac_/)
    })

    it('issues authorization code on consent (redirect with code + state)', async () => {
      const client = await registerPublicClient(provider)
      await storage.put(`client:${client.client_id}`, {
        ...(await storage.get(`client:${client.client_id}`)),
        trusted: true,
      })

      const codeChallenge = await computeS256Challenge('my-verifier')
      const params = new URLSearchParams({
        client_id: client.client_id as string,
        redirect_uri: 'https://app.example.com/callback',
        response_type: 'code',
        scope: 'openid profile email',
        state: 'xyz-state-123',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      })
      const request = new Request(`${TEST_ISSUER}/oauth/authorize?${params}`)
      const response = await provider.handleAuthorize(request, 'user-1')
      expect(response.status).toBe(302)
      const location = new URL(response.headers.get('location')!)
      expect(location.origin).toBe('https://app.example.com')
      expect(location.pathname).toBe('/callback')
      expect(location.searchParams.get('code')).toMatch(/^ac_/)
      expect(location.searchParams.get('state')).toBe('xyz-state-123')
    })

    it('skips consent when user has already consented to all requested scopes', async () => {
      const client = await registerPublicClient(provider)
      const clientId = client.client_id as string

      // Pre-store consent for user-1
      await storage.put(`consent:user-1:${clientId}`, {
        scopes: ['openid', 'profile', 'email'],
        createdAt: Date.now(),
      })

      const codeChallenge = await computeS256Challenge('test-verifier')
      const params = new URLSearchParams({
        client_id: clientId,
        redirect_uri: 'https://app.example.com/callback',
        response_type: 'code',
        scope: 'openid profile email',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      })
      const request = new Request(`${TEST_ISSUER}/oauth/authorize?${params}`)
      const response = await provider.handleAuthorize(request, 'user-1')
      // Should redirect with code (no consent page)
      expect(response.status).toBe(302)
      const location = new URL(response.headers.get('location')!)
      expect(location.searchParams.get('code')).toMatch(/^ac_/)
    })

    it('shows consent when user previously consented to fewer scopes', async () => {
      const client = await registerPublicClient(provider)
      const clientId = client.client_id as string

      // Pre-store partial consent
      await storage.put(`consent:user-1:${clientId}`, {
        scopes: ['openid'],
        createdAt: Date.now(),
      })

      const codeChallenge = await computeS256Challenge('test-verifier')
      const params = new URLSearchParams({
        client_id: clientId,
        redirect_uri: 'https://app.example.com/callback',
        response_type: 'code',
        scope: 'openid profile email',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      })
      const request = new Request(`${TEST_ISSUER}/oauth/authorize?${params}`)
      const response = await provider.handleAuthorize(request, 'user-1')
      // Should show consent page because existing consent doesn't cover all scopes
      expect(response.headers.get('Content-Type')).toContain('text/html')
    })

    it('preserves state in error redirects', async () => {
      const client = await registerPublicClient(provider)
      const params = new URLSearchParams({
        client_id: client.client_id as string,
        redirect_uri: 'https://app.example.com/callback',
        response_type: 'token',
        state: 'my-state',
        code_challenge: 'something',
        code_challenge_method: 'S256',
      })
      const request = new Request(`${TEST_ISSUER}/oauth/authorize?${params}`)
      const response = await provider.handleAuthorize(request, 'user-1')
      expect(response.status).toBe(302)
      const location = new URL(response.headers.get('location')!)
      expect(location.searchParams.get('state')).toBe('my-state')
    })
  })

  // ────────────────────────────────────────────────────────────────────
  // Authorization Consent Submission
  // ────────────────────────────────────────────────────────────────────

  describe('Authorization Consent Submission', () => {
    it('issues code when user approves', async () => {
      const client = await registerPublicClient(provider)
      const clientId = client.client_id as string
      const codeChallenge = await computeS256Challenge('verifier-123')

      const body = new URLSearchParams({
        client_id: clientId,
        redirect_uri: 'https://app.example.com/callback',
        scope: 'openid profile email',
        state: 'consent-state',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
        approved: 'true',
      })
      const request = new Request(`${TEST_ISSUER}/oauth/authorize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
      })
      const response = await provider.handleAuthorizeConsent(request, 'user-1')
      expect(response.status).toBe(302)
      const location = new URL(response.headers.get('location')!)
      expect(location.searchParams.get('code')).toMatch(/^ac_/)
      expect(location.searchParams.get('state')).toBe('consent-state')
    })

    it('redirects with access_denied when user denies', async () => {
      const client = await registerPublicClient(provider)
      const clientId = client.client_id as string

      const body = new URLSearchParams({
        client_id: clientId,
        redirect_uri: 'https://app.example.com/callback',
        approved: 'false',
        state: 'deny-state',
      })
      const request = new Request(`${TEST_ISSUER}/oauth/authorize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
      })
      const response = await provider.handleAuthorizeConsent(request, 'user-1')
      expect(response.status).toBe(302)
      const location = new URL(response.headers.get('location')!)
      expect(location.searchParams.get('error')).toBe('access_denied')
      expect(location.searchParams.get('state')).toBe('deny-state')
    })

    it('stores consent for future requests', async () => {
      const client = await registerPublicClient(provider)
      const clientId = client.client_id as string

      const body = new URLSearchParams({
        client_id: clientId,
        redirect_uri: 'https://app.example.com/callback',
        scope: 'openid profile',
        approved: 'true',
      })
      const request = new Request(`${TEST_ISSUER}/oauth/authorize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
      })
      await provider.handleAuthorizeConsent(request, 'user-1')

      const consentKey = `consent:user-1:${clientId}`
      const consent = await storage.get<{ scopes: string[] }>(consentKey)
      expect(consent).toBeDefined()
      expect(consent!.scopes).toContain('openid')
      expect(consent!.scopes).toContain('profile')
    })
  })

  // ────────────────────────────────────────────────────────────────────
  // Token Endpoint - Authorization Code
  // ────────────────────────────────────────────────────────────────────

  describe('Token Endpoint - Authorization Code', () => {
    it('exchanges valid code for access + refresh tokens', async () => {
      const client = await registerPublicClient(provider)
      const clientId = client.client_id as string
      const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
      const codeChallenge = await computeS256Challenge(verifier)

      // Mark client as trusted to skip consent
      const storedClient = await storage.get(`client:${clientId}`)
      await storage.put(`client:${clientId}`, { ...storedClient, trusted: true })

      const code = await getAuthorizationCode(provider, clientId, 'https://app.example.com/callback', codeChallenge, 'user-1')
      const { data } = await exchangeCode(provider, clientId, code, 'https://app.example.com/callback', verifier)

      expect(data.access_token).toBeDefined()
      expect((data.access_token as string)).toMatch(/^at_/)
      expect(data.refresh_token).toBeDefined()
      expect((data.refresh_token as string)).toMatch(/^rt_/)
      expect(data.token_type).toBe('Bearer')
      expect(data.expires_in).toBe(3600)
      expect(data.scope).toBe('openid profile email')
    })

    it('validates PKCE code_verifier (S256)', async () => {
      const client = await registerPublicClient(provider)
      const clientId = client.client_id as string
      const verifier = 'correct-verifier-value-for-pkce-test'
      const codeChallenge = await computeS256Challenge(verifier)

      await storage.put(`client:${clientId}`, { ...(await storage.get(`client:${clientId}`)), trusted: true })

      const code = await getAuthorizationCode(provider, clientId, 'https://app.example.com/callback', codeChallenge, 'user-1')
      const { response } = await exchangeCode(provider, clientId, code, 'https://app.example.com/callback', verifier)

      expect(response.status).toBe(200)
    })

    it('rejects invalid code_verifier', async () => {
      const client = await registerPublicClient(provider)
      const clientId = client.client_id as string
      const correctVerifier = 'the-correct-verifier'
      const codeChallenge = await computeS256Challenge(correctVerifier)

      await storage.put(`client:${clientId}`, { ...(await storage.get(`client:${clientId}`)), trusted: true })

      const code = await getAuthorizationCode(provider, clientId, 'https://app.example.com/callback', codeChallenge, 'user-1')
      const { data } = await exchangeCode(provider, clientId, code, 'https://app.example.com/callback', 'wrong-verifier')

      expect(data.error).toBe('invalid_grant')
      expect(data.error_description).toContain('code_verifier')
    })

    it('rejects expired authorization code', async () => {
      const client = await registerPublicClient(provider)
      const clientId = client.client_id as string
      const verifier = 'my-verifier'
      const codeChallenge = await computeS256Challenge(verifier)

      await storage.put(`client:${clientId}`, { ...(await storage.get(`client:${clientId}`)), trusted: true })

      const code = await getAuthorizationCode(provider, clientId, 'https://app.example.com/callback', codeChallenge, 'user-1')

      // Manually expire the code
      const codeData = await storage.get<Record<string, unknown>>(`code:${code}`)
      await storage.put(`code:${code}`, { ...codeData, expiresAt: Date.now() - 1000 })

      const { data } = await exchangeCode(provider, clientId, code, 'https://app.example.com/callback', verifier)

      expect(data.error).toBe('invalid_grant')
      expect(data.error_description).toContain('expired')
    })

    it('rejects code from wrong client', async () => {
      const client1 = await registerPublicClient(provider, { client_name: 'Client 1' })
      const client2 = await registerPublicClient(provider, { client_name: 'Client 2' })
      const clientId1 = client1.client_id as string
      const clientId2 = client2.client_id as string
      const verifier = 'my-verifier'
      const codeChallenge = await computeS256Challenge(verifier)

      await storage.put(`client:${clientId1}`, { ...(await storage.get(`client:${clientId1}`)), trusted: true })

      const code = await getAuthorizationCode(provider, clientId1, 'https://app.example.com/callback', codeChallenge, 'user-1')

      // Try to exchange using client2
      const { data } = await exchangeCode(provider, clientId2, code, 'https://app.example.com/callback', verifier)

      expect(data.error).toBe('invalid_grant')
      expect(data.error_description).toContain('not issued to this client')
    })

    it('rejects redirect_uri mismatch', async () => {
      const client = await registerPublicClient(provider, {
        redirect_uris: ['https://app.example.com/callback', 'https://app.example.com/other'],
      })
      const clientId = client.client_id as string
      const verifier = 'my-verifier'
      const codeChallenge = await computeS256Challenge(verifier)

      await storage.put(`client:${clientId}`, { ...(await storage.get(`client:${clientId}`)), trusted: true })

      const code = await getAuthorizationCode(provider, clientId, 'https://app.example.com/callback', codeChallenge, 'user-1')
      const { data } = await exchangeCode(provider, clientId, code, 'https://app.example.com/other', verifier)

      expect(data.error).toBe('invalid_grant')
      expect(data.error_description).toContain('redirect_uri mismatch')
    })

    it('consumes code (one-time use)', async () => {
      const client = await registerPublicClient(provider)
      const clientId = client.client_id as string
      const verifier = 'single-use-verifier'
      const codeChallenge = await computeS256Challenge(verifier)

      await storage.put(`client:${clientId}`, { ...(await storage.get(`client:${clientId}`)), trusted: true })

      const code = await getAuthorizationCode(provider, clientId, 'https://app.example.com/callback', codeChallenge, 'user-1')

      // First exchange succeeds
      const { data: first } = await exchangeCode(provider, clientId, code, 'https://app.example.com/callback', verifier)
      expect(first.access_token).toBeDefined()

      // Second exchange fails
      const { data: second } = await exchangeCode(provider, clientId, code, 'https://app.example.com/callback', verifier)
      expect(second.error).toBe('invalid_grant')
    })

    it('validates client secret for confidential clients', async () => {
      const client = await registerConfidentialClient(provider)
      const clientId = client.client_id as string
      const clientSecret = client.client_secret as string

      await storage.put(`client:${clientId}`, { ...(await storage.get(`client:${clientId}`)), trusted: true })

      // Confidential clients can use PKCE too, or omit it and use secret
      // For this test, create a code without PKCE challenge (empty string)
      // by directly inserting the code into storage
      const codeId = 'ac_test_confidential_code'
      await storage.put(`code:${codeId}`, {
        id: codeId,
        clientId,
        identityId: 'user-1',
        scopes: ['openid', 'profile', 'email'],
        redirectUri: 'https://app.example.com/callback',
        codeChallenge: '', // no PKCE
        codeChallengeMethod: 'S256',
        expiresAt: Date.now() + 600000,
        createdAt: Date.now(),
      })

      // Exchange with wrong secret
      const body = new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: clientId,
        client_secret: 'wrong-secret',
        code: codeId,
        redirect_uri: 'https://app.example.com/callback',
      })
      const request = new Request(`${TEST_ISSUER}/oauth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
      })
      const response = await provider.handleToken(request)
      const data = (await response.json()) as Record<string, unknown>
      expect(data.error).toBe('invalid_client')
      expect(response.status).toBe(401)
    })

    it('rejects missing code', async () => {
      const client = await registerPublicClient(provider)
      const clientId = client.client_id as string

      const body = new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: clientId,
        redirect_uri: 'https://app.example.com/callback',
        code_verifier: 'some-verifier',
      })
      const request = new Request(`${TEST_ISSUER}/oauth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
      })
      const response = await provider.handleToken(request)
      const data = (await response.json()) as Record<string, unknown>
      expect(data.error).toBe('invalid_request')
      expect(data.error_description).toContain('code is required')
    })

    it('rejects non-POST method', async () => {
      const request = new Request(`${TEST_ISSUER}/oauth/token`, { method: 'GET' })
      const response = await provider.handleToken(request)
      expect(response.status).toBe(405)
    })

    it('supports Basic auth header for client credentials', async () => {
      const client = await registerConfidentialClient(provider)
      const clientId = client.client_id as string
      const clientSecret = client.client_secret as string
      const verifier = 'basic-auth-verifier'
      const codeChallenge = await computeS256Challenge(verifier)

      await storage.put(`client:${clientId}`, { ...(await storage.get(`client:${clientId}`)), trusted: true })

      const code = await getAuthorizationCode(provider, clientId, 'https://app.example.com/callback', codeChallenge, 'user-1')

      const basicAuth = btoa(`${clientId}:${clientSecret}`)
      const body = new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'https://app.example.com/callback',
        code_verifier: verifier,
      })
      const request = new Request(`${TEST_ISSUER}/oauth/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Basic ${basicAuth}`,
        },
        body,
      })
      const response = await provider.handleToken(request)
      const data = (await response.json()) as Record<string, unknown>
      expect(data.access_token).toBeDefined()
    })

    it('rejects unsupported grant_type', async () => {
      const body = new URLSearchParams({
        grant_type: 'password',
        username: 'alice',
        password: 'secret',
      })
      const request = new Request(`${TEST_ISSUER}/oauth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
      })
      const response = await provider.handleToken(request)
      const data = (await response.json()) as Record<string, unknown>
      expect(data.error).toBe('unsupported_grant_type')
    })
  })

  // ────────────────────────────────────────────────────────────────────
  // Token Endpoint - Refresh Token
  // ────────────────────────────────────────────────────────────────────

  describe('Token Endpoint - Refresh Token', () => {
    async function getTokenPair(clientId: string, verifier: string, codeChallenge: string) {
      await storage.put(`client:${clientId}`, { ...(await storage.get(`client:${clientId}`)), trusted: true })
      const code = await getAuthorizationCode(provider, clientId, 'https://app.example.com/callback', codeChallenge, 'user-1')
      const { data } = await exchangeCode(provider, clientId, code, 'https://app.example.com/callback', verifier)
      return data
    }

    async function refreshToken(clientId: string, refreshTokenId: string, clientSecret?: string) {
      const bodyParams: Record<string, string> = {
        grant_type: 'refresh_token',
        client_id: clientId,
        refresh_token: refreshTokenId,
      }
      if (clientSecret) bodyParams.client_secret = clientSecret
      const body = new URLSearchParams(bodyParams)
      const request = new Request(`${TEST_ISSUER}/oauth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
      })
      const response = await provider.handleToken(request)
      return (await response.json()) as Record<string, unknown>
    }

    it('issues new access + refresh tokens', async () => {
      const client = await registerPublicClient(provider)
      const clientId = client.client_id as string
      const verifier = 'refresh-verifier'
      const codeChallenge = await computeS256Challenge(verifier)

      const tokens = await getTokenPair(clientId, verifier, codeChallenge)
      const result = await refreshToken(clientId, tokens.refresh_token as string)

      expect(result.access_token).toBeDefined()
      expect((result.access_token as string)).toMatch(/^at_/)
      expect(result.refresh_token).toBeDefined()
      expect((result.refresh_token as string)).toMatch(/^rt_/)
      // New tokens should be different from old ones
      expect(result.access_token).not.toBe(tokens.access_token)
      expect(result.refresh_token).not.toBe(tokens.refresh_token)
    })

    it('revokes old refresh token on rotation', async () => {
      const client = await registerPublicClient(provider)
      const clientId = client.client_id as string
      const verifier = 'rotation-verifier'
      const codeChallenge = await computeS256Challenge(verifier)

      const tokens = await getTokenPair(clientId, verifier, codeChallenge)
      const oldRt = tokens.refresh_token as string

      await refreshToken(clientId, oldRt)

      // Old refresh token should now be revoked
      const oldTokenData = await storage.get<{ revoked: boolean }>(`refresh:${oldRt}`)
      expect(oldTokenData!.revoked).toBe(true)
    })

    it('rejects revoked token (replay detection)', async () => {
      const client = await registerPublicClient(provider)
      const clientId = client.client_id as string
      const verifier = 'replay-verifier'
      const codeChallenge = await computeS256Challenge(verifier)

      const tokens = await getTokenPair(clientId, verifier, codeChallenge)
      const oldRt = tokens.refresh_token as string

      // First refresh succeeds
      const result1 = await refreshToken(clientId, oldRt)
      expect(result1.access_token).toBeDefined()

      // Second use of same token (replay) should fail
      const result2 = await refreshToken(clientId, oldRt)
      expect(result2.error).toBe('invalid_grant')
      expect(result2.error_description).toContain('revoked')
    })

    it('revokes entire family on replay', async () => {
      const client = await registerPublicClient(provider)
      const clientId = client.client_id as string
      const verifier = 'family-verifier'
      const codeChallenge = await computeS256Challenge(verifier)

      const tokens = await getTokenPair(clientId, verifier, codeChallenge)
      const rt1 = tokens.refresh_token as string

      // Rotate once (get rt2)
      const result1 = await refreshToken(clientId, rt1)
      const rt2 = result1.refresh_token as string

      // Replay rt1 (already revoked) - this should revoke the entire family
      await refreshToken(clientId, rt1)

      // Now rt2 should also be revoked
      const rt2Data = await storage.get<{ revoked: boolean }>(`refresh:${rt2}`)
      expect(rt2Data!.revoked).toBe(true)
    })

    it('rejects expired refresh token', async () => {
      const client = await registerPublicClient(provider)
      const clientId = client.client_id as string
      const verifier = 'expired-refresh-verifier'
      const codeChallenge = await computeS256Challenge(verifier)

      const tokens = await getTokenPair(clientId, verifier, codeChallenge)
      const rt = tokens.refresh_token as string

      // Manually expire the token
      const tokenData = await storage.get<Record<string, unknown>>(`refresh:${rt}`)
      await storage.put(`refresh:${rt}`, { ...tokenData, expiresAt: Date.now() - 1000 })

      const result = await refreshToken(clientId, rt)
      expect(result.error).toBe('invalid_grant')
      expect(result.error_description).toContain('expired')
    })

    it('validates client_id match', async () => {
      const client1 = await registerPublicClient(provider, { client_name: 'Client A' })
      const client2 = await registerPublicClient(provider, { client_name: 'Client B' })
      const clientId1 = client1.client_id as string
      const clientId2 = client2.client_id as string
      const verifier = 'client-match-verifier'
      const codeChallenge = await computeS256Challenge(verifier)

      const tokens = await getTokenPair(clientId1, verifier, codeChallenge)
      const rt = tokens.refresh_token as string

      // Try to refresh with wrong client_id
      const result = await refreshToken(clientId2, rt)
      expect(result.error).toBe('invalid_grant')
      expect(result.error_description).toContain('not issued to this client')
    })

    it('rejects missing refresh_token', async () => {
      const client = await registerPublicClient(provider)
      const clientId = client.client_id as string

      const body = new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: clientId,
      })
      const request = new Request(`${TEST_ISSUER}/oauth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
      })
      const response = await provider.handleToken(request)
      const data = (await response.json()) as Record<string, unknown>
      expect(data.error).toBe('invalid_request')
      expect(data.error_description).toContain('refresh_token is required')
    })

    it('rejects invalid refresh_token id', async () => {
      const client = await registerPublicClient(provider)
      const clientId = client.client_id as string

      const result = await refreshToken(clientId, 'rt_nonexistent_token')
      expect(result.error).toBe('invalid_grant')
    })

    it('validates client secret for confidential clients during refresh', async () => {
      const client = await registerConfidentialClient(provider)
      const clientId = client.client_id as string
      const clientSecret = client.client_secret as string
      const verifier = 'confidential-refresh-verifier'
      const codeChallenge = await computeS256Challenge(verifier)

      await storage.put(`client:${clientId}`, { ...(await storage.get(`client:${clientId}`)), trusted: true })

      const code = await getAuthorizationCode(provider, clientId, 'https://app.example.com/callback', codeChallenge, 'user-1')
      const { data: tokens } = await exchangeCode(provider, clientId, code, 'https://app.example.com/callback', verifier)
      const rt = tokens.refresh_token as string

      // Refresh with wrong secret
      const bodyParams = new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: clientId,
        client_secret: 'wrong-secret',
        refresh_token: rt,
      })
      const request = new Request(`${TEST_ISSUER}/oauth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: bodyParams,
      })
      const response = await provider.handleToken(request)
      const data = (await response.json()) as Record<string, unknown>
      expect(data.error).toBe('invalid_client')
      expect(response.status).toBe(401)
    })
  })

  // ────────────────────────────────────────────────────────────────────
  // Token Endpoint - Client Credentials
  // ────────────────────────────────────────────────────────────────────

  describe('Token Endpoint - Client Credentials', () => {
    it('issues access token (no refresh)', async () => {
      const client = await registerConfidentialClient(provider, {
        grant_types: ['authorization_code', 'refresh_token', 'client_credentials'],
      })
      const clientId = client.client_id as string
      const clientSecret = client.client_secret as string

      const body = new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: clientId,
        client_secret: clientSecret,
      })
      const request = new Request(`${TEST_ISSUER}/oauth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
      })
      const response = await provider.handleToken(request)
      const data = (await response.json()) as Record<string, unknown>

      expect(response.status).toBe(200)
      expect(data.access_token).toBeDefined()
      expect((data.access_token as string)).toMatch(/^at_/)
      expect(data.token_type).toBe('Bearer')
      expect(data.expires_in).toBe(3600)
      expect(data.refresh_token).toBeUndefined()
    })

    it('validates client secret', async () => {
      const client = await registerConfidentialClient(provider, {
        grant_types: ['client_credentials'],
      })
      const clientId = client.client_id as string

      const body = new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: clientId,
        client_secret: 'wrong-secret',
      })
      const request = new Request(`${TEST_ISSUER}/oauth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
      })
      const response = await provider.handleToken(request)
      const data = (await response.json()) as Record<string, unknown>

      expect(response.status).toBe(401)
      expect(data.error).toBe('invalid_client')
    })

    it('rejects unauthorized grant type', async () => {
      // Register a client without client_credentials grant
      const client = await registerConfidentialClient(provider, {
        grant_types: ['authorization_code', 'refresh_token'],
      })
      const clientId = client.client_id as string
      const clientSecret = client.client_secret as string

      const body = new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: clientId,
        client_secret: clientSecret,
      })
      const request = new Request(`${TEST_ISSUER}/oauth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
      })
      const response = await provider.handleToken(request)
      const data = (await response.json()) as Record<string, unknown>
      expect(data.error).toBe('unauthorized_client')
    })

    it('requires both client_id and client_secret', async () => {
      const body = new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: 'some-client',
      })
      const request = new Request(`${TEST_ISSUER}/oauth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
      })
      const response = await provider.handleToken(request)
      const data = (await response.json()) as Record<string, unknown>
      expect(response.status).toBe(401)
      expect(data.error).toBe('invalid_client')
    })

    it('rejects unknown client', async () => {
      const body = new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: 'cid_nonexistent',
        client_secret: 'cs_fake',
      })
      const request = new Request(`${TEST_ISSUER}/oauth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
      })
      const response = await provider.handleToken(request)
      const data = (await response.json()) as Record<string, unknown>
      expect(response.status).toBe(401)
      expect(data.error).toBe('invalid_client')
    })

    it('uses requested scope if provided', async () => {
      const client = await registerConfidentialClient(provider, {
        grant_types: ['client_credentials'],
        scope: 'openid profile email',
      })
      const clientId = client.client_id as string
      const clientSecret = client.client_secret as string

      const body = new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: clientId,
        client_secret: clientSecret,
        scope: 'openid profile',
      })
      const request = new Request(`${TEST_ISSUER}/oauth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
      })
      const response = await provider.handleToken(request)
      const data = (await response.json()) as Record<string, unknown>
      expect(data.scope).toBe('openid profile')
    })
  })

  // ────────────────────────────────────────────────────────────────────
  // Device Flow (RFC 8628)
  // ────────────────────────────────────────────────────────────────────

  describe('Device Flow (RFC 8628)', () => {
    async function registerDeviceClient() {
      return registerPublicClient(provider, {
        grant_types: ['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:device_code'],
      })
    }

    it('device authorization returns device_code, user_code, verification_uri', async () => {
      const client = await registerDeviceClient()
      const clientId = client.client_id as string

      const body = new URLSearchParams({ client_id: clientId })
      const request = new Request(`${TEST_ISSUER}/oauth/device`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
      })
      const response = await provider.handleDeviceAuthorization(request)
      const data = (await response.json()) as Record<string, unknown>

      expect(data.device_code).toBeDefined()
      expect((data.device_code as string)).toMatch(/^dc_/)
      expect(data.user_code).toBeDefined()
      expect((data.user_code as string).length).toBe(8)
      expect(data.verification_uri).toBe(`${TEST_ISSUER}/device`)
      expect(data.verification_uri_complete).toContain(data.user_code as string)
      expect(data.expires_in).toBe(1800)
      expect(data.interval).toBe(5)
    })

    it('polling returns authorization_pending for pending code', async () => {
      const client = await registerDeviceClient()
      const clientId = client.client_id as string

      // Create device code
      const deviceBody = new URLSearchParams({ client_id: clientId })
      const deviceReq = new Request(`${TEST_ISSUER}/oauth/device`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: deviceBody,
      })
      const deviceResp = await provider.handleDeviceAuthorization(deviceReq)
      const deviceData = (await deviceResp.json()) as Record<string, unknown>

      // Poll
      const pollBody = new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
        client_id: clientId,
        device_code: deviceData.device_code as string,
      })
      const pollReq = new Request(`${TEST_ISSUER}/oauth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: pollBody,
      })
      const pollResp = await provider.handleToken(pollReq)
      const pollData = (await pollResp.json()) as Record<string, unknown>

      expect(pollData.error).toBe('authorization_pending')
    })

    it('polling returns tokens after user approves', async () => {
      const client = await registerDeviceClient()
      const clientId = client.client_id as string

      // Create device code
      const deviceBody = new URLSearchParams({ client_id: clientId })
      const deviceReq = new Request(`${TEST_ISSUER}/oauth/device`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: deviceBody,
      })
      const deviceResp = await provider.handleDeviceAuthorization(deviceReq)
      const deviceData = (await deviceResp.json()) as Record<string, unknown>
      const deviceCode = deviceData.device_code as string
      const userCode = deviceData.user_code as string

      // Approve the device code via verification endpoint
      const approveBody = new URLSearchParams({
        user_code: userCode,
        approved: 'true',
      })
      const approveReq = new Request(`${TEST_ISSUER}/device`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: approveBody,
      })
      await provider.handleDeviceVerification(approveReq, 'user-1')

      // Poll
      const pollBody = new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
        client_id: clientId,
        device_code: deviceCode,
      })
      const pollReq = new Request(`${TEST_ISSUER}/oauth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: pollBody,
      })
      const pollResp = await provider.handleToken(pollReq)
      const pollData = (await pollResp.json()) as Record<string, unknown>

      expect(pollData.access_token).toBeDefined()
      expect(pollData.refresh_token).toBeDefined()
      expect(pollData.token_type).toBe('Bearer')
    })

    it('polling returns access_denied after user denies', async () => {
      const client = await registerDeviceClient()
      const clientId = client.client_id as string

      const deviceBody = new URLSearchParams({ client_id: clientId })
      const deviceReq = new Request(`${TEST_ISSUER}/oauth/device`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: deviceBody,
      })
      const deviceResp = await provider.handleDeviceAuthorization(deviceReq)
      const deviceData = (await deviceResp.json()) as Record<string, unknown>

      // Deny
      const denyBody = new URLSearchParams({
        user_code: deviceData.user_code as string,
        approved: 'false',
      })
      const denyReq = new Request(`${TEST_ISSUER}/device`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: denyBody,
      })
      await provider.handleDeviceVerification(denyReq, 'user-1')

      // Poll
      const pollBody = new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
        client_id: clientId,
        device_code: deviceData.device_code as string,
      })
      const pollReq = new Request(`${TEST_ISSUER}/oauth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: pollBody,
      })
      const pollResp = await provider.handleToken(pollReq)
      const pollData = (await pollResp.json()) as Record<string, unknown>

      expect(pollData.error).toBe('access_denied')
    })

    it('polling returns expired_token after expiry', async () => {
      const client = await registerDeviceClient()
      const clientId = client.client_id as string

      const deviceBody = new URLSearchParams({ client_id: clientId })
      const deviceReq = new Request(`${TEST_ISSUER}/oauth/device`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: deviceBody,
      })
      const deviceResp = await provider.handleDeviceAuthorization(deviceReq)
      const deviceData = (await deviceResp.json()) as Record<string, unknown>
      const deviceCode = deviceData.device_code as string

      // Manually expire the device code
      const dcData = await storage.get<Record<string, unknown>>(`device:${deviceCode}`)
      await storage.put(`device:${deviceCode}`, { ...dcData, expiresAt: Date.now() - 1000 })

      // Poll
      const pollBody = new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
        client_id: clientId,
        device_code: deviceCode,
      })
      const pollReq = new Request(`${TEST_ISSUER}/oauth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: pollBody,
      })
      const pollResp = await provider.handleToken(pollReq)
      const pollData = (await pollResp.json()) as Record<string, unknown>

      expect(pollData.error).toBe('expired_token')
    })

    it('user code verification page renders for GET', async () => {
      const request = new Request(`${TEST_ISSUER}/device?user_code=ABCD1234`, { method: 'GET' })
      const response = await provider.handleDeviceVerification(request, 'user-1')
      expect(response.headers.get('Content-Type')).toContain('text/html')
      const html = await response.text()
      expect(html).toContain('Authorize Device')
      expect(html).toContain('ABCD1234')
    })

    it('approval updates device code status', async () => {
      const client = await registerDeviceClient()
      const clientId = client.client_id as string

      const deviceBody = new URLSearchParams({ client_id: clientId })
      const deviceReq = new Request(`${TEST_ISSUER}/oauth/device`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: deviceBody,
      })
      const deviceResp = await provider.handleDeviceAuthorization(deviceReq)
      const deviceData = (await deviceResp.json()) as Record<string, unknown>
      const deviceCode = deviceData.device_code as string
      const userCode = deviceData.user_code as string

      // Verify initial status is pending
      const beforeApproval = await storage.get<{ status: string }>(`device:${deviceCode}`)
      expect(beforeApproval!.status).toBe('pending')

      // Approve
      const approveBody = new URLSearchParams({
        user_code: userCode,
        approved: 'true',
      })
      const approveReq = new Request(`${TEST_ISSUER}/device`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: approveBody,
      })
      await provider.handleDeviceVerification(approveReq, 'user-1')

      // Verify status changed
      const afterApproval = await storage.get<{ status: string; identityId?: string }>(`device:${deviceCode}`)
      expect(afterApproval!.status).toBe('approved')
      expect(afterApproval!.identityId).toBe('user-1')
    })

    it('redirects to /login when user is not authenticated on device page', async () => {
      const request = new Request(`${TEST_ISSUER}/device?user_code=ABCD1234`, { method: 'GET' })
      const response = await provider.handleDeviceVerification(request, null)
      expect(response.status).toBe(302)
      const location = new URL(response.headers.get('location')!)
      expect(location.pathname).toBe('/login')
    })

    it('rejects device authorization for unauthorized client', async () => {
      const client = await registerPublicClient(provider, {
        grant_types: ['authorization_code'],
      })
      const clientId = client.client_id as string

      const body = new URLSearchParams({ client_id: clientId })
      const request = new Request(`${TEST_ISSUER}/oauth/device`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
      })
      const response = await provider.handleDeviceAuthorization(request)
      const data = (await response.json()) as Record<string, unknown>
      expect(data.error).toBe('unauthorized_client')
    })

    it('rejects device authorization without client_id', async () => {
      const body = new URLSearchParams({})
      const request = new Request(`${TEST_ISSUER}/oauth/device`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
      })
      const response = await provider.handleDeviceAuthorization(request)
      const data = (await response.json()) as Record<string, unknown>
      expect(data.error).toBe('invalid_request')
    })

    it('rejects non-POST method for device authorization', async () => {
      const request = new Request(`${TEST_ISSUER}/oauth/device`, { method: 'GET' })
      const response = await provider.handleDeviceAuthorization(request)
      expect(response.status).toBe(405)
    })

    it('rejects invalid user code format on verification', async () => {
      const body = new URLSearchParams({
        user_code: 'AB',
        approved: 'true',
      })
      const request = new Request(`${TEST_ISSUER}/device`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
      })
      const response = await provider.handleDeviceVerification(request, 'user-1')
      const html = await response.text()
      expect(html).toContain('valid 8-character code')
    })

    it('rejects unknown user code on verification', async () => {
      const body = new URLSearchParams({
        user_code: 'ZZZZZZZZ',
        approved: 'true',
      })
      const request = new Request(`${TEST_ISSUER}/device`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
      })
      const response = await provider.handleDeviceVerification(request, 'user-1')
      const html = await response.text()
      expect(html).toContain('Invalid or expired')
    })

    it('shows approved HTML after successful device authorization', async () => {
      const client = await registerDeviceClient()
      const clientId = client.client_id as string

      const deviceBody = new URLSearchParams({ client_id: clientId })
      const deviceReq = new Request(`${TEST_ISSUER}/oauth/device`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: deviceBody,
      })
      const deviceResp = await provider.handleDeviceAuthorization(deviceReq)
      const deviceData = (await deviceResp.json()) as Record<string, unknown>

      const approveBody = new URLSearchParams({
        user_code: deviceData.user_code as string,
        approved: 'true',
      })
      const approveReq = new Request(`${TEST_ISSUER}/device`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: approveBody,
      })
      const response = await provider.handleDeviceVerification(approveReq, 'user-1')
      const html = await response.text()
      expect(html).toContain('Device Authorized')
      expect(html).toContain('close this window')
    })
  })

  // ────────────────────────────────────────────────────────────────────
  // Token Introspection (RFC 7662)
  // ────────────────────────────────────────────────────────────────────

  describe('Token Introspection (RFC 7662)', () => {
    async function introspect(token: string) {
      const body = new URLSearchParams({ token })
      const request = new Request(`${TEST_ISSUER}/oauth/introspect`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
      })
      const response = await provider.handleIntrospect(request)
      return (await response.json()) as Record<string, unknown>
    }

    it('returns active: true for valid access token with claims', async () => {
      const client = await registerPublicClient(provider)
      const clientId = client.client_id as string
      const verifier = 'introspect-verifier'
      const codeChallenge = await computeS256Challenge(verifier)

      await storage.put(`client:${clientId}`, { ...(await storage.get(`client:${clientId}`)), trusted: true })
      const code = await getAuthorizationCode(provider, clientId, 'https://app.example.com/callback', codeChallenge, 'user-1')
      const { data: tokens } = await exchangeCode(provider, clientId, code, 'https://app.example.com/callback', verifier)

      const result = await introspect(tokens.access_token as string)
      expect(result.active).toBe(true)
      expect(result.client_id).toBe(clientId)
      expect(result.sub).toBe('user-1')
      expect(result.scope).toBe('openid profile email')
      expect(result.token_type).toBe('Bearer')
      expect(result.exp).toBeDefined()
      expect(result.iat).toBeDefined()
    })

    it('returns active: true for valid refresh token', async () => {
      const client = await registerPublicClient(provider)
      const clientId = client.client_id as string
      const verifier = 'introspect-rt-verifier'
      const codeChallenge = await computeS256Challenge(verifier)

      await storage.put(`client:${clientId}`, { ...(await storage.get(`client:${clientId}`)), trusted: true })
      const code = await getAuthorizationCode(provider, clientId, 'https://app.example.com/callback', codeChallenge, 'user-1')
      const { data: tokens } = await exchangeCode(provider, clientId, code, 'https://app.example.com/callback', verifier)

      const result = await introspect(tokens.refresh_token as string)
      expect(result.active).toBe(true)
      expect(result.client_id).toBe(clientId)
      expect(result.token_type).toBe('refresh_token')
    })

    it('returns active: false for expired access token', async () => {
      const tokenId = 'at_expired_token_test'
      await storage.put(`access:${tokenId}`, {
        id: tokenId,
        clientId: 'cid_test',
        identityId: 'user-1',
        scopes: ['openid'],
        expiresAt: Date.now() - 1000,
        createdAt: Date.now() - 7200000,
      })

      const result = await introspect(tokenId)
      expect(result.active).toBe(false)
    })

    it('returns active: false for unknown token', async () => {
      const result = await introspect('at_nonexistent_token_xyz')
      expect(result.active).toBe(false)
    })

    it('returns active: false for revoked refresh token', async () => {
      const tokenId = 'rt_revoked_test'
      await storage.put(`refresh:${tokenId}`, {
        id: tokenId,
        clientId: 'cid_test',
        identityId: 'user-1',
        scopes: ['openid'],
        family: 'family-test',
        revoked: true,
        expiresAt: Date.now() + 86400000,
        createdAt: Date.now(),
      })

      const result = await introspect(tokenId)
      expect(result.active).toBe(false)
    })

    it('returns active: false when no token is provided', async () => {
      const body = new URLSearchParams({})
      const request = new Request(`${TEST_ISSUER}/oauth/introspect`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
      })
      const response = await provider.handleIntrospect(request)
      const data = (await response.json()) as Record<string, unknown>
      expect(data.active).toBe(false)
    })

    it('rejects non-POST method', async () => {
      const request = new Request(`${TEST_ISSUER}/oauth/introspect`, { method: 'GET' })
      const response = await provider.handleIntrospect(request)
      expect(response.status).toBe(405)
    })

    it('returns active: false for token with unrecognized prefix', async () => {
      const result = await introspect('unknown_prefix_token')
      expect(result.active).toBe(false)
    })
  })

  // ────────────────────────────────────────────────────────────────────
  // Token Revocation (RFC 7009)
  // ────────────────────────────────────────────────────────────────────

  describe('Token Revocation (RFC 7009)', () => {
    async function revoke(token: string) {
      const body = new URLSearchParams({ token })
      const request = new Request(`${TEST_ISSUER}/oauth/revoke`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
      })
      return provider.handleRevoke(request)
    }

    it('revokes access token (deletes it)', async () => {
      const tokenId = 'at_revoke_access_test'
      await storage.put(`access:${tokenId}`, {
        id: tokenId,
        clientId: 'cid_test',
        identityId: 'user-1',
        scopes: ['openid'],
        expiresAt: Date.now() + 3600000,
        createdAt: Date.now(),
      })

      const response = await revoke(tokenId)
      expect(response.status).toBe(200)

      // Token should be deleted
      const tokenData = await storage.get(`access:${tokenId}`)
      expect(tokenData).toBeUndefined()
    })

    it('revokes refresh token (marks as revoked)', async () => {
      const tokenId = 'rt_revoke_refresh_test'
      await storage.put(`refresh:${tokenId}`, {
        id: tokenId,
        clientId: 'cid_test',
        identityId: 'user-1',
        scopes: ['openid'],
        family: 'family-revoke-test',
        revoked: false,
        expiresAt: Date.now() + 86400000,
        createdAt: Date.now(),
      })

      const response = await revoke(tokenId)
      expect(response.status).toBe(200)

      // Token should be marked revoked
      const tokenData = await storage.get<{ revoked: boolean }>(`refresh:${tokenId}`)
      expect(tokenData!.revoked).toBe(true)
    })

    it('revokes entire refresh token family', async () => {
      const familyId = 'family-full-revoke'
      const rt1 = 'rt_family_member_1'
      const rt2 = 'rt_family_member_2'
      const rt3 = 'rt_family_member_3'

      for (const rtId of [rt1, rt2, rt3]) {
        await storage.put(`refresh:${rtId}`, {
          id: rtId,
          clientId: 'cid_test',
          identityId: 'user-1',
          scopes: ['openid'],
          family: familyId,
          revoked: false,
          expiresAt: Date.now() + 86400000,
          createdAt: Date.now(),
        })
      }

      // Revoke one family member
      await revoke(rt1)

      // All family members should be revoked
      for (const rtId of [rt1, rt2, rt3]) {
        const tokenData = await storage.get<{ revoked: boolean }>(`refresh:${rtId}`)
        expect(tokenData!.revoked).toBe(true)
      }
    })

    it('returns 200 for unknown token (per RFC)', async () => {
      const response = await revoke('at_nonexistent_revoke_token')
      expect(response.status).toBe(200)
    })

    it('returns 200 when no token is provided', async () => {
      const body = new URLSearchParams({})
      const request = new Request(`${TEST_ISSUER}/oauth/revoke`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
      })
      const response = await provider.handleRevoke(request)
      expect(response.status).toBe(200)
    })

    it('rejects non-POST method', async () => {
      const request = new Request(`${TEST_ISSUER}/oauth/revoke`, { method: 'GET' })
      const response = await provider.handleRevoke(request)
      expect(response.status).toBe(405)
    })
  })

  // ────────────────────────────────────────────────────────────────────
  // UserInfo Endpoint
  // ────────────────────────────────────────────────────────────────────

  describe('UserInfo Endpoint', () => {
    async function createAccessToken(scopes: string[], identityId = 'user-1') {
      const tokenId = `at_userinfo_${Date.now()}_${Math.random().toString(36).slice(2)}`
      await storage.put(`access:${tokenId}`, {
        id: tokenId,
        clientId: 'cid_test',
        identityId,
        scopes,
        expiresAt: Date.now() + 3600000,
        createdAt: Date.now(),
      })
      return tokenId
    }

    it('returns profile claims when scope includes profile', async () => {
      const tokenId = await createAccessToken(['openid', 'profile'])

      const request = new Request(`${TEST_ISSUER}/oauth/userinfo`, {
        headers: { Authorization: `Bearer ${tokenId}` },
      })
      const response = await provider.handleUserinfo(request)
      const data = (await response.json()) as Record<string, unknown>

      expect(data.sub).toBe('user-1')
      expect(data.name).toBe('Alice Test')
      expect(data.preferred_username).toBe('alice')
      expect(data.picture).toBe('https://example.com/alice.png')
    })

    it('returns email claims when scope includes email', async () => {
      const tokenId = await createAccessToken(['openid', 'email'])

      const request = new Request(`${TEST_ISSUER}/oauth/userinfo`, {
        headers: { Authorization: `Bearer ${tokenId}` },
      })
      const response = await provider.handleUserinfo(request)
      const data = (await response.json()) as Record<string, unknown>

      expect(data.sub).toBe('user-1')
      expect(data.email).toBe('alice@example.com')
      expect(data.email_verified).toBe(true)
    })

    it('omits profile claims when scope does not include profile', async () => {
      const tokenId = await createAccessToken(['openid', 'email'])

      const request = new Request(`${TEST_ISSUER}/oauth/userinfo`, {
        headers: { Authorization: `Bearer ${tokenId}` },
      })
      const response = await provider.handleUserinfo(request)
      const data = (await response.json()) as Record<string, unknown>

      expect(data.name).toBeUndefined()
      expect(data.preferred_username).toBeUndefined()
      expect(data.picture).toBeUndefined()
    })

    it('omits email claims when scope does not include email', async () => {
      const tokenId = await createAccessToken(['openid', 'profile'])

      const request = new Request(`${TEST_ISSUER}/oauth/userinfo`, {
        headers: { Authorization: `Bearer ${tokenId}` },
      })
      const response = await provider.handleUserinfo(request)
      const data = (await response.json()) as Record<string, unknown>

      expect(data.email).toBeUndefined()
      expect(data.email_verified).toBeUndefined()
    })

    it('returns both profile and email when both scopes requested', async () => {
      const tokenId = await createAccessToken(['openid', 'profile', 'email'])

      const request = new Request(`${TEST_ISSUER}/oauth/userinfo`, {
        headers: { Authorization: `Bearer ${tokenId}` },
      })
      const response = await provider.handleUserinfo(request)
      const data = (await response.json()) as Record<string, unknown>

      expect(data.sub).toBe('user-1')
      expect(data.name).toBe('Alice Test')
      expect(data.email).toBe('alice@example.com')
    })

    it('returns error for expired token', async () => {
      const tokenId = 'at_expired_userinfo_test'
      await storage.put(`access:${tokenId}`, {
        id: tokenId,
        clientId: 'cid_test',
        identityId: 'user-1',
        scopes: ['openid', 'profile'],
        expiresAt: Date.now() - 1000,
        createdAt: Date.now() - 7200000,
      })

      const request = new Request(`${TEST_ISSUER}/oauth/userinfo`, {
        headers: { Authorization: `Bearer ${tokenId}` },
      })
      const response = await provider.handleUserinfo(request)
      expect(response.status).toBe(401)
      const data = (await response.json()) as Record<string, unknown>
      expect(data.error).toBe('invalid_token')
    })

    it('returns error for invalid/unknown token', async () => {
      const request = new Request(`${TEST_ISSUER}/oauth/userinfo`, {
        headers: { Authorization: 'Bearer at_nonexistent_token' },
      })
      const response = await provider.handleUserinfo(request)
      expect(response.status).toBe(401)
      const data = (await response.json()) as Record<string, unknown>
      expect(data.error).toBe('invalid_token')
    })

    it('returns error for missing Bearer token', async () => {
      const request = new Request(`${TEST_ISSUER}/oauth/userinfo`)
      const response = await provider.handleUserinfo(request)
      expect(response.status).toBe(401)
      expect(response.headers.get('WWW-Authenticate')).toBe('Bearer')
    })

    it('returns error for non-Bearer auth scheme', async () => {
      const request = new Request(`${TEST_ISSUER}/oauth/userinfo`, {
        headers: { Authorization: 'Basic dXNlcjpwYXNz' },
      })
      const response = await provider.handleUserinfo(request)
      expect(response.status).toBe(401)
    })

    it('returns error for unknown identity', async () => {
      const tokenId = 'at_unknown_identity_test'
      await storage.put(`access:${tokenId}`, {
        id: tokenId,
        clientId: 'cid_test',
        identityId: 'user-nonexistent',
        scopes: ['openid', 'profile'],
        expiresAt: Date.now() + 3600000,
        createdAt: Date.now(),
      })

      const request = new Request(`${TEST_ISSUER}/oauth/userinfo`, {
        headers: { Authorization: `Bearer ${tokenId}` },
      })
      const response = await provider.handleUserinfo(request)
      expect(response.status).toBe(401)
    })

    it('returns error for client_credentials token (no identity)', async () => {
      const tokenId = 'at_no_identity_test'
      await storage.put(`access:${tokenId}`, {
        id: tokenId,
        clientId: 'cid_test',
        scopes: ['openid'],
        expiresAt: Date.now() + 3600000,
        createdAt: Date.now(),
        // no identityId
      })

      const request = new Request(`${TEST_ISSUER}/oauth/userinfo`, {
        headers: { Authorization: `Bearer ${tokenId}` },
      })
      const response = await provider.handleUserinfo(request)
      expect(response.status).toBe(401)
    })

    it('returns email_verified: false for unverified email', async () => {
      const tokenId = await createAccessToken(['openid', 'email'], 'user-2')

      const request = new Request(`${TEST_ISSUER}/oauth/userinfo`, {
        headers: { Authorization: `Bearer ${tokenId}` },
      })
      const response = await provider.handleUserinfo(request)
      const data = (await response.json()) as Record<string, unknown>
      expect(data.email_verified).toBe(false)
    })
  })

  // ────────────────────────────────────────────────────────────────────
  // Validate Access Token (utility)
  // ────────────────────────────────────────────────────────────────────

  describe('validateAccessToken', () => {
    it('returns token data for valid access token', async () => {
      const tokenId = 'at_validate_test'
      await storage.put(`access:${tokenId}`, {
        id: tokenId,
        clientId: 'cid_test',
        identityId: 'user-1',
        scopes: ['openid'],
        expiresAt: Date.now() + 3600000,
        createdAt: Date.now(),
      })

      const result = await provider.validateAccessToken(tokenId)
      expect(result).not.toBeNull()
      expect(result!.id).toBe(tokenId)
      expect(result!.identityId).toBe('user-1')
    })

    it('returns null for expired token', async () => {
      const tokenId = 'at_validate_expired'
      await storage.put(`access:${tokenId}`, {
        id: tokenId,
        clientId: 'cid_test',
        identityId: 'user-1',
        scopes: ['openid'],
        expiresAt: Date.now() - 1000,
        createdAt: Date.now() - 7200000,
      })

      const result = await provider.validateAccessToken(tokenId)
      expect(result).toBeNull()
    })

    it('returns null for unknown token', async () => {
      const result = await provider.validateAccessToken('at_nonexistent')
      expect(result).toBeNull()
    })

    it('returns null for non-at_ prefix', async () => {
      const result = await provider.validateAccessToken('rt_wrong_prefix')
      expect(result).toBeNull()
    })
  })

  // ────────────────────────────────────────────────────────────────────
  // End-to-end: Full Authorization Code + PKCE flow
  // ────────────────────────────────────────────────────────────────────

  describe('End-to-end: Full Authorization Code + PKCE Flow', () => {
    it('completes the full flow from registration to userinfo', async () => {
      // 1. Register a client
      const client = await registerPublicClient(provider)
      const clientId = client.client_id as string

      // Mark as trusted for simplicity
      await storage.put(`client:${clientId}`, { ...(await storage.get(`client:${clientId}`)), trusted: true })

      // 2. Authorization request with PKCE
      const codeVerifier = 'e2e-test-verifier-with-sufficient-entropy-for-pkce'
      const codeChallenge = await computeS256Challenge(codeVerifier)

      const authParams = new URLSearchParams({
        client_id: clientId,
        redirect_uri: 'https://app.example.com/callback',
        response_type: 'code',
        scope: 'openid profile email',
        state: 'e2e-state',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      })
      const authRequest = new Request(`${TEST_ISSUER}/oauth/authorize?${authParams}`)
      const authResponse = await provider.handleAuthorize(authRequest, 'user-1')
      expect(authResponse.status).toBe(302)

      const authLocation = new URL(authResponse.headers.get('location')!)
      const code = authLocation.searchParams.get('code')!
      expect(code).toMatch(/^ac_/)
      expect(authLocation.searchParams.get('state')).toBe('e2e-state')

      // 3. Exchange code for tokens
      const { data: tokens } = await exchangeCode(provider, clientId, code, 'https://app.example.com/callback', codeVerifier)
      expect(tokens.access_token).toBeDefined()
      expect(tokens.refresh_token).toBeDefined()
      expect(tokens.token_type).toBe('Bearer')

      // 4. Access userinfo
      const userinfoRequest = new Request(`${TEST_ISSUER}/oauth/userinfo`, {
        headers: { Authorization: `Bearer ${tokens.access_token}` },
      })
      const userinfoResponse = await provider.handleUserinfo(userinfoRequest)
      expect(userinfoResponse.status).toBe(200)

      const userinfo = (await userinfoResponse.json()) as Record<string, unknown>
      expect(userinfo.sub).toBe('user-1')
      expect(userinfo.name).toBe('Alice Test')
      expect(userinfo.email).toBe('alice@example.com')

      // 5. Introspect access token
      const introspectBody = new URLSearchParams({ token: tokens.access_token as string })
      const introspectRequest = new Request(`${TEST_ISSUER}/oauth/introspect`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: introspectBody,
      })
      const introspectResponse = await provider.handleIntrospect(introspectRequest)
      const introspectData = (await introspectResponse.json()) as Record<string, unknown>
      expect(introspectData.active).toBe(true)

      // 6. Refresh tokens
      const refreshBody = new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: clientId,
        refresh_token: tokens.refresh_token as string,
      })
      const refreshRequest = new Request(`${TEST_ISSUER}/oauth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: refreshBody,
      })
      const refreshResponse = await provider.handleToken(refreshRequest)
      const newTokens = (await refreshResponse.json()) as Record<string, unknown>
      expect(newTokens.access_token).toBeDefined()
      expect(newTokens.refresh_token).toBeDefined()
      expect(newTokens.access_token).not.toBe(tokens.access_token)

      // 7. Revoke new access token
      const revokeBody = new URLSearchParams({ token: newTokens.access_token as string })
      const revokeRequest = new Request(`${TEST_ISSUER}/oauth/revoke`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: revokeBody,
      })
      const revokeResponse = await provider.handleRevoke(revokeRequest)
      expect(revokeResponse.status).toBe(200)

      // 8. Verify revoked token is no longer valid
      const afterRevokeIntrospect = new URLSearchParams({ token: newTokens.access_token as string })
      const afterRevokeRequest = new Request(`${TEST_ISSUER}/oauth/introspect`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: afterRevokeIntrospect,
      })
      const afterRevokeResponse = await provider.handleIntrospect(afterRevokeRequest)
      const afterRevokeData = (await afterRevokeResponse.json()) as Record<string, unknown>
      expect(afterRevokeData.active).toBe(false)
    })
  })
})
