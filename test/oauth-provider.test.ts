/**
 * OAuthProvider Comprehensive Test Suite
 *
 * Tests the complete OAuth 2.1 authorization server implementation:
 *   - OIDC Discovery
 *   - Dynamic Client Registration (RFC 7591)
 *   - Authorization Code + PKCE (S256 mandatory)
 *   - Refresh Token with Rotation
 *   - Client Credentials
 *   - Device Flow (RFC 8628)
 *   - Token Introspection (RFC 7662)
 *   - Token Revocation (RFC 7009)
 *   - UserInfo Endpoint (OIDC Core)
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { OAuthProvider } from '../src/oauth/provider'
import type { OAuthConfig } from '../src/oauth/provider'

// ============================================================================
// Helpers
// ============================================================================

type StorageLike = {
  get<T = unknown>(key: string): Promise<T | undefined>
  put(key: string, value: unknown, options?: { expirationTtl?: number }): Promise<void>
  delete(key: string): Promise<boolean>
  list<T = unknown>(options?: { prefix?: string; limit?: number }): Promise<Map<string, T>>
}

interface IdentityInfo {
  id: string
  name?: string
  handle?: string
  email?: string
  emailVerified?: boolean
  image?: string
}

function createMockStorage(): StorageLike {
  const store = new Map<string, unknown>()
  return {
    async get<T = unknown>(key: string): Promise<T | undefined> {
      return store.get(key) as T | undefined
    },
    async put(key: string, value: unknown, _options?: { expirationTtl?: number }): Promise<void> {
      store.set(key, value)
    },
    async delete(key: string): Promise<boolean> {
      return store.delete(key)
    },
    async list<T = unknown>(options?: { prefix?: string; limit?: number }): Promise<Map<string, T>> {
      const result = new Map<string, T>()
      let count = 0
      for (const [key, value] of store) {
        if (options?.prefix && !key.startsWith(options.prefix)) continue
        if (options?.limit && count >= options.limit) break
        result.set(key, value as T)
        count++
      }
      return result
    },
  }
}

const TEST_CONFIG: OAuthConfig = {
  issuer: 'https://id.org.ai',
  authorizationEndpoint: 'https://id.org.ai/oauth/authorize',
  tokenEndpoint: 'https://id.org.ai/oauth/token',
  userinfoEndpoint: 'https://id.org.ai/oauth/userinfo',
  registrationEndpoint: 'https://id.org.ai/oauth/register',
  deviceAuthorizationEndpoint: 'https://id.org.ai/oauth/device',
  revocationEndpoint: 'https://id.org.ai/oauth/revoke',
  introspectionEndpoint: 'https://id.org.ai/oauth/introspect',
  jwksUri: 'https://id.org.ai/.well-known/jwks.json',
}

const TEST_IDENTITIES: Record<string, IdentityInfo> = {
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
    name: 'Bob Agent',
    handle: 'bob',
    email: 'bob@example.com',
    emailVerified: false,
  },
}

function createProvider(storage?: StorageLike): OAuthProvider {
  return new OAuthProvider({
    storage: storage ?? createMockStorage(),
    config: TEST_CONFIG,
    getIdentity: async (id: string) => TEST_IDENTITIES[id] ?? null,
  })
}

async function registerClient(
  provider: OAuthProvider,
  overrides: Record<string, unknown> = {},
): Promise<Record<string, unknown>> {
  const body = {
    client_name: 'Test App',
    redirect_uris: ['https://app.example.com/callback'],
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    scope: 'openid profile email',
    token_endpoint_auth_method: 'none',
    ...overrides,
  }
  const request = new Request('https://id.org.ai/oauth/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  const response = await provider.handleRegister(request)
  return response.json() as Promise<Record<string, unknown>>
}

async function registerConfidentialClient(
  provider: OAuthProvider,
  overrides: Record<string, unknown> = {},
): Promise<Record<string, unknown>> {
  return registerClient(provider, {
    token_endpoint_auth_method: 'client_secret_post',
    ...overrides,
  })
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

async function getAuthCode(
  provider: OAuthProvider,
  clientId: string,
  redirectUri: string,
  identityId: string,
  codeVerifier: string,
  extraParams: Record<string, string> = {},
): Promise<string> {
  const codeChallenge = await computeS256Challenge(codeVerifier)
  const url = new URL('https://id.org.ai/oauth/authorize')
  url.searchParams.set('client_id', clientId)
  url.searchParams.set('redirect_uri', redirectUri)
  url.searchParams.set('response_type', 'code')
  url.searchParams.set('scope', 'openid profile email')
  url.searchParams.set('code_challenge', codeChallenge)
  url.searchParams.set('code_challenge_method', 'S256')
  url.searchParams.set('state', 'test-state')
  for (const [k, v] of Object.entries(extraParams)) url.searchParams.set(k, v)

  const req = new Request(url.toString(), { method: 'GET', redirect: 'manual' })
  const res = await provider.handleAuthorize(req, identityId)
  const location = new URL(res.headers.get('location')!)
  return location.searchParams.get('code')!
}

async function getAuthCodeTokens(
  provider: OAuthProvider,
  clientId: string,
  redirectUri: string,
  identityId: string,
  codeVerifier: string,
): Promise<Record<string, unknown>> {
  const code = await getAuthCode(provider, clientId, redirectUri, identityId, codeVerifier)
  const tokenReq = new Request('https://id.org.ai/oauth/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
      client_id: clientId,
      code_verifier: codeVerifier,
    }),
  })
  const tokenRes = await provider.handleToken(tokenReq)
  return tokenRes.json() as Promise<Record<string, unknown>>
}

function makeTokenRequest(body: Record<string, string>, authHeader?: string): Request {
  const headers: Record<string, string> = { 'Content-Type': 'application/x-www-form-urlencoded' }
  if (authHeader) headers['Authorization'] = authHeader
  return new Request('https://id.org.ai/oauth/token', { method: 'POST', headers, body: new URLSearchParams(body) })
}

function makeJsonRequest(url: string, body: unknown): Request {
  return new Request(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
}

// ============================================================================
// Tests
// ============================================================================

describe('OAuthProvider', () => {
  let storage: StorageLike
  let provider: OAuthProvider

  beforeEach(() => {
    storage = createMockStorage()
    provider = createProvider(storage)
  })

  // ══════════════════════════════════════════════════════════════════════════
  // 1. OIDC Discovery
  // ══════════════════════════════════════════════════════════════════════════

  describe('OIDC Discovery', () => {
    it('returns 200 JSON response', () => {
      const res = provider.getOpenIDConfiguration()
      expect(res.status).toBe(200)
      expect(res.headers.get('Content-Type')).toBe('application/json')
    })

    it('includes issuer matching config', async () => {
      const d = await provider.getOpenIDConfiguration().json()
      expect(d.issuer).toBe('https://id.org.ai')
    })

    it('includes all endpoint URLs', async () => {
      const d = await provider.getOpenIDConfiguration().json() as Record<string, unknown>
      expect(d.authorization_endpoint).toBe(TEST_CONFIG.authorizationEndpoint)
      expect(d.token_endpoint).toBe(TEST_CONFIG.tokenEndpoint)
      expect(d.userinfo_endpoint).toBe(TEST_CONFIG.userinfoEndpoint)
      expect(d.registration_endpoint).toBe(TEST_CONFIG.registrationEndpoint)
      expect(d.device_authorization_endpoint).toBe(TEST_CONFIG.deviceAuthorizationEndpoint)
      expect(d.revocation_endpoint).toBe(TEST_CONFIG.revocationEndpoint)
      expect(d.introspection_endpoint).toBe(TEST_CONFIG.introspectionEndpoint)
      expect(d.jwks_uri).toBe(TEST_CONFIG.jwksUri)
    })

    it('supports only code response type', async () => {
      const d = await provider.getOpenIDConfiguration().json() as Record<string, unknown>
      expect(d.response_types_supported).toEqual(['code'])
    })

    it('supports all four grant types', async () => {
      const d = await provider.getOpenIDConfiguration().json() as Record<string, unknown>
      const gt = d.grant_types_supported as string[]
      expect(gt).toContain('authorization_code')
      expect(gt).toContain('refresh_token')
      expect(gt).toContain('client_credentials')
      expect(gt).toContain('urn:ietf:params:oauth:grant-type:device_code')
    })

    it('only supports S256 code challenge method', async () => {
      const d = await provider.getOpenIDConfiguration().json() as Record<string, unknown>
      expect(d.code_challenge_methods_supported).toEqual(['S256'])
    })

    it('includes scopes and claims', async () => {
      const d = await provider.getOpenIDConfiguration().json() as Record<string, unknown>
      expect(d.scopes_supported).toEqual(['openid', 'profile', 'email', 'offline_access'])
      expect(d.claims_supported).toContain('sub')
      expect(d.claims_supported).toContain('email')
    })

    it('includes token endpoint auth methods', async () => {
      const d = await provider.getOpenIDConfiguration().json() as Record<string, unknown>
      expect(d.token_endpoint_auth_methods_supported).toContain('none')
      expect(d.token_endpoint_auth_methods_supported).toContain('client_secret_basic')
      expect(d.token_endpoint_auth_methods_supported).toContain('client_secret_post')
    })

    it('sets no-store cache control', () => {
      expect(provider.getOpenIDConfiguration().headers.get('Cache-Control')).toBe('no-store')
    })
  })

  // ══════════════════════════════════════════════════════════════════════════
  // 2. Dynamic Client Registration
  // ══════════════════════════════════════════════════════════════════════════

  describe('Dynamic Client Registration', () => {
    it('registers a valid public client', async () => {
      const d = await registerClient(provider)
      expect((d.client_id as string).startsWith('cid_')).toBe(true)
      expect(d.client_name).toBe('Test App')
      expect(d.token_endpoint_auth_method).toBe('none')
      expect(d.client_secret).toBeUndefined()
    })

    it('registers a confidential client with secret', async () => {
      const d = await registerConfidentialClient(provider)
      expect((d.client_secret as string).startsWith('cs_')).toBe(true)
      expect(d.client_secret_expires_at).toBe(0)
    })

    it('rejects GET method', async () => {
      const req = new Request('https://id.org.ai/oauth/register', { method: 'GET' })
      const res = await provider.handleRegister(req)
      expect(res.status).toBe(405)
    })

    it('rejects PUT method', async () => {
      const req = new Request('https://id.org.ai/oauth/register', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ client_name: 'X' }),
      })
      expect((await provider.handleRegister(req)).status).toBe(405)
    })

    it('rejects invalid JSON body', async () => {
      const req = new Request('https://id.org.ai/oauth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{bad json',
      })
      const res = await provider.handleRegister(req)
      expect(res.status).toBe(400)
      expect((await res.json() as Record<string, unknown>).error).toBe('invalid_request')
    })

    it('rejects missing client_name', async () => {
      const req = makeJsonRequest('https://id.org.ai/oauth/register', { redirect_uris: ['https://x.com/cb'] })
      const res = await provider.handleRegister(req)
      expect(res.status).toBe(400)
      const d = await res.json() as Record<string, unknown>
      expect(d.error).toBe('invalid_client_metadata')
      expect(d.error_description).toContain('client_name')
    })

    it('rejects unsupported grant type: implicit', async () => {
      const req = makeJsonRequest('https://id.org.ai/oauth/register', {
        client_name: 'Bad', redirect_uris: ['https://x.com/cb'], grant_types: ['implicit'],
      })
      const d = await (await provider.handleRegister(req)).json() as Record<string, unknown>
      expect(d.error).toBe('invalid_client_metadata')
      expect(d.error_description).toContain('implicit')
    })

    it('rejects unsupported grant type: password', async () => {
      const req = makeJsonRequest('https://id.org.ai/oauth/register', {
        client_name: 'Bad', redirect_uris: ['https://x.com/cb'], grant_types: ['password'],
      })
      expect((await (await provider.handleRegister(req)).json() as Record<string, unknown>).error).toBe('invalid_client_metadata')
    })

    it('rejects non-HTTPS redirect URI', async () => {
      const req = makeJsonRequest('https://id.org.ai/oauth/register', {
        client_name: 'HTTP', redirect_uris: ['http://insecure.com/cb'],
      })
      const d = await (await provider.handleRegister(req)).json() as Record<string, unknown>
      expect(d.error).toBe('invalid_redirect_uri')
      expect(d.error_description).toContain('HTTPS')
    })

    it('allows localhost redirect URI', async () => {
      const d = await registerClient(provider, { redirect_uris: ['http://localhost:3000/cb'] })
      expect(d.client_id).toBeDefined()
    })

    it('allows 127.0.0.1 redirect URI', async () => {
      const d = await registerClient(provider, { redirect_uris: ['http://127.0.0.1:8080/cb'] })
      expect(d.client_id).toBeDefined()
    })

    it('allows HTTPS redirect URI', async () => {
      const d = await registerClient(provider, { redirect_uris: ['https://secure.example.com/cb'] })
      expect(d.redirect_uris).toEqual(['https://secure.example.com/cb'])
    })

    it('rejects redirect URI with fragment', async () => {
      const req = makeJsonRequest('https://id.org.ai/oauth/register', {
        client_name: 'Frag', redirect_uris: ['https://x.com/cb#frag'],
      })
      const d = await (await provider.handleRegister(req)).json() as Record<string, unknown>
      expect(d.error).toBe('invalid_redirect_uri')
      expect(d.error_description).toContain('fragment')
    })

    it('rejects invalid redirect URI', async () => {
      const req = makeJsonRequest('https://id.org.ai/oauth/register', {
        client_name: 'Bad', redirect_uris: ['not-a-url'],
      })
      expect((await (await provider.handleRegister(req)).json() as Record<string, unknown>).error).toBe('invalid_redirect_uri')
    })

    it('requires redirect_uris for authorization_code grant', async () => {
      const req = makeJsonRequest('https://id.org.ai/oauth/register', {
        client_name: 'No URIs', grant_types: ['authorization_code'], redirect_uris: [],
      })
      const d = await (await provider.handleRegister(req)).json() as Record<string, unknown>
      expect(d.error).toBe('invalid_client_metadata')
      expect(d.error_description).toContain('redirect_uris')
    })

    it('allows client_credentials without redirect_uris', async () => {
      const d = await registerClient(provider, {
        grant_types: ['client_credentials'], redirect_uris: [],
        token_endpoint_auth_method: 'client_secret_post',
      })
      expect(d.client_id).toBeDefined()
    })

    it('returns 201 on success', async () => {
      const req = makeJsonRequest('https://id.org.ai/oauth/register', {
        client_name: 'OK', redirect_uris: ['https://x.com/cb'],
      })
      expect((await provider.handleRegister(req)).status).toBe(201)
    })

    it('includes client_id_issued_at', async () => {
      const d = await registerClient(provider)
      expect(typeof d.client_id_issued_at).toBe('number')
      expect(d.client_id_issued_at as number).toBeGreaterThan(0)
    })

    it('includes optional logo_uri and client_uri', async () => {
      const d = await registerClient(provider, {
        logo_uri: 'https://x.com/logo.png', client_uri: 'https://x.com',
      })
      expect(d.logo_uri).toBe('https://x.com/logo.png')
      expect(d.client_uri).toBe('https://x.com')
    })

    it('defaults to authorization_code + refresh_token', async () => {
      const req = makeJsonRequest('https://id.org.ai/oauth/register', {
        client_name: 'Defaults', redirect_uris: ['https://x.com/cb'],
      })
      const d = await (await provider.handleRegister(req)).json() as Record<string, unknown>
      expect(d.grant_types).toEqual(['authorization_code', 'refresh_token'])
    })

    it('stores client in storage', async () => {
      const d = await registerClient(provider)
      const stored = await storage.get<Record<string, unknown>>(`client:${d.client_id}`)
      expect(stored).toBeDefined()
      expect(stored!.name).toBe('Test App')
    })
  })

  // ══════════════════════════════════════════════════════════════════════════
  // 3. Authorization Code + PKCE
  // ══════════════════════════════════════════════════════════════════════════

  describe('Authorization Code + PKCE', () => {
    let clientId: string
    const redir = 'https://app.example.com/callback'
    const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'

    beforeEach(async () => {
      const d = await registerClient(provider)
      clientId = d.client_id as string
      const s = await storage.get<Record<string, unknown>>(`client:${clientId}`)
      await storage.put(`client:${clientId}`, { ...s, trusted: true })
    })

    it('completes full auth code flow', async () => {
      const t = await getAuthCodeTokens(provider, clientId, redir, 'user-1', verifier)
      expect((t.access_token as string).startsWith('at_')).toBe(true)
      expect((t.refresh_token as string).startsWith('rt_')).toBe(true)
      expect(t.token_type).toBe('Bearer')
      expect(t.expires_in).toBe(3600)
      expect(t.scope).toBe('openid profile email')
    })

    it('redirects with code and state', async () => {
      const ch = await computeS256Challenge(verifier)
      const url = new URL('https://id.org.ai/oauth/authorize')
      url.searchParams.set('client_id', clientId)
      url.searchParams.set('redirect_uri', redir)
      url.searchParams.set('response_type', 'code')
      url.searchParams.set('scope', 'openid profile email')
      url.searchParams.set('code_challenge', ch)
      url.searchParams.set('code_challenge_method', 'S256')
      url.searchParams.set('state', 'my-state')

      const res = await provider.handleAuthorize(new Request(url.toString(), { method: 'GET', redirect: 'manual' }), 'user-1')
      expect(res.status).toBe(302)
      const loc = new URL(res.headers.get('location')!)
      expect(loc.searchParams.get('code')!.startsWith('ac_')).toBe(true)
      expect(loc.searchParams.get('state')).toBe('my-state')
    })

    it('requires code_challenge for public clients', async () => {
      const url = new URL('https://id.org.ai/oauth/authorize')
      url.searchParams.set('client_id', clientId)
      url.searchParams.set('redirect_uri', redir)
      url.searchParams.set('response_type', 'code')

      const res = await provider.handleAuthorize(new Request(url.toString(), { method: 'GET', redirect: 'manual' }), 'user-1')
      expect(res.status).toBe(302)
      const loc = new URL(res.headers.get('location')!)
      expect(loc.searchParams.get('error')).toBe('invalid_request')
      expect(loc.searchParams.get('error_description')).toContain('code_challenge')
    })

    it('rejects non-S256 code_challenge_method', async () => {
      const url = new URL('https://id.org.ai/oauth/authorize')
      url.searchParams.set('client_id', clientId)
      url.searchParams.set('redirect_uri', redir)
      url.searchParams.set('response_type', 'code')
      url.searchParams.set('code_challenge', 'plain_value')
      url.searchParams.set('code_challenge_method', 'plain')

      const res = await provider.handleAuthorize(new Request(url.toString(), { method: 'GET', redirect: 'manual' }), 'user-1')
      const loc = new URL(res.headers.get('location')!)
      expect(loc.searchParams.get('error')).toBe('invalid_request')
      expect(loc.searchParams.get('error_description')).toContain('S256')
    })

    it('rejects unknown client_id', async () => {
      const url = new URL('https://id.org.ai/oauth/authorize')
      url.searchParams.set('client_id', 'cid_nonexistent')
      url.searchParams.set('redirect_uri', redir)
      url.searchParams.set('response_type', 'code')

      const res = await provider.handleAuthorize(new Request(url.toString(), { method: 'GET', redirect: 'manual' }), 'user-1')
      expect(res.status).toBe(400)
      expect((await res.json() as Record<string, unknown>).error).toBe('invalid_client')
    })

    it('rejects invalid redirect_uri', async () => {
      const url = new URL('https://id.org.ai/oauth/authorize')
      url.searchParams.set('client_id', clientId)
      url.searchParams.set('redirect_uri', 'https://evil.com/steal')
      url.searchParams.set('response_type', 'code')

      const res = await provider.handleAuthorize(new Request(url.toString(), { method: 'GET', redirect: 'manual' }), 'user-1')
      expect(res.status).toBe(400)
      expect((await res.json() as Record<string, unknown>).error).toBe('invalid_request')
    })

    it('rejects unsupported response_type token', async () => {
      const ch = await computeS256Challenge(verifier)
      const url = new URL('https://id.org.ai/oauth/authorize')
      url.searchParams.set('client_id', clientId)
      url.searchParams.set('redirect_uri', redir)
      url.searchParams.set('response_type', 'token')
      url.searchParams.set('code_challenge', ch)
      url.searchParams.set('code_challenge_method', 'S256')

      const res = await provider.handleAuthorize(new Request(url.toString(), { method: 'GET', redirect: 'manual' }), 'user-1')
      expect(res.status).toBe(302)
      expect(new URL(res.headers.get('location')!).searchParams.get('error')).toBe('unsupported_response_type')
    })

    it('rejects wrong code_verifier', async () => {
      const code = await getAuthCode(provider, clientId, redir, 'user-1', verifier)
      const res = await provider.handleToken(makeTokenRequest({
        grant_type: 'authorization_code', code, redirect_uri: redir,
        client_id: clientId, code_verifier: 'wrong-verifier',
      }))
      expect(res.status).toBe(400)
      expect((await res.json() as Record<string, unknown>).error).toBe('invalid_grant')
    })

    it('succeeds with correct code_verifier', async () => {
      const t = await getAuthCodeTokens(provider, clientId, redir, 'user-1', verifier)
      expect(t.access_token).toBeDefined()
      expect(t.error).toBeUndefined()
    })

    it('rejects code reuse (one-time use)', async () => {
      const code = await getAuthCode(provider, clientId, redir, 'user-1', verifier)
      const body = { grant_type: 'authorization_code', code, redirect_uri: redir, client_id: clientId, code_verifier: verifier }

      const r1 = await provider.handleToken(makeTokenRequest(body))
      expect(r1.status).toBe(200)

      const r2 = await provider.handleToken(makeTokenRequest(body))
      expect(r2.status).toBe(400)
      expect((await r2.json() as Record<string, unknown>).error).toBe('invalid_grant')
    })

    it('rejects expired authorization code', async () => {
      const code = await getAuthCode(provider, clientId, redir, 'user-1', verifier)
      const cd = await storage.get<Record<string, unknown>>(`code:${code}`)
      await storage.put(`code:${code}`, { ...cd, expiresAt: Date.now() - 1000 })

      const res = await provider.handleToken(makeTokenRequest({
        grant_type: 'authorization_code', code, redirect_uri: redir,
        client_id: clientId, code_verifier: verifier,
      }))
      expect(res.status).toBe(400)
      const d = await res.json() as Record<string, unknown>
      expect(d.error).toBe('invalid_grant')
      expect(d.error_description).toContain('expired')
    })

    it('rejects redirect_uri mismatch on token exchange', async () => {
      const code = await getAuthCode(provider, clientId, redir, 'user-1', verifier)
      const res = await provider.handleToken(makeTokenRequest({
        grant_type: 'authorization_code', code, redirect_uri: 'https://other.com/cb',
        client_id: clientId, code_verifier: verifier,
      }))
      expect(res.status).toBe(400)
      expect((await res.json() as Record<string, unknown>).error_description).toContain('redirect_uri')
    })

    it('rejects wrong client_id on token exchange', async () => {
      const other = await registerClient(provider, { client_name: 'Other', redirect_uris: ['https://o.com/cb'] })
      const code = await getAuthCode(provider, clientId, redir, 'user-1', verifier)
      const res = await provider.handleToken(makeTokenRequest({
        grant_type: 'authorization_code', code, redirect_uri: redir,
        client_id: other.client_id as string, code_verifier: verifier,
      }))
      expect(res.status).toBe(400)
    })

    it('rejects missing code on token exchange', async () => {
      const res = await provider.handleToken(makeTokenRequest({
        grant_type: 'authorization_code', redirect_uri: redir,
        client_id: clientId, code_verifier: verifier,
      }))
      expect(res.status).toBe(400)
      expect((await res.json() as Record<string, unknown>).error_description).toContain('code')
    })

    it('rejects missing code_verifier when code has challenge', async () => {
      const code = await getAuthCode(provider, clientId, redir, 'user-1', verifier)
      const res = await provider.handleToken(makeTokenRequest({
        grant_type: 'authorization_code', code, redirect_uri: redir, client_id: clientId,
      }))
      expect(res.status).toBe(400)
      expect((await res.json() as Record<string, unknown>).error_description).toContain('code_verifier')
    })

    it('redirects to login when user not authenticated', async () => {
      const ch = await computeS256Challenge(verifier)
      const url = new URL('https://id.org.ai/oauth/authorize')
      url.searchParams.set('client_id', clientId)
      url.searchParams.set('redirect_uri', redir)
      url.searchParams.set('response_type', 'code')
      url.searchParams.set('code_challenge', ch)
      url.searchParams.set('code_challenge_method', 'S256')

      const res = await provider.handleAuthorize(new Request(url.toString(), { method: 'GET', redirect: 'manual' }), null)
      expect(res.status).toBe(302)
      const loc = new URL(res.headers.get('location')!)
      expect(loc.pathname).toBe('/login')
      expect(loc.searchParams.get('continue')).toContain('authorize')
    })

    it('shows consent page for untrusted client', async () => {
      const ud = await registerClient(provider, { client_name: 'Untrusted' })
      const ch = await computeS256Challenge(verifier)
      const url = new URL('https://id.org.ai/oauth/authorize')
      url.searchParams.set('client_id', ud.client_id as string)
      url.searchParams.set('redirect_uri', redir)
      url.searchParams.set('response_type', 'code')
      url.searchParams.set('scope', 'openid profile email')
      url.searchParams.set('code_challenge', ch)
      url.searchParams.set('code_challenge_method', 'S256')

      const res = await provider.handleAuthorize(new Request(url.toString(), { method: 'GET', redirect: 'manual' }), 'user-1')
      expect(res.status).toBe(200)
      expect(res.headers.get('Content-Type')).toContain('text/html')
      const html = await res.text()
      expect(html).toContain('Authorize application')
      expect(html).toContain('Untrusted')
    })

    it('trusted client skips consent', async () => {
      const ch = await computeS256Challenge(verifier)
      const url = new URL('https://id.org.ai/oauth/authorize')
      url.searchParams.set('client_id', clientId)
      url.searchParams.set('redirect_uri', redir)
      url.searchParams.set('response_type', 'code')
      url.searchParams.set('scope', 'openid profile email')
      url.searchParams.set('code_challenge', ch)
      url.searchParams.set('code_challenge_method', 'S256')

      const res = await provider.handleAuthorize(new Request(url.toString(), { method: 'GET', redirect: 'manual' }), 'user-1')
      expect(res.status).toBe(302)
      expect(new URL(res.headers.get('location')!).searchParams.get('code')).toBeDefined()
    })

    it('skips consent with prior consent record', async () => {
      const ud = await registerClient(provider, { client_name: 'Prior' })
      await storage.put(`consent:user-1:${ud.client_id}`, { scopes: ['openid', 'profile', 'email'], createdAt: Date.now() })

      const ch = await computeS256Challenge(verifier)
      const url = new URL('https://id.org.ai/oauth/authorize')
      url.searchParams.set('client_id', ud.client_id as string)
      url.searchParams.set('redirect_uri', redir)
      url.searchParams.set('response_type', 'code')
      url.searchParams.set('scope', 'openid profile email')
      url.searchParams.set('code_challenge', ch)
      url.searchParams.set('code_challenge_method', 'S256')

      const res = await provider.handleAuthorize(new Request(url.toString(), { method: 'GET', redirect: 'manual' }), 'user-1')
      expect(res.status).toBe(302)
    })

    it('shows consent when new scopes exceed prior consent', async () => {
      const ud = await registerClient(provider, { client_name: 'Scope', scope: 'openid profile email offline_access' })
      await storage.put(`consent:user-1:${ud.client_id}`, { scopes: ['openid', 'profile'], createdAt: Date.now() })

      const ch = await computeS256Challenge(verifier)
      const url = new URL('https://id.org.ai/oauth/authorize')
      url.searchParams.set('client_id', ud.client_id as string)
      url.searchParams.set('redirect_uri', redir)
      url.searchParams.set('response_type', 'code')
      url.searchParams.set('scope', 'openid profile email')
      url.searchParams.set('code_challenge', ch)
      url.searchParams.set('code_challenge_method', 'S256')

      const res = await provider.handleAuthorize(new Request(url.toString(), { method: 'GET', redirect: 'manual' }), 'user-1')
      expect(res.status).toBe(200)
      expect(res.headers.get('Content-Type')).toContain('text/html')
    })

    it('rejects GET on token endpoint', async () => {
      expect((await provider.handleToken(new Request('https://id.org.ai/oauth/token', { method: 'GET' }))).status).toBe(405)
    })

    it('rejects unsupported grant_type', async () => {
      const res = await provider.handleToken(makeTokenRequest({ grant_type: 'password' }))
      expect((await res.json() as Record<string, unknown>).error).toBe('unsupported_grant_type')
    })

    it('supports Basic auth on token endpoint', async () => {
      const cd = await registerConfidentialClient(provider)
      const cid = cd.client_id as string
      const cs = cd.client_secret as string
      const s = await storage.get<Record<string, unknown>>(`client:${cid}`)
      await storage.put(`client:${cid}`, { ...s, trusted: true, redirectUris: [redir] })

      const url = new URL('https://id.org.ai/oauth/authorize')
      url.searchParams.set('client_id', cid)
      url.searchParams.set('redirect_uri', redir)
      url.searchParams.set('response_type', 'code')
      url.searchParams.set('scope', 'openid profile email')

      const authRes = await provider.handleAuthorize(new Request(url.toString(), { method: 'GET', redirect: 'manual' }), 'user-1')
      const code = new URL(authRes.headers.get('location')!).searchParams.get('code')!

      const basic = 'Basic ' + btoa(`${cid}:${cs}`)
      const tRes = await provider.handleToken(makeTokenRequest({ grant_type: 'authorization_code', code, redirect_uri: redir }, basic))
      expect(tRes.status).toBe(200)
      expect((await tRes.json() as Record<string, unknown>).access_token).toBeDefined()
    })
  })

  // ══════════════════════════════════════════════════════════════════════════
  // 4. Consent Submission
  // ══════════════════════════════════════════════════════════════════════════

  describe('Consent Submission', () => {
    let untrustedId: string
    const redir = 'https://app.example.com/callback'
    const verifier = 'consent-test-verifier-long-enough-value'

    beforeEach(async () => {
      untrustedId = (await registerClient(provider, { client_name: 'Consent App' })).client_id as string
    })

    it('issues code after user approves', async () => {
      const ch = await computeS256Challenge(verifier)
      const req = new Request('https://id.org.ai/oauth/authorize', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id: untrustedId, redirect_uri: redir, scope: 'openid profile email',
          state: 'cs', code_challenge: ch, code_challenge_method: 'S256', approved: 'true',
        }),
      })
      const res = await provider.handleAuthorizeConsent(req, 'user-1')
      expect(res.status).toBe(302)
      const loc = new URL(res.headers.get('location')!)
      expect(loc.searchParams.get('code')).toBeDefined()
      expect(loc.searchParams.get('state')).toBe('cs')
    })

    it('redirects with access_denied when user denies', async () => {
      const req = new Request('https://id.org.ai/oauth/authorize', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id: untrustedId, redirect_uri: redir, state: 'ds', approved: 'false',
        }),
      })
      const res = await provider.handleAuthorizeConsent(req, 'user-1')
      expect(res.status).toBe(302)
      expect(new URL(res.headers.get('location')!).searchParams.get('error')).toBe('access_denied')
    })

    it('stores consent record', async () => {
      const ch = await computeS256Challenge(verifier)
      const req = new Request('https://id.org.ai/oauth/authorize', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id: untrustedId, redirect_uri: redir, scope: 'openid profile email',
          code_challenge: ch, code_challenge_method: 'S256', approved: 'true',
        }),
      })
      await provider.handleAuthorizeConsent(req, 'user-1')
      const c = await storage.get<Record<string, unknown>>(`consent:user-1:${untrustedId}`)
      expect(c).toBeDefined()
      expect((c!.scopes as string[])).toContain('email')
    })

    it('rejects unknown client_id', async () => {
      const req = new Request('https://id.org.ai/oauth/authorize', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ client_id: 'cid_bogus', redirect_uri: redir, approved: 'true' }),
      })
      const res = await provider.handleAuthorizeConsent(req, 'user-1')
      expect(res.status).toBe(400)
      expect((await res.json() as Record<string, unknown>).error).toBe('invalid_client')
    })
  })

  // ══════════════════════════════════════════════════════════════════════════
  // 5. Refresh Token
  // ══════════════════════════════════════════════════════════════════════════

  describe('Refresh Token', () => {
    let clientId: string
    const redir = 'https://app.example.com/callback'
    const verifier = 'refresh-test-verifier-long-enough-value'

    beforeEach(async () => {
      clientId = (await registerClient(provider)).client_id as string
      const s = await storage.get<Record<string, unknown>>(`client:${clientId}`)
      await storage.put(`client:${clientId}`, { ...s, trusted: true })
    })

    it('exchanges refresh token for new pair', async () => {
      const t1 = await getAuthCodeTokens(provider, clientId, redir, 'user-1', verifier)
      const res = await provider.handleToken(makeTokenRequest({
        grant_type: 'refresh_token', refresh_token: t1.refresh_token as string, client_id: clientId,
      }))
      expect(res.status).toBe(200)
      const t2 = await res.json() as Record<string, unknown>
      expect(t2.access_token).not.toBe(t1.access_token)
      expect(t2.refresh_token).not.toBe(t1.refresh_token)
    })

    it('rotates: old token revoked after use', async () => {
      const t = await getAuthCodeTokens(provider, clientId, redir, 'user-1', verifier)
      const rt = t.refresh_token as string
      await provider.handleToken(makeTokenRequest({ grant_type: 'refresh_token', refresh_token: rt, client_id: clientId }))
      const d = await storage.get<Record<string, unknown>>(`refresh:${rt}`)
      expect(d!.revoked).toBe(true)
    })

    it('detects replay and revokes entire family', async () => {
      const t1 = await getAuthCodeTokens(provider, clientId, redir, 'user-1', verifier)
      const rt1 = t1.refresh_token as string

      const r1 = await provider.handleToken(makeTokenRequest({ grant_type: 'refresh_token', refresh_token: rt1, client_id: clientId }))
      const t2 = await r1.json() as Record<string, unknown>
      const rt2 = t2.refresh_token as string

      // Replay old token
      const r2 = await provider.handleToken(makeTokenRequest({ grant_type: 'refresh_token', refresh_token: rt1, client_id: clientId }))
      expect(r2.status).toBe(400)
      expect((await r2.json() as Record<string, unknown>).error_description).toContain('revoked')

      // New token also revoked (family revocation)
      expect((await storage.get<Record<string, unknown>>(`refresh:${rt2}`))!.revoked).toBe(true)
    })

    it('rejects expired refresh token', async () => {
      const t = await getAuthCodeTokens(provider, clientId, redir, 'user-1', verifier)
      const rt = t.refresh_token as string
      const d = await storage.get<Record<string, unknown>>(`refresh:${rt}`)
      await storage.put(`refresh:${rt}`, { ...d, expiresAt: Date.now() - 1000 })

      const res = await provider.handleToken(makeTokenRequest({ grant_type: 'refresh_token', refresh_token: rt, client_id: clientId }))
      expect(res.status).toBe(400)
      expect((await res.json() as Record<string, unknown>).error_description).toContain('expired')
    })

    it('rejects refresh token from different client', async () => {
      const t = await getAuthCodeTokens(provider, clientId, redir, 'user-1', verifier)
      const other = (await registerClient(provider, { client_name: 'Other', redirect_uris: ['https://o.com/cb'] })).client_id as string
      const res = await provider.handleToken(makeTokenRequest({
        grant_type: 'refresh_token', refresh_token: t.refresh_token as string, client_id: other,
      }))
      expect(res.status).toBe(400)
      expect((await res.json() as Record<string, unknown>).error_description).toContain('not issued to this client')
    })

    it('rejects missing refresh_token parameter', async () => {
      const res = await provider.handleToken(makeTokenRequest({ grant_type: 'refresh_token', client_id: clientId }))
      expect((await res.json() as Record<string, unknown>).error_description).toContain('refresh_token')
    })

    it('rejects invalid refresh token id', async () => {
      const res = await provider.handleToken(makeTokenRequest({
        grant_type: 'refresh_token', refresh_token: 'rt_nonexistent', client_id: clientId,
      }))
      expect((await res.json() as Record<string, unknown>).error).toBe('invalid_grant')
    })

    it('preserves family across rotations', async () => {
      const t1 = await getAuthCodeTokens(provider, clientId, redir, 'user-1', verifier)
      const family = (await storage.get<Record<string, unknown>>(`refresh:${t1.refresh_token}`))!.family

      const r1 = await (await provider.handleToken(makeTokenRequest({
        grant_type: 'refresh_token', refresh_token: t1.refresh_token as string, client_id: clientId,
      }))).json() as Record<string, unknown>
      expect((await storage.get<Record<string, unknown>>(`refresh:${r1.refresh_token}`))!.family).toBe(family)

      const r2 = await (await provider.handleToken(makeTokenRequest({
        grant_type: 'refresh_token', refresh_token: r1.refresh_token as string, client_id: clientId,
      }))).json() as Record<string, unknown>
      expect((await storage.get<Record<string, unknown>>(`refresh:${r2.refresh_token}`))!.family).toBe(family)
    })

    it('validates confidential client secret on refresh', async () => {
      const cd = await registerConfidentialClient(provider)
      const cid = cd.client_id as string
      const cs = cd.client_secret as string
      const s = await storage.get<Record<string, unknown>>(`client:${cid}`)
      await storage.put(`client:${cid}`, { ...s, trusted: true, redirectUris: [redir] })

      // Get tokens via auth code
      const url = new URL('https://id.org.ai/oauth/authorize')
      url.searchParams.set('client_id', cid)
      url.searchParams.set('redirect_uri', redir)
      url.searchParams.set('response_type', 'code')
      url.searchParams.set('scope', 'openid profile email')
      const authRes = await provider.handleAuthorize(new Request(url.toString(), { method: 'GET', redirect: 'manual' }), 'user-1')
      const code = new URL(authRes.headers.get('location')!).searchParams.get('code')!
      const basic = 'Basic ' + btoa(`${cid}:${cs}`)
      const tRes = await provider.handleToken(makeTokenRequest({ grant_type: 'authorization_code', code, redirect_uri: redir }, basic))
      const tokens = await tRes.json() as Record<string, unknown>

      // Refresh with wrong secret
      const res = await provider.handleToken(makeTokenRequest({
        grant_type: 'refresh_token', refresh_token: tokens.refresh_token as string,
        client_id: cid, client_secret: 'cs_wrong',
      }))
      expect(res.status).toBe(401)
      expect((await res.json() as Record<string, unknown>).error).toBe('invalid_client')
    })

    it('maintains scope through rotation', async () => {
      const t1 = await getAuthCodeTokens(provider, clientId, redir, 'user-1', verifier)
      expect(t1.scope).toBe('openid profile email')
      const t2 = await (await provider.handleToken(makeTokenRequest({
        grant_type: 'refresh_token', refresh_token: t1.refresh_token as string, client_id: clientId,
      }))).json() as Record<string, unknown>
      expect(t2.scope).toBe('openid profile email')
    })
  })

  // ══════════════════════════════════════════════════════════════════════════
  // 6. Client Credentials
  // ══════════════════════════════════════════════════════════════════════════

  describe('Client Credentials', () => {
    let cid: string
    let cs: string

    beforeEach(async () => {
      const d = await registerConfidentialClient(provider, { grant_types: ['client_credentials'], redirect_uris: [] })
      cid = d.client_id as string
      cs = d.client_secret as string
    })

    it('issues access token for valid credentials', async () => {
      const res = await provider.handleToken(makeTokenRequest({ grant_type: 'client_credentials', client_id: cid, client_secret: cs }))
      expect(res.status).toBe(200)
      const d = await res.json() as Record<string, unknown>
      expect((d.access_token as string).startsWith('at_')).toBe(true)
      expect(d.token_type).toBe('Bearer')
      expect(d.expires_in).toBe(3600)
      expect(d.refresh_token).toBeUndefined()
    })

    it('uses Basic auth', async () => {
      const basic = 'Basic ' + btoa(`${cid}:${cs}`)
      const res = await provider.handleToken(makeTokenRequest({ grant_type: 'client_credentials' }, basic))
      expect(res.status).toBe(200)
    })

    it('rejects missing client_secret', async () => {
      const res = await provider.handleToken(makeTokenRequest({ grant_type: 'client_credentials', client_id: cid }))
      expect(res.status).toBe(401)
    })

    it('rejects wrong client_secret', async () => {
      const res = await provider.handleToken(makeTokenRequest({ grant_type: 'client_credentials', client_id: cid, client_secret: 'cs_wrong' }))
      expect(res.status).toBe(401)
    })

    it('rejects unknown client_id', async () => {
      const res = await provider.handleToken(makeTokenRequest({ grant_type: 'client_credentials', client_id: 'cid_x', client_secret: 'cs_x' }))
      expect(res.status).toBe(401)
    })

    it('rejects client not authorized for client_credentials', async () => {
      const d = await registerConfidentialClient(provider, { grant_types: ['authorization_code'], redirect_uris: ['https://x.com/cb'] })
      const res = await provider.handleToken(makeTokenRequest({
        grant_type: 'client_credentials', client_id: d.client_id as string, client_secret: d.client_secret as string,
      }))
      expect((await res.json() as Record<string, unknown>).error).toBe('unauthorized_client')
    })

    it('rejects public client', async () => {
      const d = await registerClient(provider, { grant_types: ['client_credentials'], redirect_uris: [] })
      const res = await provider.handleToken(makeTokenRequest({ grant_type: 'client_credentials', client_id: d.client_id as string }))
      expect(res.status).toBe(401)
    })

    it('respects custom scope', async () => {
      const res = await provider.handleToken(makeTokenRequest({
        grant_type: 'client_credentials', client_id: cid, client_secret: cs, scope: 'openid profile',
      }))
      expect((await res.json() as Record<string, unknown>).scope).toBe('openid profile')
    })
  })

  // ══════════════════════════════════════════════════════════════════════════
  // 7. Device Flow
  // ══════════════════════════════════════════════════════════════════════════

  describe('Device Flow', () => {
    let dcid: string

    beforeEach(async () => {
      dcid = (await registerClient(provider, {
        client_name: 'CLI', grant_types: ['urn:ietf:params:oauth:grant-type:device_code'], redirect_uris: [],
      })).client_id as string
    })

    async function initDevice(): Promise<Record<string, unknown>> {
      const req = new Request('https://id.org.ai/oauth/device', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ client_id: dcid }),
      })
      return (await provider.handleDeviceAuthorization(req)).json() as Promise<Record<string, unknown>>
    }

    it('initiates device authorization', async () => {
      const d = await initDevice()
      expect((d.device_code as string).startsWith('dc_')).toBe(true)
      expect((d.user_code as string).length).toBe(8)
      expect(d.verification_uri).toBe('https://id.org.ai/device')
      expect(d.verification_uri_complete).toContain('user_code=')
      expect(d.expires_in).toBe(1800)
      expect(d.interval).toBe(5)
    })

    it('rejects non-POST for device authorization', async () => {
      const res = await provider.handleDeviceAuthorization(new Request('https://id.org.ai/oauth/device', { method: 'GET' }))
      expect(res.status).toBe(405)
    })

    it('rejects missing client_id', async () => {
      const req = new Request('https://id.org.ai/oauth/device', {
        method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({}),
      })
      expect((await (await provider.handleDeviceAuthorization(req)).json() as Record<string, unknown>).error).toBe('invalid_request')
    })

    it('rejects unknown client', async () => {
      const req = new Request('https://id.org.ai/oauth/device', {
        method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ client_id: 'cid_unknown' }),
      })
      expect((await (await provider.handleDeviceAuthorization(req)).json() as Record<string, unknown>).error).toBe('invalid_client')
    })

    it('rejects client not authorized for device_code', async () => {
      const other = (await registerClient(provider, { client_name: 'NoDevice', redirect_uris: ['https://x.com/cb'] })).client_id as string
      const req = new Request('https://id.org.ai/oauth/device', {
        method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ client_id: other }),
      })
      expect((await (await provider.handleDeviceAuthorization(req)).json() as Record<string, unknown>).error).toBe('unauthorized_client')
    })

    it('returns authorization_pending before user acts', async () => {
      const d = await initDevice()
      const res = await provider.handleToken(makeTokenRequest({
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code', device_code: d.device_code as string, client_id: dcid,
      }))
      expect(res.status).toBe(400)
      expect((await res.json() as Record<string, unknown>).error).toBe('authorization_pending')
    })

    it('returns access_denied when user denies', async () => {
      const d = await initDevice()
      await provider.handleDeviceVerification(new Request('https://id.org.ai/device', {
        method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ user_code: d.user_code as string, approved: 'false' }),
      }), 'user-1')

      const res = await provider.handleToken(makeTokenRequest({
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code', device_code: d.device_code as string, client_id: dcid,
      }))
      expect((await res.json() as Record<string, unknown>).error).toBe('access_denied')
    })

    it('full device flow: init -> approve -> tokens', async () => {
      const d = await initDevice()
      const approveRes = await provider.handleDeviceVerification(new Request('https://id.org.ai/device', {
        method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ user_code: d.user_code as string, approved: 'true' }),
      }), 'user-1')
      expect(await approveRes.text()).toContain('Device Authorized')

      const res = await provider.handleToken(makeTokenRequest({
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code', device_code: d.device_code as string, client_id: dcid,
      }))
      expect(res.status).toBe(200)
      const t = await res.json() as Record<string, unknown>
      expect(t.access_token).toBeDefined()
      expect(t.refresh_token).toBeDefined()
      expect(t.token_type).toBe('Bearer')
    })

    it('returns expired_token for expired device code', async () => {
      const d = await initDevice()
      const dc = await storage.get<Record<string, unknown>>(`device:${d.device_code}`)
      await storage.put(`device:${d.device_code}`, { ...dc, expiresAt: Date.now() - 1000 })

      const res = await provider.handleToken(makeTokenRequest({
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code', device_code: d.device_code as string, client_id: dcid,
      }))
      expect((await res.json() as Record<string, unknown>).error).toBe('expired_token')
    })

    it('rejects device code from wrong client', async () => {
      const d = await initDevice()
      const other = (await registerClient(provider, {
        client_name: 'Other', grant_types: ['urn:ietf:params:oauth:grant-type:device_code'], redirect_uris: [],
      })).client_id as string

      const res = await provider.handleToken(makeTokenRequest({
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code', device_code: d.device_code as string, client_id: other,
      }))
      expect((await res.json() as Record<string, unknown>).error).toBe('invalid_grant')
    })

    it('rejects invalid device code', async () => {
      const res = await provider.handleToken(makeTokenRequest({
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code', device_code: 'dc_none', client_id: dcid,
      }))
      expect((await res.json() as Record<string, unknown>).error).toBe('invalid_grant')
    })

    it('rejects missing device_code', async () => {
      const res = await provider.handleToken(makeTokenRequest({
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code', client_id: dcid,
      }))
      expect((await res.json() as Record<string, unknown>).error).toBe('invalid_request')
    })

    it('device code is one-time use', async () => {
      const d = await initDevice()
      await provider.handleDeviceVerification(new Request('https://id.org.ai/device', {
        method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ user_code: d.user_code as string, approved: 'true' }),
      }), 'user-1')

      const body = { grant_type: 'urn:ietf:params:oauth:grant-type:device_code', device_code: d.device_code as string, client_id: dcid }
      expect((await provider.handleToken(makeTokenRequest(body))).status).toBe(200)
      expect((await provider.handleToken(makeTokenRequest(body))).status).toBe(400)
    })

    it('redirects to login for unauthenticated user', async () => {
      const res = await provider.handleDeviceVerification(new Request('https://id.org.ai/device', { method: 'GET', redirect: 'manual' }), null)
      expect(res.status).toBe(302)
      expect(new URL(res.headers.get('location')!).pathname).toBe('/login')
    })

    it('renders verification page with user_code', async () => {
      const res = await provider.handleDeviceVerification(
        new Request('https://id.org.ai/device?user_code=ABCD1234', { method: 'GET' }), 'user-1',
      )
      expect(res.status).toBe(200)
      const html = await res.text()
      expect(html).toContain('Authorize Device')
      expect(html).toContain('ABCD1234')
    })

    it('shows error for short user code', async () => {
      const res = await provider.handleDeviceVerification(new Request('https://id.org.ai/device', {
        method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ user_code: 'ABC', approved: 'true' }),
      }), 'user-1')
      expect(await res.text()).toContain('valid 8-character code')
    })

    it('shows error for non-existent user code', async () => {
      const res = await provider.handleDeviceVerification(new Request('https://id.org.ai/device', {
        method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ user_code: 'ZZZZZZZZ', approved: 'true' }),
      }), 'user-1')
      expect(await res.text()).toContain('Invalid or expired code')
    })

    it('rejects PUT method for device verification', async () => {
      const res = await provider.handleDeviceVerification(new Request('https://id.org.ai/device', { method: 'PUT' }), 'user-1')
      expect(res.status).toBe(405)
    })
  })

  // ══════════════════════════════════════════════════════════════════════════
  // 8. Token Introspection
  // ══════════════════════════════════════════════════════════════════════════

  describe('Token Introspection', () => {
    let clientId: string
    const redir = 'https://app.example.com/callback'
    const verifier = 'introspection-verifier-long-enough'

    beforeEach(async () => {
      clientId = (await registerClient(provider)).client_id as string
      const s = await storage.get<Record<string, unknown>>(`client:${clientId}`)
      await storage.put(`client:${clientId}`, { ...s, trusted: true })
    })

    function introspect(token: string): Promise<Response> {
      return provider.handleIntrospect(new Request('https://id.org.ai/oauth/introspect', {
        method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token }),
      }))
    }

    it('active=true for valid access token', async () => {
      const t = await getAuthCodeTokens(provider, clientId, redir, 'user-1', verifier)
      const d = await (await introspect(t.access_token as string)).json() as Record<string, unknown>
      expect(d.active).toBe(true)
      expect(d.client_id).toBe(clientId)
      expect(d.sub).toBe('user-1')
      expect(d.token_type).toBe('Bearer')
      expect(d.scope).toContain('openid')
      expect(d.exp).toBeDefined()
      expect(d.iat).toBeDefined()
    })

    it('active=true for valid refresh token', async () => {
      const t = await getAuthCodeTokens(provider, clientId, redir, 'user-1', verifier)
      const d = await (await introspect(t.refresh_token as string)).json() as Record<string, unknown>
      expect(d.active).toBe(true)
      expect(d.token_type).toBe('refresh_token')
    })

    it('active=false for expired access token', async () => {
      const t = await getAuthCodeTokens(provider, clientId, redir, 'user-1', verifier)
      const at = t.access_token as string
      const td = await storage.get<Record<string, unknown>>(`access:${at}`)
      await storage.put(`access:${at}`, { ...td, expiresAt: Date.now() - 1000 })
      expect((await (await introspect(at)).json() as Record<string, unknown>).active).toBe(false)
    })

    it('active=false for revoked refresh token', async () => {
      const t = await getAuthCodeTokens(provider, clientId, redir, 'user-1', verifier)
      const rt = t.refresh_token as string
      await provider.handleToken(makeTokenRequest({ grant_type: 'refresh_token', refresh_token: rt, client_id: clientId }))
      expect((await (await introspect(rt)).json() as Record<string, unknown>).active).toBe(false)
    })

    it('active=false for unknown token', async () => {
      expect((await (await introspect('at_nonexistent')).json() as Record<string, unknown>).active).toBe(false)
    })

    it('active=false when no token provided', async () => {
      const res = await provider.handleIntrospect(new Request('https://id.org.ai/oauth/introspect', {
        method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({}),
      }))
      expect((await res.json() as Record<string, unknown>).active).toBe(false)
    })

    it('active=false for non-prefixed token', async () => {
      expect((await (await introspect('random_garbage')).json() as Record<string, unknown>).active).toBe(false)
    })

    it('rejects GET method', async () => {
      expect((await provider.handleIntrospect(new Request('https://id.org.ai/oauth/introspect', { method: 'GET' }))).status).toBe(405)
    })
  })

  // ══════════════════════════════════════════════════════════════════════════
  // 9. Token Revocation
  // ══════════════════════════════════════════════════════════════════════════

  describe('Token Revocation', () => {
    let clientId: string
    const redir = 'https://app.example.com/callback'
    const verifier = 'revocation-verifier-long-enough'

    beforeEach(async () => {
      clientId = (await registerClient(provider)).client_id as string
      const s = await storage.get<Record<string, unknown>>(`client:${clientId}`)
      await storage.put(`client:${clientId}`, { ...s, trusted: true })
    })

    function revoke(token: string): Promise<Response> {
      return provider.handleRevoke(new Request('https://id.org.ai/oauth/revoke', {
        method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token }),
      }))
    }

    it('revokes an access token', async () => {
      const t = await getAuthCodeTokens(provider, clientId, redir, 'user-1', verifier)
      const at = t.access_token as string
      expect((await revoke(at)).status).toBe(200)
      expect(await storage.get(`access:${at}`)).toBeUndefined()
    })

    it('revokes a refresh token and its family', async () => {
      const t = await getAuthCodeTokens(provider, clientId, redir, 'user-1', verifier)
      const rt = t.refresh_token as string

      const t2 = await (await provider.handleToken(makeTokenRequest({
        grant_type: 'refresh_token', refresh_token: rt, client_id: clientId,
      }))).json() as Record<string, unknown>
      const rt2 = t2.refresh_token as string

      expect((await revoke(rt2)).status).toBe(200)
      expect((await storage.get<Record<string, unknown>>(`refresh:${rt2}`))!.revoked).toBe(true)
    })

    it('returns 200 for missing token (RFC 7009)', async () => {
      const res = await provider.handleRevoke(new Request('https://id.org.ai/oauth/revoke', {
        method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({}),
      }))
      expect(res.status).toBe(200)
    })

    it('returns 200 for non-existent token', async () => {
      expect((await revoke('at_doesnotexist')).status).toBe(200)
    })

    it('rejects GET method', async () => {
      expect((await provider.handleRevoke(new Request('https://id.org.ai/oauth/revoke', { method: 'GET' }))).status).toBe(405)
    })

    it('revoked token fails introspection', async () => {
      const t = await getAuthCodeTokens(provider, clientId, redir, 'user-1', verifier)
      const at = t.access_token as string
      await revoke(at)
      const res = await provider.handleIntrospect(new Request('https://id.org.ai/oauth/introspect', {
        method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token: at }),
      }))
      expect((await res.json() as Record<string, unknown>).active).toBe(false)
    })
  })

  // ══════════════════════════════════════════════════════════════════════════
  // 10. UserInfo
  // ══════════════════════════════════════════════════════════════════════════

  describe('UserInfo', () => {
    let clientId: string
    const redir = 'https://app.example.com/callback'
    const verifier = 'userinfo-verifier-long-enough-value'

    beforeEach(async () => {
      clientId = (await registerClient(provider)).client_id as string
      const s = await storage.get<Record<string, unknown>>(`client:${clientId}`)
      await storage.put(`client:${clientId}`, { ...s, trusted: true })
    })

    function userinfo(token: string): Promise<Response> {
      return provider.handleUserinfo(new Request('https://id.org.ai/oauth/userinfo', {
        headers: { Authorization: `Bearer ${token}` },
      }))
    }

    it('returns full claims for valid token', async () => {
      const t = await getAuthCodeTokens(provider, clientId, redir, 'user-1', verifier)
      const res = await userinfo(t.access_token as string)
      expect(res.status).toBe(200)
      const d = await res.json() as Record<string, unknown>
      expect(d.sub).toBe('user-1')
      expect(d.name).toBe('Alice Test')
      expect(d.preferred_username).toBe('alice')
      expect(d.picture).toBe('https://example.com/alice.png')
      expect(d.email).toBe('alice@example.com')
      expect(d.email_verified).toBe(true)
    })

    it('401 for missing Authorization header', async () => {
      const res = await provider.handleUserinfo(new Request('https://id.org.ai/oauth/userinfo'))
      expect(res.status).toBe(401)
      expect(res.headers.get('WWW-Authenticate')).toBe('Bearer')
    })

    it('401 for non-Bearer auth', async () => {
      const res = await provider.handleUserinfo(new Request('https://id.org.ai/oauth/userinfo', {
        headers: { Authorization: 'Basic dXNlcjpwYXNz' },
      }))
      expect(res.status).toBe(401)
    })

    it('401 for unknown token', async () => {
      expect((await userinfo('at_nonexistent')).status).toBe(401)
    })

    it('401 for expired token', async () => {
      const t = await getAuthCodeTokens(provider, clientId, redir, 'user-1', verifier)
      const at = t.access_token as string
      const td = await storage.get<Record<string, unknown>>(`access:${at}`)
      await storage.put(`access:${at}`, { ...td, expiresAt: Date.now() - 1000 })
      const res = await userinfo(at)
      expect(res.status).toBe(401)
      expect((await res.json() as Record<string, unknown>).error_description).toContain('expired')
    })

    it('only sub when no profile/email scope', async () => {
      const t = await getAuthCodeTokens(provider, clientId, redir, 'user-1', verifier)
      const at = t.access_token as string
      const td = await storage.get<Record<string, unknown>>(`access:${at}`)
      await storage.put(`access:${at}`, { ...td, scopes: ['openid'] })
      const d = await (await userinfo(at)).json() as Record<string, unknown>
      expect(d.sub).toBe('user-1')
      expect(d.name).toBeUndefined()
      expect(d.email).toBeUndefined()
    })

    it('profile claims when profile scope present', async () => {
      const t = await getAuthCodeTokens(provider, clientId, redir, 'user-1', verifier)
      const at = t.access_token as string
      const td = await storage.get<Record<string, unknown>>(`access:${at}`)
      await storage.put(`access:${at}`, { ...td, scopes: ['openid', 'profile'] })
      const d = await (await userinfo(at)).json() as Record<string, unknown>
      expect(d.name).toBe('Alice Test')
      expect(d.preferred_username).toBe('alice')
      expect(d.email).toBeUndefined()
    })

    it('email claims when email scope present', async () => {
      const t = await getAuthCodeTokens(provider, clientId, redir, 'user-1', verifier)
      const at = t.access_token as string
      const td = await storage.get<Record<string, unknown>>(`access:${at}`)
      await storage.put(`access:${at}`, { ...td, scopes: ['openid', 'email'] })
      const d = await (await userinfo(at)).json() as Record<string, unknown>
      expect(d.email).toBe('alice@example.com')
      expect(d.email_verified).toBe(true)
      expect(d.name).toBeUndefined()
    })

    it('401 for token without identityId', async () => {
      await storage.put('access:at_no_id', {
        id: 'at_no_id', clientId, scopes: ['openid'], expiresAt: Date.now() + 3600000, createdAt: Date.now(),
      })
      expect((await userinfo('at_no_id')).status).toBe(401)
    })

    it('401 when identity lookup fails', async () => {
      const t = await getAuthCodeTokens(provider, clientId, redir, 'user-1', verifier)
      const at = t.access_token as string
      const td = await storage.get<Record<string, unknown>>(`access:${at}`)
      await storage.put(`access:${at}`, { ...td, identityId: 'user-nonexistent' })
      expect((await userinfo(at)).status).toBe(401)
    })
  })

  // ══════════════════════════════════════════════════════════════════════════
  // 11. validateAccessToken
  // ══════════════════════════════════════════════════════════════════════════

  describe('validateAccessToken', () => {
    let clientId: string
    const redir = 'https://app.example.com/callback'
    const verifier = 'validate-verifier-long-enough-value'

    beforeEach(async () => {
      clientId = (await registerClient(provider)).client_id as string
      const s = await storage.get<Record<string, unknown>>(`client:${clientId}`)
      await storage.put(`client:${clientId}`, { ...s, trusted: true })
    })

    it('returns data for valid token', async () => {
      const t = await getAuthCodeTokens(provider, clientId, redir, 'user-1', verifier)
      const r = await provider.validateAccessToken(t.access_token as string)
      expect(r).not.toBeNull()
      expect(r!.clientId).toBe(clientId)
      expect(r!.identityId).toBe('user-1')
    })

    it('returns null for expired token', async () => {
      const t = await getAuthCodeTokens(provider, clientId, redir, 'user-1', verifier)
      const at = t.access_token as string
      const td = await storage.get<Record<string, unknown>>(`access:${at}`)
      await storage.put(`access:${at}`, { ...td, expiresAt: Date.now() - 1000 })
      expect(await provider.validateAccessToken(at)).toBeNull()
    })

    it('returns null for non-existent token', async () => {
      expect(await provider.validateAccessToken('at_doesnotexist')).toBeNull()
    })

    it('returns null for non-at_ prefix', async () => {
      expect(await provider.validateAccessToken('rt_some_token')).toBeNull()
    })
  })

  // ══════════════════════════════════════════════════════════════════════════
  // 12. PKCE S256 Computation
  // ══════════════════════════════════════════════════════════════════════════

  describe('PKCE S256 Computation', () => {
    it('matches RFC 7636 Appendix B example', async () => {
      const challenge = await computeS256Challenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')
      expect(challenge).toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM')
    })

    it('produces URL-safe base64', async () => {
      const challenge = await computeS256Challenge('test-verifier-for-base64-safety')
      expect(challenge).not.toContain('+')
      expect(challenge).not.toContain('/')
      expect(challenge).not.toContain('=')
    })

    it('different verifiers produce different challenges', async () => {
      const c1 = await computeS256Challenge('verifier-one')
      const c2 = await computeS256Challenge('verifier-two')
      expect(c1).not.toBe(c2)
    })

    it('same verifier is deterministic', async () => {
      const c1 = await computeS256Challenge('deterministic')
      const c2 = await computeS256Challenge('deterministic')
      expect(c1).toBe(c2)
    })
  })

  // ══════════════════════════════════════════════════════════════════════════
  // 13. End-to-End Integration
  // ══════════════════════════════════════════════════════════════════════════

  describe('End-to-End Integration', () => {
    it('register -> authorize -> token -> userinfo -> refresh -> revoke', async () => {
      const cid = (await registerClient(provider)).client_id as string
      const s = await storage.get<Record<string, unknown>>(`client:${cid}`)
      await storage.put(`client:${cid}`, { ...s, trusted: true })

      const redir = 'https://app.example.com/callback'
      const v = 'e2e-integration-test-code-verifier'

      const t1 = await getAuthCodeTokens(provider, cid, redir, 'user-1', v)
      expect(t1.access_token).toBeDefined()

      // UserInfo
      const ui = await (await provider.handleUserinfo(new Request('https://id.org.ai/oauth/userinfo', {
        headers: { Authorization: `Bearer ${t1.access_token}` },
      }))).json() as Record<string, unknown>
      expect(ui.sub).toBe('user-1')
      expect(ui.name).toBe('Alice Test')

      // Introspect
      const ir = await (await provider.handleIntrospect(new Request('https://id.org.ai/oauth/introspect', {
        method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token: t1.access_token as string }),
      }))).json() as Record<string, unknown>
      expect(ir.active).toBe(true)

      // Refresh
      const t2 = await (await provider.handleToken(makeTokenRequest({
        grant_type: 'refresh_token', refresh_token: t1.refresh_token as string, client_id: cid,
      }))).json() as Record<string, unknown>
      expect(t2.access_token).not.toBe(t1.access_token)

      // Revoke
      expect((await provider.handleRevoke(new Request('https://id.org.ai/oauth/revoke', {
        method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token: t2.access_token as string }),
      }))).status).toBe(200)

      // Verify revoked
      expect(await provider.validateAccessToken(t2.access_token as string)).toBeNull()
    })

    it('device flow: register -> device auth -> approve -> tokens -> userinfo', async () => {
      const cid = (await registerClient(provider, {
        client_name: 'E2E Agent', grant_types: ['urn:ietf:params:oauth:grant-type:device_code'], redirect_uris: [],
      })).client_id as string

      const init = await (await provider.handleDeviceAuthorization(new Request('https://id.org.ai/oauth/device', {
        method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ client_id: cid }),
      }))).json() as Record<string, unknown>

      // Pending
      const p = await (await provider.handleToken(makeTokenRequest({
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code', device_code: init.device_code as string, client_id: cid,
      }))).json() as Record<string, unknown>
      expect(p.error).toBe('authorization_pending')

      // Approve
      await provider.handleDeviceVerification(new Request('https://id.org.ai/device', {
        method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ user_code: init.user_code as string, approved: 'true' }),
      }), 'user-2')

      // Tokens
      const t = await (await provider.handleToken(makeTokenRequest({
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code', device_code: init.device_code as string, client_id: cid,
      }))).json() as Record<string, unknown>
      expect(t.access_token).toBeDefined()

      // UserInfo
      const ui = await (await provider.handleUserinfo(new Request('https://id.org.ai/oauth/userinfo', {
        headers: { Authorization: `Bearer ${t.access_token}` },
      }))).json() as Record<string, unknown>
      expect(ui.sub).toBe('user-2')
      expect(ui.name).toBe('Bob Agent')
    })

    it('client_credentials: register -> token -> introspect', async () => {
      const d = await registerConfidentialClient(provider, { grant_types: ['client_credentials'], redirect_uris: [] })
      const cid = d.client_id as string
      const cs = d.client_secret as string

      const t = await (await provider.handleToken(makeTokenRequest({
        grant_type: 'client_credentials', client_id: cid, client_secret: cs, scope: 'openid',
      }))).json() as Record<string, unknown>
      expect(t.access_token).toBeDefined()

      const ir = await (await provider.handleIntrospect(new Request('https://id.org.ai/oauth/introspect', {
        method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token: t.access_token as string }),
      }))).json() as Record<string, unknown>
      expect(ir.active).toBe(true)
      expect(ir.client_id).toBe(cid)
      expect(ir.sub).toBeUndefined()
    })
  })
})
