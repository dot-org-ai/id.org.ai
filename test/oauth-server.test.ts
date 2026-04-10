import { describe, it, expect } from 'vitest'
import { createOAuth21Server } from '../src/oauth/server'
import { MemoryOAuthStorage } from '../src/oauth/storage'
import { generateCodeVerifier, generateCodeChallenge } from '../src/oauth/pkce'

describe('createOAuth21Server', () => {
  it('creates a Hono app with discovery endpoint', async () => {
    const server = createOAuth21Server({
      issuer: 'https://test.example.com',
      storage: new MemoryOAuthStorage(),
      devMode: { enabled: true },
    })
    const res = await server.request('/.well-known/oauth-authorization-server')
    expect(res.status).toBe(200)
    const metadata = await res.json()
    expect(metadata.issuer).toBe('https://test.example.com')
    expect(metadata.authorization_endpoint).toContain('/authorize')
    expect(metadata.token_endpoint).toContain('/token')
  })

  it('serves JWKS endpoint when JWT access tokens enabled', async () => {
    const server = createOAuth21Server({
      issuer: 'https://test.example.com',
      storage: new MemoryOAuthStorage(),
      devMode: { enabled: true },
      useJwtAccessTokens: true,
    })
    const res = await server.request('/.well-known/jwks.json')
    expect(res.status).toBe(200)
    const jwks = await res.json()
    expect(jwks.keys).toBeDefined()
  })

  it('returns error for unsupported grant type on /token', async () => {
    const server = createOAuth21Server({
      issuer: 'https://test.example.com',
      storage: new MemoryOAuthStorage(),
      devMode: { enabled: true },
    })
    const res = await server.request('/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'grant_type=invalid_grant',
    })
    expect(res.status).toBe(400)
    const body = await res.json()
    expect(body.error).toBe('unsupported_grant_type')
  })

  it('serves protected resource metadata', async () => {
    const server = createOAuth21Server({
      issuer: 'https://test.example.com',
      storage: new MemoryOAuthStorage(),
      devMode: { enabled: true },
    })
    const res = await server.request('/.well-known/oauth-protected-resource')
    expect(res.status).toBe(200)
    const metadata = await res.json()
    expect(metadata.resource).toBe('https://test.example.com')
    expect(metadata.authorization_servers).toContain('https://test.example.com')
  })

  it('requires either upstream or devMode config', () => {
    expect(() => {
      createOAuth21Server({
        issuer: 'https://test.example.com',
        storage: new MemoryOAuthStorage(),
      })
    }).toThrow('Either upstream configuration or devMode must be provided')
  })

  it('exposes test helpers in devMode', () => {
    const server = createOAuth21Server({
      issuer: 'https://test.example.com',
      storage: new MemoryOAuthStorage(),
      devMode: { enabled: true },
    })
    expect(server.testHelpers).toBeDefined()
    expect(server.testHelpers!.createUser).toBeTypeOf('function')
    expect(server.testHelpers!.getAccessToken).toBeTypeOf('function')
  })

  it('returns empty JWKS when signing keys not configured', async () => {
    const server = createOAuth21Server({
      issuer: 'https://test.example.com',
      storage: new MemoryOAuthStorage(),
      devMode: { enabled: true },
      useJwtAccessTokens: false,
    })
    const res = await server.request('/.well-known/jwks.json')
    expect(res.status).toBe(200)
    const jwks = await res.json()
    expect(jwks.keys).toEqual([])
  })
})

// ============================================================================
// RFC 8707 Resource Indicator Tests
// ============================================================================

describe('RFC 8707 resource parameter', () => {
  /** Helper: create a JWT-enabled server with a dev user and registered client */
  async function setupServer() {
    const storage = new MemoryOAuthStorage()
    const server = createOAuth21Server({
      issuer: 'https://id.example.com',
      storage,
      devMode: {
        enabled: true,
        users: [{ id: 'user_1', email: 'test@example.com', password: 'pass', name: 'Test User' }],
        allowAnyCredentials: true,
      },
      useJwtAccessTokens: true,
      skipConsent: true,
    })

    // Register a client
    const regRes = await server.request('/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_name: 'Test Client',
        redirect_uris: ['https://client.example.com/callback'],
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        token_endpoint_auth_method: 'none',
      }),
    })
    expect(regRes.status).toBe(201)
    const clientData = await regRes.json() as { client_id: string }

    return { server, storage, clientId: clientData.client_id }
  }

  /** Helper: run full authorize → login → token exchange flow */
  async function doAuthFlow(
    server: ReturnType<typeof createOAuth21Server>,
    clientId: string,
    opts: { resource?: string } = {},
  ) {
    const codeVerifier = generateCodeVerifier()
    const codeChallenge = await generateCodeChallenge(codeVerifier)

    // Step 1: GET /authorize — returns login form in dev mode
    const authorizeParams = new URLSearchParams({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: 'https://client.example.com/callback',
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      scope: 'openid profile email',
      state: 'test_state',
    })
    if (opts.resource) {
      authorizeParams.set('resource', opts.resource)
    }

    const authRes = await server.request(`/authorize?${authorizeParams.toString()}`)
    expect(authRes.status).toBe(200) // dev mode returns login form

    // Step 2: POST /login — dev mode login
    const loginBody = new URLSearchParams({
      email: 'test@example.com',
      password: 'pass',
      client_id: clientId,
      redirect_uri: 'https://client.example.com/callback',
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      scope: 'openid profile email',
      state: 'test_state',
    })
    if (opts.resource) {
      loginBody.set('resource', opts.resource)
    }

    const loginRes = await server.request('/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: loginBody.toString(),
      redirect: 'manual',
    })

    // Should redirect with code
    expect(loginRes.status).toBe(302)
    const location = loginRes.headers.get('location')!
    expect(location).toBeTruthy()
    const redirectUrl = new URL(location)
    const authCode = redirectUrl.searchParams.get('code')!
    expect(authCode).toBeTruthy()

    // Step 3: POST /token — exchange code for tokens
    const tokenRes = await server.request('/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: authCode,
        redirect_uri: 'https://client.example.com/callback',
        client_id: clientId,
        code_verifier: codeVerifier,
      }).toString(),
    })

    expect(tokenRes.status).toBe(200)
    const tokenData = await tokenRes.json() as { access_token: string; token_type: string; expires_in: number; refresh_token?: string }
    expect(tokenData.access_token).toBeTruthy()
    expect(tokenData.token_type).toBe('Bearer')

    return tokenData
  }

  /** Decode a JWT payload without verification (for test assertions) */
  function decodeJwtPayload(jwt: string): Record<string, unknown> {
    const parts = jwt.split('.')
    expect(parts.length).toBe(3)
    // Base64url decode
    const payload = parts[1]!.replace(/-/g, '+').replace(/_/g, '/')
    const padded = payload + '='.repeat((4 - (payload.length % 4)) % 4)
    return JSON.parse(atob(padded))
  }

  it('sets aud to resource when resource param is provided', async () => {
    const { server, clientId } = await setupServer()
    const tokenData = await doAuthFlow(server, clientId, { resource: 'https://mcp.auto.dev' })

    // Access token should be a JWT (3 dot-separated parts)
    expect(tokenData.access_token.split('.').length).toBe(3)

    const payload = decodeJwtPayload(tokenData.access_token)
    expect(payload.aud).toBe('https://mcp.auto.dev')
    expect(payload.sub).toBeTruthy()
    expect(payload.client_id).toBe(clientId)
  })

  it('sets aud to client_id when resource param is omitted (backwards compatible)', async () => {
    const { server, clientId } = await setupServer()
    const tokenData = await doAuthFlow(server, clientId)

    // Access token should be a JWT
    expect(tokenData.access_token.split('.').length).toBe(3)

    const payload = decodeJwtPayload(tokenData.access_token)
    // When no resource is provided, audience defaults to client_id
    expect(payload.aud).toBe(clientId)
    expect(payload.sub).toBeTruthy()
  })

  it('preserves resource through the full authorize → code → token pipeline', async () => {
    const { server, clientId } = await setupServer()
    const resource = 'https://api.example.com/v1'
    const tokenData = await doAuthFlow(server, clientId, { resource })

    const payload = decodeJwtPayload(tokenData.access_token)
    expect(payload.aud).toBe(resource)
    // Verify other standard claims are still present
    expect(payload.iss).toBe('https://id.example.com')
    expect(payload.scope).toBe('openid profile email')
  })
})
