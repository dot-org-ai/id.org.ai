import { describe, it, expect } from 'vitest'
import { createOAuth21Server } from '../src/oauth/server'
import { MemoryOAuthStorage } from '../src/oauth/storage'

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
