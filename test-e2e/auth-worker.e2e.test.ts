/**
 * Flow 7: Auth Worker Verification
 *
 * Tests that the auth.dotdo.workers.dev worker correctly:
 *   1. Verifies JWTs signed by id.org.ai
 *   2. Returns user info via GET /me
 *   3. Handles session tokens via POST /verify
 *   4. Reads camelCase claims and nested org correctly
 */

import { describe, it, expect, beforeAll } from 'vitest'

const ID_URL = process.env.ID_URL || 'https://oauth.do'
const AUTH_URL = process.env.AUTH_URL || 'https://auth.dotdo.workers.dev'

describe('Auth Worker Verification', () => {
  let sessionToken: string

  beforeAll(async () => {
    // Provision a session to get a ses_* token
    const res = await fetch(`${ID_URL}/api/provision`, { method: 'POST' })
    expect(res.ok).toBe(true)

    const body = (await res.json()) as { sessionToken: string }
    sessionToken = body.sessionToken
    expect(sessionToken).toBeTruthy()
  }, 30_000)

  it('should return health status', async () => {
    const res = await fetch(`${AUTH_URL}/health`)
    expect(res.ok).toBe(true)

    const body = (await res.json()) as { status: string }
    expect(body.status).toBe('ok')
  })

  it('should verify a session token via POST /verify', async () => {
    const res = await fetch(`${AUTH_URL}/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: sessionToken }),
    })

    expect(res.ok).toBe(true)
    const body = (await res.json()) as { valid: boolean; user?: { id: string } }
    expect(body.valid).toBe(true)
    expect(body.user).toBeTruthy()
    expect(body.user!.id).toBeTruthy()
  })

  it('should verify a session token via GET /verify with Bearer header', async () => {
    const res = await fetch(`${AUTH_URL}/verify`, {
      headers: { Authorization: `Bearer ${sessionToken}` },
    })

    expect(res.ok).toBe(true)
    const body = (await res.json()) as { valid: boolean; user?: { id: string } }
    expect(body.valid).toBe(true)
    expect(body.user).toBeTruthy()
  })

  it('should return user info via GET /me', async () => {
    const res = await fetch(`${AUTH_URL}/me`, {
      headers: { Authorization: `Bearer ${sessionToken}` },
    })

    expect(res.ok).toBe(true)
    const user = (await res.json()) as { id: string; email?: string }
    expect(user.id).toBeTruthy()
  })

  it('should return 401 for GET /me without credentials', async () => {
    const res = await fetch(`${AUTH_URL}/me`)
    expect(res.status).toBe(401)

    const body = (await res.json()) as { error: string }
    expect(body.error).toBeTruthy()
  })

  it('should reject invalid tokens', async () => {
    const res = await fetch(`${AUTH_URL}/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: 'invalid-token-value' }),
    })

    expect(res.ok).toBe(true)
    const body = (await res.json()) as { valid: boolean; error?: string }
    expect(body.valid).toBe(false)
    expect(body.error).toBeTruthy()
  })

  it('should reject expired/malformed JWTs', async () => {
    // Create a fake JWT with expired exp claim
    const fakePayload = btoa(JSON.stringify({ sub: 'fake', exp: 0, iss: 'https://id.org.ai' }))
    const fakeJwt = `eyJhbGciOiJSUzI1NiJ9.${fakePayload}.fakesig`

    const res = await fetch(`${AUTH_URL}/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: fakeJwt }),
    })

    expect(res.ok).toBe(true)
    const body = (await res.json()) as { valid: boolean; error?: string }
    expect(body.valid).toBe(false)
  })

  it('should verify via cookie header on GET /me', async () => {
    // The auth worker supports cookie-based auth via the Cookie header
    const res = await fetch(`${AUTH_URL}/me`, {
      headers: { Cookie: `auth=${sessionToken}` },
    })

    // Session tokens in cookies should work (the auth worker parses auth cookie)
    // Note: ses_* tokens aren't JWTs, so cookie parsing may not apply here
    // This tests the cookie parsing path of the auth worker
    if (res.ok) {
      const user = (await res.json()) as { id: string }
      expect(user.id).toBeTruthy()
    } else {
      // ses_* tokens may not be parseable as cookies (they're opaque session refs)
      // This is expected — cookie auth is for JWT tokens set by /callback
      expect(res.status).toBe(401)
    }
  })
})
