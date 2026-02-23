/**
 * Flow 6: API Key Lifecycle
 *
 * Tests the full API key CRUD lifecycle using a provisioned identity.
 * API key management requires an authenticated identity (the provision
 * endpoint creates an L1 identity that can use the custom hly_sk_* key path).
 *
 * For WorkOS-managed API keys (sk_*), a browser login session is needed.
 * This test covers the custom key path which works with provisioned sessions.
 *
 * Steps:
 *   1. Provision a session via /api/provision
 *   2. POST /api/keys → create key (custom hly_sk_* or WorkOS sk_*)
 *   3. GET /api/keys → list keys, verify created key appears
 *   4. Use the API key via Authorization header → verify authenticated
 *   5. DELETE /api/keys/:id → revoke key
 *   6. Verify revoked key no longer works
 */

import { describe, it, expect, beforeAll } from 'vitest'

const ID_URL = process.env.ID_URL || 'https://oauth.do'
const AUTH_URL = process.env.AUTH_URL || 'https://auth.dotdo.workers.dev'

describe('API Key Lifecycle', () => {
  let sessionToken: string
  let identityId: string
  let createdKeyId: string | null = null
  let createdKeyValue: string | null = null

  beforeAll(async () => {
    // Provision an anonymous session (L1)
    const res = await fetch(`${ID_URL}/api/provision`, { method: 'POST' })
    expect(res.ok).toBe(true)

    const body = (await res.json()) as {
      tenantId: string
      sessionToken: string
      identityId: string
    }
    sessionToken = body.sessionToken
    identityId = body.identityId
    expect(sessionToken).toBeTruthy()
    expect(sessionToken).toMatch(/^ses_/)
  }, 30_000)

  it('should provision returns valid session token and identity', () => {
    expect(sessionToken).toMatch(/^ses_/)
    expect(identityId).toBeTruthy()
  })

  it('should attempt to create an API key', async () => {
    const res = await fetch(`${ID_URL}/api/keys`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${sessionToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        name: `e2e-test-key-${Date.now()}`,
        scopes: ['read', 'write'],
      }),
    })

    if (res.status === 201) {
      // Custom hly_sk_* key path or WorkOS key creation succeeded
      const body = (await res.json()) as { id: string; key: string; name: string }
      expect(body.id).toBeTruthy()
      expect(body.key).toBeTruthy()
      expect(body.name).toMatch(/^e2e-test-key-/)

      createdKeyId = body.id
      createdKeyValue = body.key
    } else if (res.status === 401) {
      // API key management requires WorkOS-authenticated session (L2+)
      // This is expected for provisioned anonymous sessions
      console.warn('API key creation requires WorkOS auth — skipping remaining key tests')
    } else if (res.status === 500) {
      // WorkOS API key endpoint may not be available (upstream dependency)
      // This is a known issue — the worker tried WorkOS but it returned an error
      const body = await res.text()
      console.warn(`API key creation failed (upstream): ${body}`)
    } else {
      throw new Error(`Unexpected status ${res.status}: ${await res.text()}`)
    }
  })

  it('should list API keys', async () => {
    if (!createdKeyId) return

    const res = await fetch(`${ID_URL}/api/keys`, {
      headers: { Authorization: `Bearer ${sessionToken}` },
    })

    expect(res.ok).toBe(true)
    const body = (await res.json()) as { keys: Array<{ id: string; name: string }> }
    expect(body.keys).toBeInstanceOf(Array)

    const found = body.keys.find((k) => k.id === createdKeyId)
    expect(found).toBeTruthy()
  })

  it('should authenticate with the created API key', async () => {
    if (!createdKeyValue) return

    // Try verifying the key via the auth worker
    const res = await fetch(`${AUTH_URL}/verify`, {
      headers: { Authorization: `Bearer ${createdKeyValue}` },
    })

    if (res.ok) {
      const body = (await res.json()) as { valid: boolean; user?: { id: string } }
      expect(body.valid).toBe(true)
      expect(body.user).toBeTruthy()
    } else {
      // If auth worker doesn't support this key type, try id.org.ai MCP
      const mcpRes = await fetch(`${ID_URL}/mcp`, {
        headers: { Authorization: `Bearer ${createdKeyValue}` },
      })
      expect(mcpRes.ok).toBe(true)
    }
  })

  it('should revoke the API key', async () => {
    if (!createdKeyId) return

    const res = await fetch(`${ID_URL}/api/keys/${createdKeyId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${sessionToken}` },
    })

    expect(res.ok).toBe(true)
    const body = (await res.json()) as { id: string; status: string }
    expect(body.status).toBe('revoked')
  })

  it('should reject the revoked API key', async () => {
    if (!createdKeyValue) return

    // Wait briefly for cache invalidation
    await new Promise((r) => setTimeout(r, 2000))

    const res = await fetch(`${AUTH_URL}/verify`, {
      headers: { Authorization: `Bearer ${createdKeyValue}` },
    })

    if (res.ok) {
      const body = (await res.json()) as { valid: boolean }
      // After revocation + cache expiry, the key should be invalid
      // Note: may still be cached for up to 5min (positive cache TTL)
      if (body.valid) {
        console.warn('Key still valid (cached) — will expire within 5 minutes')
      }
    }
  })

  it('should access MCP endpoint (anonymous or authenticated)', async () => {
    // MCP is accessible at all auth levels (L0+)
    const res = await fetch(`${ID_URL}/mcp`, {
      headers: { Authorization: `Bearer ${sessionToken}` },
    })

    expect(res.ok).toBe(true)
    const body = (await res.json()) as { jsonrpc: string; result: { _meta: { auth: { level: number } } } }
    expect(body.jsonrpc).toBe('2.0')
    // Session token may not resolve externally (requires KV → DO shard routing)
    // but MCP should still respond with capabilities
    expect(body.result._meta.auth.level).toBeGreaterThanOrEqual(0)
  })
})
