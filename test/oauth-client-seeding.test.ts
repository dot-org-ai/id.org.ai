/**
 * OAuth Client Seeding Tests
 *
 * Verifies that ensureCliClient() lazily seeds the id_org_ai_cli
 * OAuth client in IdentityDO storage, and is idempotent.
 */

import { describe, it, expect, beforeEach } from 'vitest'
import { OAuthProvider } from '../src/sdk/oauth/provider'
import type { OAuthConfig } from '../src/sdk/oauth/provider'

// ============================================================================
// Helpers (same pattern as oauth-provider.test.ts)
// ============================================================================

type StorageLike = {
  get<T = unknown>(key: string): Promise<T | undefined>
  put(key: string, value: unknown, options?: { expirationTtl?: number }): Promise<void>
  delete(key: string): Promise<boolean>
  list<T = unknown>(options?: { prefix?: string; limit?: number }): Promise<Map<string, T>>
}

function createMockStorage(): StorageLike & { _store: Map<string, unknown> } {
  const store = new Map<string, unknown>()
  return {
    _store: store,
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

/**
 * Simulates ensureCliClient() using the same storage mock.
 * This mirrors the logic in IdentityDO.ensureCliClient().
 */
async function ensureCliClient(storage: StorageLike): Promise<void> {
  const existing = await storage.get('client:id_org_ai_cli')
  if (existing) return

  await storage.put('client:id_org_ai_cli', {
    id: 'id_org_ai_cli',
    name: 'id.org.ai CLI',
    redirectUris: [],
    grantTypes: ['urn:ietf:params:oauth:grant-type:device_code'],
    responseTypes: [],
    scopes: ['openid', 'profile', 'email', 'offline_access'],
    trusted: true,
    tokenEndpointAuthMethod: 'none',
    createdAt: Date.now(),
  })
}

// ============================================================================
// Tests
// ============================================================================

describe('ensureCliClient', () => {
  let storage: ReturnType<typeof createMockStorage>

  beforeEach(() => {
    storage = createMockStorage()
  })

  it('creates the id_org_ai_cli client with correct properties', async () => {
    await ensureCliClient(storage)

    const client = await storage.get<Record<string, unknown>>('client:id_org_ai_cli')
    expect(client).toBeDefined()
    expect(client!.id).toBe('id_org_ai_cli')
    expect(client!.name).toBe('id.org.ai CLI')
    expect(client!.redirectUris).toEqual([])
    expect(client!.grantTypes).toEqual(['urn:ietf:params:oauth:grant-type:device_code'])
    expect(client!.responseTypes).toEqual([])
    expect(client!.scopes).toEqual(['openid', 'profile', 'email', 'offline_access'])
    expect(client!.trusted).toBe(true)
    expect(client!.tokenEndpointAuthMethod).toBe('none')
    expect(typeof client!.createdAt).toBe('number')
  })

  it('is idempotent — calling twice does not overwrite', async () => {
    await ensureCliClient(storage)
    const first = await storage.get<Record<string, unknown>>('client:id_org_ai_cli')
    const firstCreatedAt = first!.createdAt

    // Small delay to ensure Date.now() would differ
    await new Promise((r) => setTimeout(r, 5))

    await ensureCliClient(storage)
    const second = await storage.get<Record<string, unknown>>('client:id_org_ai_cli')
    expect(second!.createdAt).toBe(firstCreatedAt)
  })

  it('seeded client works with OAuthProvider device flow', async () => {
    await ensureCliClient(storage)

    const provider = new OAuthProvider({
      storage,
      config: {
        issuer: 'https://id.org.ai',
        authorizationEndpoint: 'https://id.org.ai/oauth/authorize',
        tokenEndpoint: 'https://id.org.ai/oauth/token',
        userinfoEndpoint: 'https://id.org.ai/oauth/userinfo',
        registrationEndpoint: 'https://id.org.ai/oauth/register',
        deviceAuthorizationEndpoint: 'https://id.org.ai/oauth/device',
        revocationEndpoint: 'https://id.org.ai/oauth/revoke',
        introspectionEndpoint: 'https://id.org.ai/oauth/introspect',
        jwksUri: 'https://id.org.ai/.well-known/jwks.json',
      } satisfies OAuthConfig,
      getIdentity: async () => null,
    })

    const req = new Request('https://id.org.ai/oauth/device', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: 'id_org_ai_cli' }),
    })

    const res = await provider.handleDeviceAuthorization(req)
    expect(res.status).toBe(200)
    const data = await res.json() as Record<string, unknown>
    expect(data.device_code).toBeDefined()
    expect(data.user_code).toBeDefined()
    expect(data.verification_uri).toBe('https://id.org.ai/device')
  })
})
