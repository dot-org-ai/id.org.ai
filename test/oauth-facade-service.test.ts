// test/oauth-facade-service.test.ts
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { OAuthServiceImpl } from '../src/services/oauth/service'
import type { StorageAdapter } from '../src/storage'

// ── Test Storage Helper ────────────────────────────────────────────────

function createTestStorage() {
  const store = new Map<string, unknown>()

  const storage: StorageAdapter = {
    async get<T = unknown>(key: string): Promise<T | undefined> {
      return store.get(key) as T | undefined
    },
    async put(key: string, value: unknown): Promise<void> {
      store.set(key, value)
    },
    async delete(key: string): Promise<boolean> {
      return store.delete(key)
    },
    async list<T = unknown>(options?: { prefix?: string; limit?: number; start?: string; reverse?: boolean }): Promise<Map<string, T>> {
      const entries = new Map<string, T>()
      for (const [k, v] of store) {
        if (!options?.prefix || k.startsWith(options.prefix)) {
          entries.set(k, v as T)
        }
      }
      return entries
    },
  }

  return { storage, store }
}

// ── Test Config ─────────────────────────────────────────────────────────

const TEST_CONFIG = {
  issuer: 'https://test.example.com',
  authorizationEndpoint: 'https://test.example.com/oauth/authorize',
  tokenEndpoint: 'https://test.example.com/oauth/token',
  userinfoEndpoint: 'https://test.example.com/oauth/userinfo',
  registrationEndpoint: 'https://test.example.com/oauth/register',
  deviceAuthorizationEndpoint: 'https://test.example.com/oauth/device',
  revocationEndpoint: 'https://test.example.com/oauth/revoke',
  introspectionEndpoint: 'https://test.example.com/oauth/introspect',
  jwksUri: 'https://test.example.com/.well-known/jwks.json',
}

// ============================================================================
// Tests
// ============================================================================

describe('OAuthServiceImpl', () => {
  let storage: StorageAdapter
  let store: Map<string, unknown>
  let service: OAuthServiceImpl

  beforeEach(() => {
    const mock = createTestStorage()
    storage = mock.storage
    store = mock.store
    service = new OAuthServiceImpl({ storage, config: TEST_CONFIG })
  })

  // ── ensureDefaultClients() ─────────────────────────────────────────────

  describe('ensureDefaultClients()', () => {
    it('seeds CLI client', async () => {
      await service.ensureDefaultClients()
      const client = store.get('client:id_org_ai_cli')
      expect(client).toBeDefined()
      expect((client as any).name).toBe('id.org.ai CLI')
      expect((client as any).grantTypes).toContain('urn:ietf:params:oauth:grant-type:device_code')
    })

    it('seeds oauth.do CLI client', async () => {
      await service.ensureDefaultClients()
      const client = store.get('client:oauth_do_cli')
      expect(client).toBeDefined()
      expect((client as any).name).toBe('oauth.do CLI')
    })

    it('seeds dashboard web client', async () => {
      await service.ensureDefaultClients()
      const client = store.get('client:id_org_ai_dash')
      expect(client).toBeDefined()
      expect((client as any).grantTypes).toContain('authorization_code')
    })

    it('seeds headlessly web client', async () => {
      await service.ensureDefaultClients()
      const client = store.get('client:id_org_ai_headlessly')
      expect(client).toBeDefined()
    })

    it('does not overwrite existing clients', async () => {
      store.set('client:id_org_ai_cli', { id: 'id_org_ai_cli', name: 'Custom Name' })
      await service.ensureDefaultClients()
      expect((store.get('client:id_org_ai_cli') as any).name).toBe('Custom Name')
    })
  })

  // ── getOpenIDConfiguration() ───────────────────────────────────────────

  describe('getOpenIDConfiguration()', () => {
    it('returns discovery document with configured endpoints', () => {
      const config = service.getOpenIDConfiguration()
      expect(config.issuer).toBe(TEST_CONFIG.issuer)
      expect(config.authorization_endpoint).toBe(TEST_CONFIG.authorizationEndpoint)
      expect(config.token_endpoint).toBe(TEST_CONFIG.tokenEndpoint)
      expect(config.jwks_uri).toBe(TEST_CONFIG.jwksUri)
    })
  })

  // ── Facade delegation ──────────────────────────────────────────────────

  describe('facade delegation', () => {
    it('handleToken delegates to OAuthProvider', async () => {
      const request = new Request('https://test.example.com/oauth/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'grant_type=client_credentials&client_id=test',
      })
      const response = await service.handleToken(request)
      expect(response).toBeInstanceOf(Response)
    })

    it('handleRegister delegates to OAuthProvider', async () => {
      const request = new Request('https://test.example.com/oauth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ client_name: 'Test App', redirect_uris: ['https://example.com/callback'] }),
      })
      const response = await service.handleRegister(request)
      expect(response).toBeInstanceOf(Response)
    })

    it('handleIntrospect delegates to OAuthProvider', async () => {
      const request = new Request('https://test.example.com/oauth/introspect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'token=fake_token',
      })
      const response = await service.handleIntrospect(request)
      expect(response).toBeInstanceOf(Response)
    })

    it('handleRevoke delegates to OAuthProvider', async () => {
      const request = new Request('https://test.example.com/oauth/revoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'token=fake_token',
      })
      const response = await service.handleRevoke(request)
      expect(response).toBeInstanceOf(Response)
    })
  })
})
