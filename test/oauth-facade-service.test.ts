// test/oauth-facade-service.test.ts
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { OAuthServiceImpl } from '../src/services/oauth/service'

// ── Mock Storage ────────────────────────────────────────────────────────

function createMockStorage() {
  const store = new Map<string, unknown>()

  const storage = {
    get: vi.fn(async (key: string) => store.get(key)),
    put: vi.fn(async (key: string | Record<string, unknown>, value?: unknown) => {
      if (typeof key === 'string') {
        store.set(key, value)
      } else {
        for (const [k, v] of Object.entries(key)) {
          store.set(k, v)
        }
      }
    }),
    delete: vi.fn(async (key: string | string[]) => {
      if (Array.isArray(key)) {
        let count = 0
        for (const k of key) {
          if (store.has(k)) { store.delete(k); count++ }
        }
        return count
      }
      const had = store.has(key)
      store.delete(key)
      return had
    }),
    list: vi.fn(async (options?: { prefix?: string }) => {
      const entries = new Map<string, unknown>()
      for (const [k, v] of store) {
        if (!options?.prefix || k.startsWith(options.prefix)) {
          entries.set(k, v)
        }
      }
      return entries
    }),
    deleteAll: vi.fn(),
    getAlarm: vi.fn(),
    setAlarm: vi.fn(),
  } as unknown as DurableObjectStorage

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
  let storage: DurableObjectStorage
  let store: Map<string, unknown>
  let service: OAuthServiceImpl

  beforeEach(() => {
    const mock = createMockStorage()
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
