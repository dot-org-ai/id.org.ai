/**
 * Default OAuth client seeding — direct unit tests.
 *
 * Replaces test/oauth-facade-service.test.ts. The OAuthServiceImpl facade was
 * a hollow forward over OAuthProvider; seedDefaultClients() is the only logic
 * that lived there worth keeping.
 */
import { describe, it, expect, beforeEach } from 'vitest'
import { seedDefaultClients, DEFAULT_OAUTH_CLIENTS } from '../src/sdk/oauth/clients'

function createMockStorage() {
  const store = new Map<string, unknown>()
  const storage = {
    async get<T = unknown>(key: string): Promise<T | undefined> {
      return store.get(key) as T | undefined
    },
    async put(key: string, value: unknown): Promise<void> {
      store.set(key, value)
    },
  }
  return { storage, store }
}

describe('seedDefaultClients', () => {
  let storage: ReturnType<typeof createMockStorage>['storage']
  let store: Map<string, unknown>

  beforeEach(() => {
    const mock = createMockStorage()
    storage = mock.storage
    store = mock.store
  })

  it('seeds CLI client (id_org_ai_cli)', async () => {
    await seedDefaultClients(storage)
    const client = store.get('client:id_org_ai_cli') as Record<string, unknown> | undefined
    expect(client).toBeDefined()
    expect(client!.name).toBe('id.org.ai CLI')
    expect(client!.grantTypes).toContain('urn:ietf:params:oauth:grant-type:device_code')
  })

  it('seeds oauth.do CLI client', async () => {
    await seedDefaultClients(storage)
    const client = store.get('client:oauth_do_cli') as Record<string, unknown> | undefined
    expect(client).toBeDefined()
    expect(client!.name).toBe('oauth.do CLI')
  })

  it('seeds dashboard web client (authorization_code grant)', async () => {
    await seedDefaultClients(storage)
    const client = store.get('client:id_org_ai_dash') as Record<string, unknown> | undefined
    expect(client).toBeDefined()
    expect(client!.grantTypes).toContain('authorization_code')
  })

  it('seeds headless.ly web client', async () => {
    await seedDefaultClients(storage)
    expect(store.get('client:id_org_ai_headlessly')).toBeDefined()
  })

  it('does not overwrite existing clients (idempotent)', async () => {
    store.set('client:id_org_ai_cli', { id: 'id_org_ai_cli', name: 'Custom Name' })
    await seedDefaultClients(storage)
    const client = store.get('client:id_org_ai_cli') as Record<string, unknown>
    expect(client.name).toBe('Custom Name')
  })

  it('seeds every client in DEFAULT_OAUTH_CLIENTS — the constant is the contract', async () => {
    await seedDefaultClients(storage)
    for (const expected of DEFAULT_OAUTH_CLIENTS) {
      expect(store.get(`client:${expected.id}`)).toBeDefined()
    }
  })
})
