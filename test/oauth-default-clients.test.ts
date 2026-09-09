/**
 * Default OAuth client seeding — direct unit tests.
 *
 * Replaces test/oauth-facade-service.test.ts. The OAuthServiceImpl facade was
 * a hollow forward over OAuthProvider; seedDefaultClients() is the only logic
 * that lived there worth keeping.
 */
import { describe, it, expect, beforeEach } from 'vitest'
import {
  seedDefaultClients,
  DEFAULT_OAUTH_CLIENTS,
  DEVICE_CODE_GRANT_TYPE,
  FIRST_PARTY_CLI_CLIENT_IDS,
  isFirstPartyCliClient,
} from '../src/sdk/oauth/clients'

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

  it('seeds SaaS.Studio dashboard web client (trusted, authorization_code + refresh)', async () => {
    await seedDefaultClients(storage)
    const client = store.get('client:saas_studio_dash') as Record<string, unknown> | undefined
    expect(client).toBeDefined()
    expect(client!.name).toBe('SaaS.Studio')
    expect(client!.trusted).toBe(true)
    expect(client!.grantTypes).toContain('authorization_code')
    expect(client!.grantTypes).toContain('refresh_token')
    expect(client!.redirectUris).toContain('https://app.saas.studio/auth/callback')
    expect(client!.redirectUris).toContain('http://localhost:3000/auth/callback')
    expect(client!.scopes).toContain('offline_access')
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

describe('first-party CLI family', () => {
  it('is derived from the registry by shape: trusted + public + device_code', () => {
    const expected = DEFAULT_OAUTH_CLIENTS
      .filter((c) => c.trusted && c.tokenEndpointAuthMethod === 'none' && c.grantTypes.includes(DEVICE_CODE_GRANT_TYPE))
      .map((c) => c.id)
    expect([...FIRST_PARTY_CLI_CLIENT_IDS].sort()).toEqual(expected.sort())
    expect([...FIRST_PARTY_CLI_CLIENT_IDS].sort()).toEqual(['auto_dev_cli', 'id_org_ai_cli', 'oauth_do_cli'])
  })

  it('excludes the trusted web clients (no device_code grant)', () => {
    for (const id of ['id_org_ai_dash', 'id_org_ai_headlessly', 'auto_dev_web', 'saas_studio_dash']) {
      expect(FIRST_PARTY_CLI_CLIENT_IDS.has(id)).toBe(false)
    }
  })

  it('isFirstPartyCliClient is structural, not name-based', () => {
    const cli = { trusted: true, tokenEndpointAuthMethod: 'none', grantTypes: [DEVICE_CODE_GRANT_TYPE] }
    expect(isFirstPartyCliClient(cli)).toBe(true)
    expect(isFirstPartyCliClient({ ...cli, trusted: false })).toBe(false)
    expect(isFirstPartyCliClient({ ...cli, tokenEndpointAuthMethod: 'client_secret_post' })).toBe(false)
    expect(isFirstPartyCliClient({ ...cli, secret: 'hashed' })).toBe(false)
    expect(isFirstPartyCliClient({ ...cli, grantTypes: ['authorization_code'] })).toBe(false)
    expect(isFirstPartyCliClient(null)).toBe(false)
    expect(isFirstPartyCliClient(undefined)).toBe(false)
  })
})
