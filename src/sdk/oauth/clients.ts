/**
 * Default OAuth client seeding.
 *
 * The IdentityDO and other system entry points call seedDefaultClients() to
 * lazily populate the well-known clients (CLI, dashboard, headless.ly, etc.).
 * Idempotent: each client is only written if a record at `client:<id>` is
 * absent — this preserves operator-edited clients across boots.
 */

/**
 * Minimal storage shape for seeding. Both `DurableObjectStorage` and the
 * provider's `StorageLike` bridge satisfy this — the seam exists so the DO
 * can seed without building a full `OAuthStorage` adapter.
 */
export interface ClientSeedStorage {
  get<T = unknown>(key: string): Promise<T | undefined | null>
  put(key: string, value: unknown, options?: unknown): Promise<void>
}

export interface DefaultClient {
  id: string
  name: string
  redirectUris: string[]
  grantTypes: string[]
  responseTypes: string[]
  scopes: string[]
  trusted: boolean
  tokenEndpointAuthMethod: string
}

/**
 * The canonical seed list. Consumers that need to know what clients ship by
 * default (docs, smoke tests, ops) read this; nothing else hardcodes IDs.
 */
export const DEFAULT_OAUTH_CLIENTS: readonly DefaultClient[] = [
  {
    id: 'id_org_ai_cli',
    name: 'id.org.ai CLI',
    redirectUris: [],
    grantTypes: ['urn:ietf:params:oauth:grant-type:device_code'],
    responseTypes: [],
    scopes: ['openid', 'profile', 'email', 'offline_access'],
    trusted: true,
    tokenEndpointAuthMethod: 'none',
  },
  {
    id: 'oauth_do_cli',
    name: 'oauth.do CLI',
    redirectUris: [],
    grantTypes: ['urn:ietf:params:oauth:grant-type:device_code'],
    responseTypes: [],
    scopes: ['openid', 'profile', 'email', 'offline_access'],
    trusted: true,
    tokenEndpointAuthMethod: 'none',
  },
  {
    id: 'auto_dev_cli',
    name: 'auto.dev CLI',
    redirectUris: [],
    grantTypes: ['urn:ietf:params:oauth:grant-type:device_code'],
    responseTypes: [],
    scopes: ['openid', 'profile', 'email', 'offline_access'],
    trusted: true,
    tokenEndpointAuthMethod: 'none',
  },
  {
    id: 'id_org_ai_dash',
    name: 'id.org.ai Dashboard',
    redirectUris: ['https://id.org.ai/dash/profile'],
    grantTypes: ['authorization_code'],
    responseTypes: ['code'],
    scopes: ['openid', 'profile', 'email'],
    trusted: true,
    tokenEndpointAuthMethod: 'none',
  },
  {
    id: 'id_org_ai_headlessly',
    name: 'Headless.ly',
    redirectUris: ['https://headless.ly/dashboard'],
    grantTypes: ['authorization_code'],
    responseTypes: ['code'],
    scopes: ['openid', 'profile', 'email'],
    trusted: true,
    tokenEndpointAuthMethod: 'none',
  },
  {
    id: 'auto_dev_web',
    name: 'auto.dev Web',
    redirectUris: [
      'https://auto.dev/api/v2/auth/callback/id-org-ai',
      'http://localhost:3000/api/v2/auth/callback/id-org-ai',
    ],
    grantTypes: ['authorization_code'],
    responseTypes: ['code'],
    scopes: ['openid', 'profile', 'email'],
    trusted: true,
    tokenEndpointAuthMethod: 'none',
  },
] as const

/**
 * Seed the default clients into the given storage. Idempotent — never
 * overwrites an existing record at `client:<id>`.
 */
export async function seedDefaultClients(storage: ClientSeedStorage): Promise<void> {
  for (const client of DEFAULT_OAUTH_CLIENTS) {
    const existing = await storage.get(`client:${client.id}`)
    if (!existing) {
      await storage.put(`client:${client.id}`, { ...client, createdAt: Date.now() })
    }
  }
}
