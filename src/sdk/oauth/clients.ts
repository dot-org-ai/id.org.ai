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

/** RFC 8628 device-authorization grant type URN. */
export const DEVICE_CODE_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:device_code'

/**
 * The canonical seed list. Consumers that need to know what clients ship by
 * default (docs, smoke tests, ops) read this; nothing else hardcodes IDs.
 */
export const DEFAULT_OAUTH_CLIENTS: readonly DefaultClient[] = [
  {
    id: 'id_org_ai_cli',
    name: 'id.org.ai CLI',
    redirectUris: [],
    grantTypes: [DEVICE_CODE_GRANT_TYPE],
    responseTypes: [],
    scopes: ['openid', 'profile', 'email', 'offline_access'],
    trusted: true,
    tokenEndpointAuthMethod: 'none',
  },
  {
    id: 'oauth_do_cli',
    name: 'oauth.do CLI',
    redirectUris: [],
    grantTypes: [DEVICE_CODE_GRANT_TYPE],
    responseTypes: [],
    scopes: ['openid', 'profile', 'email', 'offline_access'],
    trusted: true,
    tokenEndpointAuthMethod: 'none',
  },
  {
    id: 'auto_dev_cli',
    name: 'auto.dev CLI',
    redirectUris: [],
    grantTypes: [DEVICE_CODE_GRANT_TYPE],
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
  {
    id: 'saas_studio_dash',
    name: 'SaaS.Studio',
    redirectUris: [
      'https://app.saas.studio/auth/callback',
      'https://saas.studio/auth/callback',
      'http://localhost:3000/auth/callback',
    ],
    grantTypes: ['authorization_code', 'refresh_token'],
    responseTypes: ['code'],
    scopes: ['openid', 'profile', 'email', 'offline_access'],
    trusted: true,
    tokenEndpointAuthMethod: 'none',
  },
] as const

/**
 * Shape check for the **first-party CLI family**: a trusted, public
 * (`token_endpoint_auth_method: none`, no secret) client that is authorized
 * for the device_code grant. This is the predicate that admits a client to
 * cross-client refresh (see `FIRST_PARTY_CLI_CLIENT_IDS` and
 * `OAuthProvider#handleRefreshTokenGrant`). It is deliberately structural —
 * membership never depends on an id prefix or a name — and it is applied
 * twice: once to the seed list to derive the family set, and again to the
 * live `client:<id>` record at refresh time so an operator edit that turns a
 * CLI into a confidential or untrusted client takes it out of the family
 * immediately.
 */
export function isFirstPartyCliClient(
  client:
    | { trusted?: boolean; tokenEndpointAuthMethod?: string; grantTypes?: readonly string[]; secret?: string }
    | null
    | undefined,
): boolean {
  if (!client) return false
  return (
    client.trusted === true &&
    client.tokenEndpointAuthMethod === 'none' &&
    !client.secret &&
    Array.isArray(client.grantTypes) &&
    client.grantTypes.includes(DEVICE_CODE_GRANT_TYPE)
  )
}

/**
 * The first-party CLI family, derived from the seed registry by
 * `isFirstPartyCliClient` — never from a string prefix. These CLIs share one
 * on-disk token store, so a refresh token minted by one member may be
 * refreshed by another member; the re-issued pair is bound to the
 * requesting member. Adding a client to `DEFAULT_OAUTH_CLIENTS` with the
 * matching shape adds it to the family; nothing else does.
 */
export const FIRST_PARTY_CLI_CLIENT_IDS: ReadonlySet<string> = new Set(
  DEFAULT_OAUTH_CLIENTS.filter(isFirstPartyCliClient).map((c) => c.id),
)

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
