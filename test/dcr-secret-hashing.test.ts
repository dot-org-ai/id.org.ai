/**
 * B13.5 (docs/product-update/spec/backend.md#b13): DCR client secrets were
 * stored in plaintext and compared with !==. New registrations store only a
 * SHA-256 hash; a legacy plaintext secret still works once, then the record
 * comes back hashed. Secrets are compared in constant time.
 */
import { describe, it, expect } from 'vitest'
import { SELF, env } from 'cloudflare:test'
import { getStubForIdentity } from '../worker/middleware/tenant'
import { hashClientSecret } from '../src/sdk/oauth/client-secret'

const BASE = 'https://id.org.ai'

function oauthStore() {
  return getStubForIdentity(env as never, 'oauth')
}

async function record(clientId: string): Promise<Record<string, unknown>> {
  return ((await oauthStore().oauthStorageOp({ op: 'get', key: `client:${clientId}` })).value ?? {}) as Record<string, unknown>
}

async function registerConfidential(): Promise<{ client_id: string; client_secret: string }> {
  const res = await SELF.fetch(`${BASE}/oauth/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      client_name: 'Secret test',
      redirect_uris: ['https://app.example.com/cb'],
      grant_types: ['client_credentials'],
      token_endpoint_auth_method: 'client_secret_post',
      scope: 'openid',
    }),
  })
  expect(res.status).toBe(201)
  return (await res.json()) as { client_id: string; client_secret: string }
}

async function clientCredentials(clientId: string, secret: string): Promise<Response> {
  return SELF.fetch(`${BASE}/oauth/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'client_credentials', client_id: clientId, client_secret: secret }).toString(),
  })
}

describe('B13.5: DCR client secrets are hashed at rest', () => {
  it('a new registration stores only the SHA-256 hash, and the secret is returned once', async () => {
    const { client_id, client_secret } = await registerConfidential()
    expect(client_secret).toMatch(/^cs_/)
    const stored = await record(client_id)
    expect(stored.secret).toBeUndefined()
    expect(stored.secretHash).toBe(await hashClientSecret(client_secret))
    expect(JSON.stringify(stored)).not.toContain(client_secret)
  })

  it('the hashed secret authenticates; a wrong one is refused', async () => {
    const { client_id, client_secret } = await registerConfidential()
    expect((await clientCredentials(client_id, client_secret)).status).toBe(200)
    expect((await clientCredentials(client_id, client_secret + 'x')).status).toBe(401)
    expect((await clientCredentials(client_id, '')).status).toBe(401)
  })

  it('a legacy plaintext secret works once, then the record comes back hashed', async () => {
    const { client_id } = await registerConfidential()
    const legacy = { ...(await record(client_id)), secret: 'cs_legacy_plaintext_secret' }
    delete legacy.secretHash
    await oauthStore().oauthStorageOp({ op: 'put', key: `client:${client_id}`, value: legacy })

    expect((await clientCredentials(client_id, 'cs_wrong')).status).toBe(401)
    expect((await record(client_id)).secret).toBe('cs_legacy_plaintext_secret')

    expect((await clientCredentials(client_id, 'cs_legacy_plaintext_secret')).status).toBe(200)
    const migrated = await record(client_id)
    expect(migrated.secret).toBeUndefined()
    expect(migrated.secretHash).toBe(await hashClientSecret('cs_legacy_plaintext_secret'))

    expect((await clientCredentials(client_id, 'cs_legacy_plaintext_secret')).status).toBe(200)
  })
})
