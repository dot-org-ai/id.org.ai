import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import {
  encodeTenantVaultName,
  decodeTenantVaultName,
  putTenantSecret,
  getTenantSecretValue,
  listTenantSecrets,
  deleteTenantSecret,
} from '../src/sdk/workos/tenant-vault'

const API_KEY = 'sk_test_fake'

// ── In-memory fake of the WorkOS Vault HTTP surface ────────────────────────
type FakeSecret = {
  id: string
  name: string
  value: string
  description?: string
  environment: string
  created_at: string
  updated_at: string
}

const store = new Map<string, FakeSecret>()
let idCounter = 0

function reset() {
  store.clear()
  idCounter = 0
}

function fakeFetch(input: RequestInfo, init?: RequestInit): Promise<Response> {
  const url = typeof input === 'string' ? input : (input as Request).url
  const method = (init?.method ?? 'GET').toUpperCase()
  const u = new URL(url)
  const path = u.pathname

  if (path === '/vault/v1/secrets' && method === 'GET') {
    const limit = Number(u.searchParams.get('limit') ?? '100')
    const data = [...store.values()].slice(0, limit).map(stripValue)
    return jsonResp(200, { data, list_metadata: {} })
  }

  if (path === '/vault/v1/secrets' && method === 'POST') {
    const body = JSON.parse(String(init!.body)) as { name: string; value: string; description?: string; environment?: string }
    const id = `secret_${++idCounter}`
    const now = new Date().toISOString()
    const secret: FakeSecret = {
      id,
      name: body.name,
      value: body.value,
      description: body.description,
      environment: body.environment ?? 'production',
      created_at: now,
      updated_at: now,
    }
    store.set(id, secret)
    return jsonResp(201, stripValue(secret))
  }

  const matchById = path.match(/^\/vault\/v1\/secrets\/(secret_[^/]+)(?:\/(.+))?$/)
  if (matchById) {
    const [, id, suffix] = matchById
    const secret = store.get(id)
    if (!secret) return jsonResp(404, { error: 'not found' })

    if (method === 'GET' && suffix === 'reveal') {
      return jsonResp(200, secret)
    }
    if (method === 'GET' && !suffix) {
      return jsonResp(200, stripValue(secret))
    }
    if (method === 'PUT' && !suffix) {
      const body = JSON.parse(String(init!.body)) as { value?: string; description?: string }
      if (body.value !== undefined) secret.value = body.value
      if (body.description !== undefined) secret.description = body.description
      secret.updated_at = new Date().toISOString()
      return jsonResp(200, stripValue(secret))
    }
    if (method === 'DELETE' && !suffix) {
      store.delete(id)
      return new Response(null, { status: 204 })
    }
  }

  return jsonResp(404, { error: `not handled: ${method} ${path}` })
}

function stripValue(s: FakeSecret): Omit<FakeSecret, 'value'> {
  const { value: _value, ...rest } = s
  return rest
}

function jsonResp(status: number, body: unknown): Promise<Response> {
  return Promise.resolve(
    new Response(JSON.stringify(body), {
      status,
      headers: { 'Content-Type': 'application/json' },
    }),
  )
}

// ── Tests ──────────────────────────────────────────────────────────────────

describe('tenant-vault: encode/decode', () => {
  it('encodes tenantId and name into a single namespaced name', () => {
    expect(encodeTenantVaultName('tenant_abc', 'STRIPE_KEY')).toBe('tenant_tenant_abc__STRIPE_KEY')
  })

  it('decodes back to the same components', () => {
    const decoded = decodeTenantVaultName('tenant_t1__STRIPE_KEY')
    expect(decoded).toEqual({ tenantId: 't1', name: 'STRIPE_KEY' })
  })

  it('returns null for foreign secrets (no tenant_ prefix)', () => {
    expect(decodeTenantVaultName('GLOBAL_KEY')).toBeNull()
  })

  it('rejects names containing the separator', () => {
    expect(() => encodeTenantVaultName('t1', 'BAD__NAME')).toThrow()
    expect(() => encodeTenantVaultName('bad__id', 'name')).toThrow()
  })

  it('rejects empty inputs', () => {
    expect(() => encodeTenantVaultName('', 'x')).toThrow()
    expect(() => encodeTenantVaultName('t', '')).toThrow()
  })
})

describe('tenant-vault: CRUD', () => {
  let originalFetch: typeof globalThis.fetch

  beforeEach(() => {
    reset()
    originalFetch = globalThis.fetch
    globalThis.fetch = fakeFetch as unknown as typeof globalThis.fetch
  })

  afterEach(() => {
    globalThis.fetch = originalFetch
  })

  it('puts and reads a tenant secret', async () => {
    const info = await putTenantSecret(API_KEY, 'tenant_a', 'STRIPE_KEY', 'sk_secret')
    expect(info.tenantId).toBe('tenant_a')
    expect(info.name).toBe('STRIPE_KEY')
    expect(info.id).toMatch(/^secret_/)

    const value = await getTenantSecretValue(API_KEY, 'tenant_a', 'STRIPE_KEY')
    expect(value).toBe('sk_secret')
  })

  it('updates the value when the secret already exists', async () => {
    await putTenantSecret(API_KEY, 'tenant_a', 'STRIPE_KEY', 'first')
    const second = await putTenantSecret(API_KEY, 'tenant_a', 'STRIPE_KEY', 'second')

    // Same WorkOS ID — update path, not create
    const stored = await getTenantSecretValue(API_KEY, 'tenant_a', 'STRIPE_KEY')
    expect(stored).toBe('second')
    expect(second.id).toBeDefined()
  })

  it('isolates secrets across tenants — same name does not collide', async () => {
    await putTenantSecret(API_KEY, 'tenant_a', 'STRIPE_KEY', 'a-value')
    await putTenantSecret(API_KEY, 'tenant_b', 'STRIPE_KEY', 'b-value')

    expect(await getTenantSecretValue(API_KEY, 'tenant_a', 'STRIPE_KEY')).toBe('a-value')
    expect(await getTenantSecretValue(API_KEY, 'tenant_b', 'STRIPE_KEY')).toBe('b-value')
  })

  it('listTenantSecrets only returns secrets for the requested tenant', async () => {
    await putTenantSecret(API_KEY, 'tenant_a', 'KEY_1', 'v1')
    await putTenantSecret(API_KEY, 'tenant_a', 'KEY_2', 'v2')
    await putTenantSecret(API_KEY, 'tenant_b', 'KEY_3', 'v3')

    const aList = await listTenantSecrets(API_KEY, 'tenant_a')
    expect(aList.length).toBe(2)
    expect(aList.map((s) => s.name).sort()).toEqual(['KEY_1', 'KEY_2'])

    const bList = await listTenantSecrets(API_KEY, 'tenant_b')
    expect(bList.length).toBe(1)
    expect(bList[0]?.name).toBe('KEY_3')
  })

  it('listTenantSecrets ignores non-tenant-scoped secrets in the vault', async () => {
    // Pretend a foreign (non-tenant-scoped) secret was created by another caller
    store.set('secret_foreign', {
      id: 'secret_foreign',
      name: 'GLOBAL_API_KEY',
      value: 'foreign-value',
      environment: 'production',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    })
    await putTenantSecret(API_KEY, 'tenant_a', 'OWN_KEY', 'mine')

    const list = await listTenantSecrets(API_KEY, 'tenant_a')
    expect(list.length).toBe(1)
    expect(list[0]?.name).toBe('OWN_KEY')
  })

  it('getTenantSecretValue throws when the secret does not exist', async () => {
    await expect(getTenantSecretValue(API_KEY, 'tenant_a', 'MISSING')).rejects.toThrow(/not found/)
  })

  it('deleteTenantSecret removes the secret', async () => {
    await putTenantSecret(API_KEY, 'tenant_a', 'EPHEMERAL', 'gone-soon')
    await deleteTenantSecret(API_KEY, 'tenant_a', 'EPHEMERAL')
    await expect(getTenantSecretValue(API_KEY, 'tenant_a', 'EPHEMERAL')).rejects.toThrow(/not found/)
  })

  it('deleteTenantSecret is idempotent — no error when secret is absent', async () => {
    await expect(deleteTenantSecret(API_KEY, 'tenant_a', 'NEVER_EXISTED')).resolves.toBeUndefined()
  })

  it('deleteTenantSecret cannot reach across tenants', async () => {
    await putTenantSecret(API_KEY, 'tenant_a', 'SHARED_NAME', 'a-value')
    await putTenantSecret(API_KEY, 'tenant_b', 'SHARED_NAME', 'b-value')

    // Tenant B tries to delete its own; A's must remain
    await deleteTenantSecret(API_KEY, 'tenant_b', 'SHARED_NAME')

    expect(await getTenantSecretValue(API_KEY, 'tenant_a', 'SHARED_NAME')).toBe('a-value')
    await expect(getTenantSecretValue(API_KEY, 'tenant_b', 'SHARED_NAME')).rejects.toThrow(/not found/)
  })

  it('rejects bad names at the encode layer', async () => {
    await expect(putTenantSecret(API_KEY, 'tenant_a', 'BAD__NAME', 'x')).rejects.toThrow()
  })
})
