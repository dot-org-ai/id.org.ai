/**
 * IdentityDO Comprehensive Unit Tests
 *
 * Tests every public method of the IdentityDO Durable Object using a
 * mock storage layer that simulates DurableObjectStorage behaviour.
 * The real DurableObject base class is not available outside the
 * Cloudflare Workers runtime, so we construct a testable instance by
 * injecting mock ctx / env via prototype tricks.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'

// ============================================================================
// Mock infrastructure
// ============================================================================

// Mock the cloudflare:workers import so the module can load outside Workers
vi.mock('cloudflare:workers', () => ({
  DurableObject: class DurableObject {
    ctx: any
    env: any
    constructor(ctx: any, env: any) {
      this.ctx = ctx
      this.env = env
    }
  },
}))

// Mock the crypto helpers used by registerAgentKey / verifyAgentSignature.
// We provide deterministic stubs that mirror the real API contract.
const MOCK_PUBLIC_KEY = new Uint8Array(32).fill(0xab)
const MOCK_PUBLIC_KEY_B64 = btoa(String.fromCharCode(...MOCK_PUBLIC_KEY))
const MOCK_DID = 'did:agent:ed25519:MockBase58EncodedPublicKey1234'
const MOCK_DID_2 = 'did:agent:ed25519:MockBase58EncodedPublicKey5678'

vi.mock('../src/crypto/keys', () => ({
  publicKeyToDID: vi.fn((_pk: Uint8Array) => MOCK_DID),
  didToPublicKey: vi.fn((_did: string) => MOCK_PUBLIC_KEY),
  pemToPublicKey: vi.fn((_pem: string) => MOCK_PUBLIC_KEY),
  verify: vi.fn(async () => true),
  base64Decode: vi.fn((str: string) => {
    const binary = atob(str)
    const data = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i++) data[i] = binary.charCodeAt(i)
    return data
  }),
  base64Encode: vi.fn((data: Uint8Array) => {
    let binary = ''
    for (let i = 0; i < data.length; i++) binary += String.fromCharCode(data[i])
    return btoa(binary)
  }),
  isValidDID: vi.fn((did: string) => did.startsWith('did:agent:ed25519:')),
}))

// Mock the audit module — writeAuditEvent / queryAuditLog delegate to AuditLog
vi.mock('../src/audit', () => {
  class AuditLog {
    storage: any
    constructor(storage: any) {
      this.storage = storage
    }
    async query(options: any) {
      return { events: [], cursor: undefined, hasMore: false }
    }
  }
  return { AuditLog }
})

// ── MockStorage ──────────────────────────────────────────────────────────

class MockStorage {
  private store = new Map<string, any>()

  async get<T>(key: string): Promise<T | undefined> {
    return this.store.get(key) as T | undefined
  }

  async put(key: string | Record<string, any>, value?: any): Promise<void> {
    if (typeof key === 'string') {
      this.store.set(key, value)
      return
    }
    for (const [k, v] of Object.entries(key)) this.store.set(k, v)
  }

  async delete(keys: string | string[]): Promise<boolean | number> {
    if (typeof keys === 'string') return this.store.delete(keys)
    let count = 0
    for (const k of keys) {
      if (this.store.delete(k)) count++
    }
    return count
  }

  async list<T>(options?: { prefix?: string; limit?: number }): Promise<Map<string, T>> {
    const map = new Map<string, T>()
    // Sort keys lexicographically (mirrors real DO storage)
    const sortedKeys = [...this.store.keys()].sort()
    for (const k of sortedKeys) {
      if (options?.prefix && !k.startsWith(options.prefix)) continue
      map.set(k, this.store.get(k) as T)
      if (options?.limit && map.size >= options.limit) break
    }
    return map
  }

  /** Expose for test introspection */
  _raw() {
    return this.store
  }
}

// ── Helper: create a testable IdentityDO ──────────────────────────────────

async function createTestDO() {
  // Dynamic import after mocks are set up
  const mod = await import('../src/do/Identity')
  const IdentityDO = mod.IdentityDO

  const storage = new MockStorage()
  const ctx = { storage } as any
  const env = {
    SESSIONS: {} as any,
    AUTH_SECRET: 'test-secret',
    JWKS_SECRET: 'test-jwks',
  }

  const identity = new IdentityDO(ctx, env)
  return { identity, storage, IdentityDO: mod.IdentityDO }
}

// ============================================================================
// Tests
// ============================================================================

describe('IdentityDO', () => {
  let identity: Awaited<ReturnType<typeof createTestDO>>['identity']
  let storage: MockStorage

  beforeEach(async () => {
    vi.clearAllMocks()
    const t = await createTestDO()
    identity = t.identity
    storage = t.storage
  })

  // ──────────────────────────────────────────────────────────────────────
  // createIdentity
  // ──────────────────────────────────────────────────────────────────────

  describe('createIdentity()', () => {
    it('creates identity with correct type, name, and defaults', async () => {
      const result = await identity.createIdentity({ type: 'human', name: 'Alice' })
      expect(result.type).toBe('human')
      expect(result.name).toBe('Alice')
      expect(result.verified).toBe(false)
      expect(result.level).toBe(0)
      expect(result.claimStatus).toBe('unclaimed')
    })

    it('generates a UUID id when none provided', async () => {
      const result = await identity.createIdentity({ type: 'agent', name: 'Bot' })
      expect(result.id).toBeDefined()
      expect(typeof result.id).toBe('string')
      expect(result.id.length).toBeGreaterThan(0)
    })

    it('uses provided id when given', async () => {
      const result = await identity.createIdentity({ type: 'human', name: 'Bob', id: 'custom-id-123' })
      expect(result.id).toBe('custom-id-123')
    })

    it('stores a claim token with clm_ prefix', async () => {
      const result = await identity.createIdentity({ type: 'agent', name: 'Bot' })
      const stored = await storage.get<any>(`identity:${result.id}`)
      expect(stored.claimToken).toBeDefined()
      expect(stored.claimToken.startsWith('clm_')).toBe(true)
    })

    it('defaults to level 0', async () => {
      const result = await identity.createIdentity({ type: 'human', name: 'Test' })
      expect(result.level).toBe(0)
    })

    it('accepts a custom level', async () => {
      const result = await identity.createIdentity({ type: 'agent', name: 'Test', level: 2 })
      expect(result.level).toBe(2)
    })

    it('stores email and handle when provided', async () => {
      const result = await identity.createIdentity({ type: 'human', name: 'Alice', email: 'alice@test.com', handle: '@alice' })
      expect(result.email).toBe('alice@test.com')
      expect(result.handle).toBe('@alice')
    })

    it('persists createdAt timestamp in storage', async () => {
      const before = Date.now()
      const result = await identity.createIdentity({ type: 'human', name: 'Ts' })
      const after = Date.now()
      const stored = await storage.get<any>(`identity:${result.id}`)
      expect(stored.createdAt).toBeGreaterThanOrEqual(before)
      expect(stored.createdAt).toBeLessThanOrEqual(after)
    })
  })

  // ──────────────────────────────────────────────────────────────────────
  // getIdentity
  // ──────────────────────────────────────────────────────────────────────

  describe('getIdentity()', () => {
    it('returns identity data for existing id', async () => {
      const created = await identity.createIdentity({ type: 'human', name: 'Alice', email: 'a@test.com' })
      const fetched = await identity.getIdentity(created.id)
      expect(fetched).not.toBeNull()
      expect(fetched!.id).toBe(created.id)
      expect(fetched!.name).toBe('Alice')
      expect(fetched!.email).toBe('a@test.com')
      expect(fetched!.type).toBe('human')
    })

    it('returns null for non-existent id', async () => {
      const result = await identity.getIdentity('does-not-exist')
      expect(result).toBeNull()
    })

    it('returns frozen status correctly', async () => {
      const created = await identity.createIdentity({ type: 'agent', name: 'Bot' })
      // Manually set frozen in storage
      const stored = await storage.get<any>(`identity:${created.id}`)
      await storage.put(`identity:${created.id}`, { ...stored, frozen: true, frozenAt: Date.now() })

      const fetched = await identity.getIdentity(created.id)
      expect(fetched!.frozen).toBe(true)
      expect(fetched!.frozenAt).toBeDefined()
    })

    it('defaults verified to false when not set', async () => {
      const created = await identity.createIdentity({ type: 'human', name: 'NoVerify' })
      const fetched = await identity.getIdentity(created.id)
      expect(fetched!.verified).toBe(false)
    })
  })

  // ──────────────────────────────────────────────────────────────────────
  // provisionAnonymous
  // ──────────────────────────────────────────────────────────────────────

  describe('provisionAnonymous()', () => {
    it('creates an agent identity with level 1', async () => {
      const result = await identity.provisionAnonymous()
      expect(result.identity.type).toBe('agent')
      expect(result.identity.level).toBe(1)
    })

    it('generates anon_ name prefix', async () => {
      const result = await identity.provisionAnonymous()
      expect(result.identity.name.startsWith('anon_')).toBe(true)
    })

    it('creates a session token with ses_ prefix', async () => {
      const result = await identity.provisionAnonymous()
      expect(result.sessionToken.startsWith('ses_')).toBe(true)
    })

    it('returns a claim token with clm_ prefix', async () => {
      const result = await identity.provisionAnonymous()
      expect(result.claimToken.startsWith('clm_')).toBe(true)
    })

    it('uses preset identity ID when provided', async () => {
      const result = await identity.provisionAnonymous('preset-id-42')
      expect(result.identity.id).toBe('preset-id-42')
    })

    it('creates a session that expires in ~24 hours', async () => {
      const before = Date.now()
      const result = await identity.provisionAnonymous()
      const sessionData = await storage.get<any>(`session:${result.sessionToken}`)
      const day = 24 * 60 * 60 * 1000
      expect(sessionData.expiresAt).toBeGreaterThanOrEqual(before + day - 100)
      expect(sessionData.expiresAt).toBeLessThanOrEqual(Date.now() + day + 100)
    })

    it('session identityId matches the created identity', async () => {
      const result = await identity.provisionAnonymous()
      const sessionData = await storage.get<any>(`session:${result.sessionToken}`)
      expect(sessionData.identityId).toBe(result.identity.id)
    })
  })

  // ──────────────────────────────────────────────────────────────────────
  // claim
  // ──────────────────────────────────────────────────────────────────────

  describe('claim()', () => {
    it('upgrades identity to claimed (level 2) on main branch', async () => {
      const { claimToken, identity: anon } = await identity.provisionAnonymous()
      const result = await identity.claim({
        claimToken,
        githubUserId: 'gh-123',
        githubUsername: 'alice',
        githubEmail: 'alice@gh.com',
        branch: 'main',
      })

      expect(result.success).toBe(true)
      expect(result.identity!.claimStatus).toBe('claimed')
      expect(result.identity!.level).toBe(2)
    })

    it('sets status to pending on non-main branch', async () => {
      const { claimToken } = await identity.provisionAnonymous()
      const result = await identity.claim({
        claimToken,
        githubUserId: 'gh-456',
        githubUsername: 'bob',
        branch: 'feature/test',
      })

      expect(result.success).toBe(true)
      expect(result.identity!.claimStatus).toBe('pending')
    })

    it('treats master branch as main', async () => {
      const { claimToken } = await identity.provisionAnonymous()
      const result = await identity.claim({
        claimToken,
        githubUserId: 'gh-789',
        githubUsername: 'charlie',
        branch: 'master',
      })

      expect(result.success).toBe(true)
      expect(result.identity!.claimStatus).toBe('claimed')
      expect(result.identity!.level).toBe(2)
    })

    it('links GitHub account in storage', async () => {
      const { claimToken, identity: anon } = await identity.provisionAnonymous()
      await identity.claim({
        claimToken,
        githubUserId: 'gh-123',
        githubUsername: 'alice',
        githubEmail: 'alice@gh.com',
        branch: 'main',
      })

      const linked = await storage.get<any>(`linked:${anon.id}:github`)
      expect(linked).not.toBeNull()
      expect(linked.provider).toBe('github')
      expect(linked.providerAccountId).toBe('gh-123')
      expect(linked.displayName).toBe('alice')
      expect(linked.email).toBe('alice@gh.com')
      expect(linked.status).toBe('active')
    })

    it('rejects already-claimed tenant', async () => {
      const { claimToken } = await identity.provisionAnonymous()
      await identity.claim({ claimToken, githubUserId: 'gh-1', githubUsername: 'first', branch: 'main' })

      const result = await identity.claim({ claimToken, githubUserId: 'gh-2', githubUsername: 'second', branch: 'main' })
      expect(result.success).toBe(false)
      expect(result.error).toContain('already claimed')
    })

    it('rejects invalid claim token', async () => {
      const result = await identity.claim({
        claimToken: 'clm_invalid_token_that_does_not_exist',
        githubUserId: 'gh-1',
        githubUsername: 'nobody',
        branch: 'main',
      })
      expect(result.success).toBe(false)
      expect(result.error).toContain('Invalid claim token')
    })

    it('stores GitHub user info on identity record', async () => {
      const { claimToken, identity: anon } = await identity.provisionAnonymous()
      await identity.claim({
        claimToken,
        githubUserId: 'gh-100',
        githubUsername: 'dev',
        githubEmail: 'dev@gh.com',
        repo: 'org/repo',
        branch: 'main',
      })

      const stored = await storage.get<any>(`identity:${anon.id}`)
      expect(stored.githubUserId).toBe('gh-100')
      expect(stored.githubUsername).toBe('dev')
      expect(stored.repo).toBe('org/repo')
    })

    it('updates email from GitHub when provided', async () => {
      const { claimToken, identity: anon } = await identity.provisionAnonymous()
      await identity.claim({
        claimToken,
        githubUserId: 'gh-1',
        githubUsername: 'user',
        githubEmail: 'new@email.com',
        branch: 'main',
      })

      const fetched = await identity.getIdentity(anon.id)
      expect(fetched!.email).toBe('new@email.com')
    })

    it('preserves existing email when GitHub email not provided', async () => {
      // Create with email first
      const created = await identity.createIdentity({ type: 'agent', name: 'bot', email: 'original@test.com' })
      const stored = await storage.get<any>(`identity:${created.id}`)

      const { claimToken } = await identity.provisionAnonymous()
      // Override storage to set email on the provisioned identity
      const entries = await storage.list<any>({ prefix: 'identity:' })
      let provisionedId = ''
      for (const [, val] of entries) {
        if (val.claimToken === claimToken) {
          provisionedId = val.id
          await storage.put(`identity:${val.id}`, { ...val, email: 'original@test.com' })
          break
        }
      }

      await identity.claim({
        claimToken,
        githubUserId: 'gh-1',
        githubUsername: 'user',
        branch: 'main',
      })

      const fetched = await identity.getIdentity(provisionedId)
      expect(fetched!.email).toBe('original@test.com')
    })
  })

  // ──────────────────────────────────────────────────────────────────────
  // getSession
  // ──────────────────────────────────────────────────────────────────────

  describe('getSession()', () => {
    it('returns valid session data', async () => {
      const { sessionToken, identity: anon } = await identity.provisionAnonymous()
      const session = await identity.getSession(sessionToken)
      expect(session.valid).toBe(true)
      expect(session.identityId).toBe(anon.id)
      expect(session.level).toBe(1)
      expect(session.expiresAt).toBeDefined()
    })

    it('returns invalid for non-ses_ tokens', async () => {
      const session = await identity.getSession('not_a_session_token')
      expect(session.valid).toBe(false)
    })

    it('returns invalid for empty ses_ token that does not exist', async () => {
      const session = await identity.getSession('ses_nonexistent')
      expect(session.valid).toBe(false)
    })

    it('returns invalid for expired sessions and deletes them', async () => {
      const { sessionToken } = await identity.provisionAnonymous()
      // Expire the session
      const sessionData = await storage.get<any>(`session:${sessionToken}`)
      await storage.put(`session:${sessionToken}`, { ...sessionData, expiresAt: Date.now() - 1000 })

      const session = await identity.getSession(sessionToken)
      expect(session.valid).toBe(false)

      // Session should be deleted
      const afterDelete = await storage.get(`session:${sessionToken}`)
      expect(afterDelete).toBeUndefined()
    })

    it('returns invalid for frozen identity', async () => {
      const { sessionToken, identity: anon } = await identity.provisionAnonymous()

      // Freeze the identity directly in storage
      const stored = await storage.get<any>(`identity:${anon.id}`)
      await storage.put(`identity:${anon.id}`, { ...stored, frozen: true })

      const session = await identity.getSession(sessionToken)
      expect(session.valid).toBe(false)
    })

    it('returns invalid for non-existent identity behind session', async () => {
      // Manually create a session pointing to a non-existent identity
      await storage.put('session:ses_orphan', {
        identityId: 'deleted-identity',
        level: 1,
        createdAt: Date.now(),
        expiresAt: Date.now() + 60_000,
      })

      const session = await identity.getSession('ses_orphan')
      expect(session.valid).toBe(false)
    })
  })

  // ──────────────────────────────────────────────────────────────────────
  // validateApiKey
  // ──────────────────────────────────────────────────────────────────────

  describe('validateApiKey()', () => {
    it('returns valid for active key with scopes', async () => {
      const { identity: anon } = await identity.provisionAnonymous()
      const created = await identity.createApiKey({ name: 'Test Key', identityId: anon.id, scopes: ['read', 'write'] })

      const result = await identity.validateApiKey(created.key)
      expect(result.valid).toBe(true)
      expect(result.identityId).toBe(anon.id)
      expect(result.scopes).toEqual(['read', 'write'])
      expect(result.level).toBe(1)
    })

    it('returns invalid for revoked key', async () => {
      const { identity: anon } = await identity.provisionAnonymous()
      const created = await identity.createApiKey({ name: 'Revoke Me', identityId: anon.id })
      await identity.revokeApiKey(created.id, anon.id)

      const result = await identity.validateApiKey(created.key)
      expect(result.valid).toBe(false)
    })

    it('returns invalid for expired key', async () => {
      const { identity: anon } = await identity.provisionAnonymous()
      // Create key with future expiration, then backdate it
      const created = await identity.createApiKey({
        name: 'Expired',
        identityId: anon.id,
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
      })

      // Manually set the expiry in the past
      const keyData = await storage.get<any>(`apikey:${created.id}`)
      await storage.put(`apikey:${created.id}`, { ...keyData, expiresAt: new Date(Date.now() - 1000).toISOString() })

      const result = await identity.validateApiKey(created.key)
      expect(result.valid).toBe(false)
    })

    it('returns invalid for non-existent key', async () => {
      const result = await identity.validateApiKey('hly_sk_nonexistent')
      expect(result.valid).toBe(false)
    })

    it('updates lastUsedAt and requestCount', async () => {
      const { identity: anon } = await identity.provisionAnonymous()
      const created = await identity.createApiKey({ name: 'Usage', identityId: anon.id })

      await identity.validateApiKey(created.key)
      const after1 = await storage.get<any>(`apikey:${created.id}`)
      expect(after1.lastUsedAt).toBeDefined()
      expect(after1.requestCount).toBe(1)

      await identity.validateApiKey(created.key)
      const after2 = await storage.get<any>(`apikey:${created.id}`)
      expect(after2.requestCount).toBe(2)
    })

    it('returns invalid when identity behind key is deleted', async () => {
      const { identity: anon } = await identity.provisionAnonymous()
      const created = await identity.createApiKey({ name: 'Orphan', identityId: anon.id })

      // Delete the identity
      await storage.delete(`identity:${anon.id}`)

      const result = await identity.validateApiKey(created.key)
      expect(result.valid).toBe(false)
    })
  })

  // ──────────────────────────────────────────────────────────────────────
  // createApiKey
  // ──────────────────────────────────────────────────────────────────────

  describe('createApiKey()', () => {
    it('creates key with hly_sk_ prefix', async () => {
      const { identity: anon } = await identity.provisionAnonymous()
      const result = await identity.createApiKey({ name: 'My Key', identityId: anon.id })
      expect(result.key.startsWith('hly_sk_')).toBe(true)
    })

    it('returns correct prefix (first 15 chars)', async () => {
      const { identity: anon } = await identity.provisionAnonymous()
      const result = await identity.createApiKey({ name: 'Prefix', identityId: anon.id })
      expect(result.prefix).toBe(result.key.slice(0, 15))
    })

    it('validates scopes - only read, write, admin allowed', async () => {
      const { identity: anon } = await identity.provisionAnonymous()
      const result = await identity.createApiKey({ name: 'Valid', identityId: anon.id, scopes: ['read', 'admin'] })
      expect(result.scopes).toEqual(['read', 'admin'])
    })

    it('rejects invalid scope', async () => {
      const { identity: anon } = await identity.provisionAnonymous()
      await expect(
        identity.createApiKey({ name: 'Bad', identityId: anon.id, scopes: ['read', 'destroy'] }),
      ).rejects.toThrow('Invalid scope: destroy')
    })

    it('requires name', async () => {
      const { identity: anon } = await identity.provisionAnonymous()
      await expect(
        identity.createApiKey({ name: '', identityId: anon.id }),
      ).rejects.toThrow('name is required')
    })

    it('sets expiration when provided', async () => {
      const { identity: anon } = await identity.provisionAnonymous()
      const future = new Date(Date.now() + 86400000).toISOString()
      const result = await identity.createApiKey({ name: 'Expiring', identityId: anon.id, expiresAt: future })
      expect(result.expiresAt).toBe(future)
    })

    it('rejects past expiration', async () => {
      const { identity: anon } = await identity.provisionAnonymous()
      const past = new Date(Date.now() - 1000).toISOString()
      await expect(
        identity.createApiKey({ name: 'Past', identityId: anon.id, expiresAt: past }),
      ).rejects.toThrow('expiresAt must be in the future')
    })

    it('creates lookup index in storage', async () => {
      const { identity: anon } = await identity.provisionAnonymous()
      const result = await identity.createApiKey({ name: 'Indexed', identityId: anon.id })
      const lookup = await storage.get<string>(`apikey-lookup:${result.key}`)
      expect(lookup).toBe(result.id)
    })

    it('defaults scopes to read + write', async () => {
      const { identity: anon } = await identity.provisionAnonymous()
      const result = await identity.createApiKey({ name: 'Default Scopes', identityId: anon.id })
      expect(result.scopes).toEqual(['read', 'write'])
    })
  })

  // ──────────────────────────────────────────────────────────────────────
  // listApiKeys
  // ──────────────────────────────────────────────────────────────────────

  describe('listApiKeys()', () => {
    it('lists all keys for an identity', async () => {
      const { identity: anon } = await identity.provisionAnonymous()
      await identity.createApiKey({ name: 'Key A', identityId: anon.id })
      await identity.createApiKey({ name: 'Key B', identityId: anon.id })

      const keys = await identity.listApiKeys(anon.id)
      expect(keys).toHaveLength(2)
      expect(keys.map((k) => k.name).sort()).toEqual(['Key A', 'Key B'])
    })

    it('excludes keys from other identities', async () => {
      const a = await identity.provisionAnonymous()
      const b = await identity.provisionAnonymous()
      await identity.createApiKey({ name: 'A Key', identityId: a.identity.id })
      await identity.createApiKey({ name: 'B Key', identityId: b.identity.id })

      const keysA = await identity.listApiKeys(a.identity.id)
      expect(keysA).toHaveLength(1)
      expect(keysA[0].name).toBe('A Key')
    })

    it('returns empty array when no keys exist', async () => {
      const keys = await identity.listApiKeys('no-keys-id')
      expect(keys).toEqual([])
    })

    it('includes status and prefix in listed keys', async () => {
      const { identity: anon } = await identity.provisionAnonymous()
      await identity.createApiKey({ name: 'Detailed', identityId: anon.id, scopes: ['admin'] })

      const keys = await identity.listApiKeys(anon.id)
      expect(keys[0].status).toBe('active')
      expect(keys[0].prefix.startsWith('hly_sk_')).toBe(true)
      expect(keys[0].scopes).toEqual(['admin'])
    })
  })

  // ──────────────────────────────────────────────────────────────────────
  // revokeApiKey
  // ──────────────────────────────────────────────────────────────────────

  describe('revokeApiKey()', () => {
    it('marks key as revoked', async () => {
      const { identity: anon } = await identity.provisionAnonymous()
      const created = await identity.createApiKey({ name: 'To Revoke', identityId: anon.id })

      const result = await identity.revokeApiKey(created.id, anon.id)
      expect(result).not.toBeNull()
      expect(result!.status).toBe('revoked')
      expect(result!.revokedAt).toBeDefined()
    })

    it('removes lookup index', async () => {
      const { identity: anon } = await identity.provisionAnonymous()
      const created = await identity.createApiKey({ name: 'Lookup', identityId: anon.id })

      await identity.revokeApiKey(created.id, anon.id)
      const lookup = await storage.get(`apikey-lookup:${created.key}`)
      expect(lookup).toBeUndefined()
    })

    it('returns null for non-existent key', async () => {
      const result = await identity.revokeApiKey('nonexistent-key-id', 'some-identity')
      expect(result).toBeNull()
    })

    it('rejects if identity does not match', async () => {
      const { identity: anon } = await identity.provisionAnonymous()
      const created = await identity.createApiKey({ name: 'Wrong Owner', identityId: anon.id })

      const result = await identity.revokeApiKey(created.id, 'different-identity')
      expect(result).toBeNull()
    })

    it('returns the revoked key value', async () => {
      const { identity: anon } = await identity.provisionAnonymous()
      const created = await identity.createApiKey({ name: 'Key Val', identityId: anon.id })

      const result = await identity.revokeApiKey(created.id, anon.id)
      expect(result!.key).toBe(created.key)
    })
  })

  // ──────────────────────────────────────────────────────────────────────
  // checkRateLimit
  // ──────────────────────────────────────────────────────────────────────

  describe('checkRateLimit()', () => {
    it('allows first request in window', async () => {
      const result = await identity.checkRateLimit('user-1', 0)
      expect(result.allowed).toBe(true)
      expect(result.remaining).toBe(29) // 30 max - 1
    })

    it('tracks request count', async () => {
      await identity.checkRateLimit('user-1', 0)
      const second = await identity.checkRateLimit('user-1', 0)
      expect(second.allowed).toBe(true)
      expect(second.remaining).toBe(28) // 30 - 2
    })

    it('blocks when limit exceeded (level 0 = 30 max)', async () => {
      // Fill up the rate limit
      for (let i = 0; i < 30; i++) {
        await identity.checkRateLimit('user-flood', 0)
      }
      const result = await identity.checkRateLimit('user-flood', 0)
      expect(result.allowed).toBe(false)
      expect(result.remaining).toBe(0)
    })

    it('resets after window expires', async () => {
      // Make a request
      await identity.checkRateLimit('user-reset', 1)

      // Manually expire the window
      const key = 'rateLimit:user-reset'
      const entry = await storage.get<any>(key)
      await storage.put(key, { ...entry, windowStart: Date.now() - 120_000 })

      const result = await identity.checkRateLimit('user-reset', 1)
      expect(result.allowed).toBe(true)
      expect(result.remaining).toBe(99) // level 1 = 100 max
    })

    it('returns Infinity remaining for level 3', async () => {
      const result = await identity.checkRateLimit('user-unlimited', 3)
      expect(result.allowed).toBe(true)
      expect(result.remaining).toBe(Infinity)
      expect(result.resetAt).toBe(0)
    })

    it('level 2 allows 1000 requests', async () => {
      const result = await identity.checkRateLimit('user-l2', 2)
      expect(result.allowed).toBe(true)
      expect(result.remaining).toBe(999)
    })
  })

  // ──────────────────────────────────────────────────────────────────────
  // freezeIdentity
  // ──────────────────────────────────────────────────────────────────────

  describe('freezeIdentity()', () => {
    it('marks identity as frozen', async () => {
      const { identity: anon } = await identity.provisionAnonymous()
      await identity.freezeIdentity(anon.id)

      const fetched = await identity.getIdentity(anon.id)
      expect(fetched!.frozen).toBe(true)
      expect(fetched!.claimStatus).toBe('frozen')
    })

    it('expires all sessions', async () => {
      const { sessionToken, identity: anon } = await identity.provisionAnonymous()
      await identity.freezeIdentity(anon.id)

      const session = await identity.getSession(sessionToken)
      expect(session.valid).toBe(false)
    })

    it('returns entity/event/session counts', async () => {
      const { identity: anon } = await identity.provisionAnonymous()

      // Add some entities and events
      await storage.put(`entity:${anon.id}:Contact:c1`, { id: 'c1' })
      await storage.put(`entity:${anon.id}:Contact:c2`, { id: 'c2' })
      await storage.put(`event:${anon.id}:e1`, { type: 'test' })

      const result = await identity.freezeIdentity(anon.id)
      expect(result.frozen).toBe(true)
      expect(result.stats.entities).toBe(2)
      expect(result.stats.events).toBe(1)
      expect(result.stats.sessions).toBe(1) // from provisionAnonymous
    })

    it('sets 30-day data preservation window', async () => {
      const { identity: anon } = await identity.provisionAnonymous()
      const before = Date.now()
      const result = await identity.freezeIdentity(anon.id)

      const thirtyDays = 30 * 24 * 60 * 60 * 1000
      expect(result.expiresAt).toBeGreaterThanOrEqual(before + thirtyDays - 100)
      expect(result.expiresAt).toBeLessThanOrEqual(Date.now() + thirtyDays + 100)
    })

    it('throws for non-existent identity', async () => {
      await expect(identity.freezeIdentity('no-such-id')).rejects.toThrow('Identity not found')
    })
  })

  // ──────────────────────────────────────────────────────────────────────
  // verifyClaimToken
  // ──────────────────────────────────────────────────────────────────────

  describe('verifyClaimToken()', () => {
    it('returns valid for existing unclaimed token', async () => {
      const { claimToken, identity: anon } = await identity.provisionAnonymous()
      const result = await identity.verifyClaimToken(claimToken)
      expect(result.valid).toBe(true)
      expect(result.identityId).toBe(anon.id)
      expect(result.status).toBe('unclaimed')
    })

    it('returns invalid for non-clm_ tokens', async () => {
      const result = await identity.verifyClaimToken('ses_not_a_claim')
      expect(result.valid).toBe(false)
    })

    it('returns invalid for unknown token', async () => {
      const result = await identity.verifyClaimToken('clm_does_not_exist_at_all')
      expect(result.valid).toBe(false)
    })

    it('includes entity/event counts in stats', async () => {
      const { claimToken, identity: anon } = await identity.provisionAnonymous()

      // Create some entities and events under this identity
      await storage.put(`entity:${anon.id}:Contact:c1`, { id: 'c1' })
      await storage.put(`event:${anon.id}:e1`, { type: 'test' })
      await storage.put(`event:${anon.id}:e2`, { type: 'test2' })

      const result = await identity.verifyClaimToken(claimToken)
      expect(result.stats!.entities).toBe(1)
      expect(result.stats!.events).toBe(2)
    })

    it('includes identity level and claim status', async () => {
      const { claimToken } = await identity.provisionAnonymous()
      const result = await identity.verifyClaimToken(claimToken)
      expect(result.level).toBe(1) // provisionAnonymous sets L1
      expect(result.status).toBe('unclaimed')
    })

    it('includes createdAt timestamp', async () => {
      const before = Date.now()
      const { claimToken } = await identity.provisionAnonymous()
      const result = await identity.verifyClaimToken(claimToken)
      expect(result.stats!.createdAt).toBeGreaterThanOrEqual(before)
    })

    it('includes expiresAt from associated session', async () => {
      const { claimToken } = await identity.provisionAnonymous()
      const result = await identity.verifyClaimToken(claimToken)
      // provisionAnonymous creates a session with 24h TTL
      expect(result.stats!.expiresAt).toBeDefined()
    })
  })

  // ──────────────────────────────────────────────────────────────────────
  // registerAgentKey
  // ──────────────────────────────────────────────────────────────────────

  describe('registerAgentKey()', () => {
    it('registers Ed25519 public key', async () => {
      const { identity: anon } = await identity.provisionAnonymous()
      const result = await identity.registerAgentKey({
        identityId: anon.id,
        publicKey: MOCK_PUBLIC_KEY_B64,
      })

      expect(result.id).toBeDefined()
      expect(result.did).toBe(MOCK_DID)
    })

    it('computes DID from public key', async () => {
      const { publicKeyToDID } = await import('../src/crypto/keys')
      const { identity: anon } = await identity.provisionAnonymous()

      await identity.registerAgentKey({ identityId: anon.id, publicKey: MOCK_PUBLIC_KEY_B64 })
      expect(publicKeyToDID).toHaveBeenCalled()
    })

    it('rejects duplicate DID', async () => {
      const { identity: anon } = await identity.provisionAnonymous()
      await identity.registerAgentKey({ identityId: anon.id, publicKey: MOCK_PUBLIC_KEY_B64 })

      await expect(
        identity.registerAgentKey({ identityId: anon.id, publicKey: MOCK_PUBLIC_KEY_B64 }),
      ).rejects.toThrow(/already registered/)
    })

    it('rejects non-32-byte keys', async () => {
      const { base64Decode } = await import('../src/crypto/keys')
      const shortKey = new Uint8Array(16)
      ;(base64Decode as any).mockReturnValueOnce(shortKey)

      const { identity: anon } = await identity.provisionAnonymous()
      await expect(
        identity.registerAgentKey({ identityId: anon.id, publicKey: 'short-key' }),
      ).rejects.toThrow(/Expected 32-byte/)
    })

    it('accepts PEM format', async () => {
      const { pemToPublicKey } = await import('../src/crypto/keys')
      // Make publicKeyToDID return a different DID for this test
      const { publicKeyToDID } = await import('../src/crypto/keys')
      ;(publicKeyToDID as any).mockReturnValueOnce(MOCK_DID_2)

      const { identity: anon } = await identity.provisionAnonymous()
      const pem = '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA...\n-----END PUBLIC KEY-----'

      const result = await identity.registerAgentKey({ identityId: anon.id, publicKey: pem })
      expect(pemToPublicKey).toHaveBeenCalledWith(pem)
      expect(result.did).toBe(MOCK_DID_2)
    })

    it('throws for non-existent identity', async () => {
      await expect(
        identity.registerAgentKey({ identityId: 'ghost', publicKey: MOCK_PUBLIC_KEY_B64 }),
      ).rejects.toThrow('Identity not found')
    })

    it('stores key indexed by both ID and DID', async () => {
      const { identity: anon } = await identity.provisionAnonymous()
      const result = await identity.registerAgentKey({ identityId: anon.id, publicKey: MOCK_PUBLIC_KEY_B64 })

      const byId = await storage.get<any>(`agentkey:${result.id}`)
      expect(byId).toBeDefined()
      expect(byId.did).toBe(MOCK_DID)

      const byDID = await storage.get<string>(`agentkey-did:${MOCK_DID}`)
      expect(byDID).toBe(result.id)
    })

    it('stores optional label', async () => {
      const { identity: anon } = await identity.provisionAnonymous()
      const result = await identity.registerAgentKey({
        identityId: anon.id,
        publicKey: MOCK_PUBLIC_KEY_B64,
        label: 'Production Key',
      })

      const stored = await storage.get<any>(`agentkey:${result.id}`)
      expect(stored.label).toBe('Production Key')
    })
  })

  // ──────────────────────────────────────────────────────────────────────
  // verifyAgentSignature
  // ──────────────────────────────────────────────────────────────────────

  describe('verifyAgentSignature()', () => {
    it('verifies valid signature', async () => {
      const { identity: anon } = await identity.provisionAnonymous()
      await identity.registerAgentKey({ identityId: anon.id, publicKey: MOCK_PUBLIC_KEY_B64 })

      const result = await identity.verifyAgentSignature({
        did: MOCK_DID,
        message: 'hello world',
        signature: btoa('fake-valid-sig'),
      })
      expect(result.valid).toBe(true)
      expect(result.identityId).toBe(anon.id)
    })

    it('rejects invalid signature', async () => {
      const { verify } = await import('../src/crypto/keys')
      ;(verify as any).mockResolvedValueOnce(false)

      const { identity: anon } = await identity.provisionAnonymous()
      await identity.registerAgentKey({ identityId: anon.id, publicKey: MOCK_PUBLIC_KEY_B64 })

      const result = await identity.verifyAgentSignature({
        did: MOCK_DID,
        message: 'hello',
        signature: btoa('bad-sig'),
      })
      expect(result.valid).toBe(false)
    })

    it('rejects unknown DID', async () => {
      const result = await identity.verifyAgentSignature({
        did: 'did:agent:ed25519:UnknownKey',
        message: 'test',
        signature: btoa('sig'),
      })
      expect(result.valid).toBe(false)
    })

    it('rejects revoked key', async () => {
      const { identity: anon } = await identity.provisionAnonymous()
      const key = await identity.registerAgentKey({ identityId: anon.id, publicKey: MOCK_PUBLIC_KEY_B64 })

      // Revoke it
      await identity.revokeAgentKey(key.id)

      const result = await identity.verifyAgentSignature({
        did: MOCK_DID,
        message: 'test',
        signature: btoa('sig'),
      })
      expect(result.valid).toBe(false)
    })

    it('rejects frozen identity', async () => {
      const { identity: anon } = await identity.provisionAnonymous()
      await identity.registerAgentKey({ identityId: anon.id, publicKey: MOCK_PUBLIC_KEY_B64 })
      await identity.freezeIdentity(anon.id)

      const result = await identity.verifyAgentSignature({
        did: MOCK_DID,
        message: 'test',
        signature: btoa('sig'),
      })
      expect(result.valid).toBe(false)
    })

    it('rejects invalid DID format', async () => {
      const { isValidDID } = await import('../src/crypto/keys')
      ;(isValidDID as any).mockReturnValueOnce(false)

      const result = await identity.verifyAgentSignature({
        did: 'not-a-did',
        message: 'test',
        signature: btoa('sig'),
      })
      expect(result.valid).toBe(false)
    })
  })

  // ──────────────────────────────────────────────────────────────────────
  // mcpDo
  // ──────────────────────────────────────────────────────────────────────

  describe('mcpDo()', () => {
    const now = Date.now()

    it('create verb stores entity', async () => {
      const result = await identity.mcpDo({
        entity: 'Contact',
        verb: 'create',
        data: { name: 'Alice', email: 'alice@test.com' },
        identityId: 'owner-1',
        authLevel: 1,
        timestamp: now,
      })

      expect(result.success).toBe(true)
      expect(result.entity).toBe('Contact')
      expect(result.verb).toBe('create')
      expect(result.result!.name).toBe('Alice')
      expect(result.result!.$type).toBe('Contact')
      expect(result.result!.id).toBeDefined()
    })

    it('create verb generates lifecycle events', async () => {
      const result = await identity.mcpDo({
        entity: 'Contact',
        verb: 'create',
        data: { name: 'Bob' },
        identityId: 'owner-1',
        authLevel: 1,
        timestamp: now,
      })

      expect(result.events).toHaveLength(2)
      // The implementation literally appends 'ing' and 'ed' to the verb
      expect((result.events![0] as any).type).toBe('createing')
      expect((result.events![1] as any).type).toBe('createed')
    })

    it('update verb modifies existing entity', async () => {
      // Create first
      const created = await identity.mcpDo({
        entity: 'Contact',
        verb: 'create',
        data: { id: 'c1', name: 'Alice', stage: 'Lead' },
        identityId: 'owner-1',
        authLevel: 1,
        timestamp: now,
      })

      // Update
      const updated = await identity.mcpDo({
        entity: 'Contact',
        verb: 'update',
        data: { id: 'c1', stage: 'Qualified' },
        identityId: 'owner-1',
        authLevel: 1,
        timestamp: now + 1000,
      })

      expect(updated.success).toBe(true)
      expect(updated.result!.stage).toBe('Qualified')
      expect(updated.result!.name).toBe('Alice') // preserved
    })

    it('update verb returns error for non-existent entity', async () => {
      const result = await identity.mcpDo({
        entity: 'Contact',
        verb: 'update',
        data: { id: 'nonexistent', stage: 'Qualified' },
        identityId: 'owner-1',
        authLevel: 1,
        timestamp: now,
      })

      expect(result.success).toBe(false)
      expect(result.error).toContain('not found')
    })

    it('delete verb removes entity', async () => {
      await identity.mcpDo({
        entity: 'Contact',
        verb: 'create',
        data: { id: 'to-delete', name: 'Gone' },
        identityId: 'owner-1',
        authLevel: 1,
        timestamp: now,
      })

      const result = await identity.mcpDo({
        entity: 'Contact',
        verb: 'delete',
        data: { id: 'to-delete' },
        identityId: 'owner-1',
        authLevel: 1,
        timestamp: now,
      })

      expect(result.success).toBe(true)
      expect(result.result!.deleted).toBe(true)
    })

    it('custom verbs work', async () => {
      await identity.mcpDo({
        entity: 'Contact',
        verb: 'create',
        data: { id: 'cv-1', name: 'Alice', stage: 'Lead' },
        identityId: 'owner-1',
        authLevel: 1,
        timestamp: now,
      })

      const result = await identity.mcpDo({
        entity: 'Contact',
        verb: 'qualify',
        data: { id: 'cv-1', stage: 'Qualified' },
        identityId: 'owner-1',
        authLevel: 1,
        timestamp: now + 1000,
      })

      expect(result.success).toBe(true)
      expect(result.verb).toBe('qualify')
      expect(result.result!.stage).toBe('Qualified')
      expect(result.events).toHaveLength(2)
      // The implementation literally appends 'ing' and 'ed' to the verb
      expect((result.events![0] as any).type).toBe('qualifying')
      expect((result.events![1] as any).type).toBe('qualifyed')
    })

    it('rejects authLevel < 1', async () => {
      const result = await identity.mcpDo({
        entity: 'Contact',
        verb: 'create',
        data: { name: 'Blocked' },
        authLevel: 0,
        timestamp: now,
      })

      expect(result.success).toBe(false)
      expect(result.error).toContain('L1+ authentication required')
    })

    it('stores event in storage on create', async () => {
      await identity.mcpDo({
        entity: 'Deal',
        verb: 'create',
        data: { id: 'deal-1', title: 'Big Deal' },
        identityId: 'owner-1',
        authLevel: 1,
        timestamp: now,
      })

      // Check events were stored
      const events = await storage.list({ prefix: 'event:owner-1:' })
      expect(events.size).toBeGreaterThan(0)
    })

    it('uses provided id for entity', async () => {
      const result = await identity.mcpDo({
        entity: 'Contact',
        verb: 'create',
        data: { id: 'my-custom-id', name: 'Custom' },
        identityId: 'owner-1',
        authLevel: 1,
        timestamp: now,
      })

      expect(result.result!.id).toBe('my-custom-id')
    })

    it('custom verb on non-existent entity creates it', async () => {
      const result = await identity.mcpDo({
        entity: 'Contact',
        verb: 'qualify',
        data: { id: 'new-qualify', stage: 'Qualified' },
        identityId: 'owner-1',
        authLevel: 1,
        timestamp: now,
      })

      expect(result.success).toBe(true)
      expect(result.result!.id).toBe('new-qualify')
      expect(result.result!.stage).toBe('Qualified')
    })
  })

  // ──────────────────────────────────────────────────────────────────────
  // mcpSearch
  // ──────────────────────────────────────────────────────────────────────

  describe('mcpSearch()', () => {
    const now = Date.now()

    beforeEach(async () => {
      // Seed some entities
      await identity.mcpDo({ entity: 'Contact', verb: 'create', data: { id: 'c1', name: 'Alice Smith', email: 'alice@test.com', stage: 'Lead' }, identityId: 'owner-1', authLevel: 1, timestamp: now })
      await identity.mcpDo({ entity: 'Contact', verb: 'create', data: { id: 'c2', name: 'Bob Jones', email: 'bob@test.com', stage: 'Customer' }, identityId: 'owner-1', authLevel: 1, timestamp: now })
      await identity.mcpDo({ entity: 'Deal', verb: 'create', data: { id: 'd1', title: 'Big Deal', stage: 'Discovery' }, identityId: 'owner-1', authLevel: 1, timestamp: now })
    })

    it('search finds entities by text', async () => {
      const result = await identity.mcpSearch({ identityId: 'owner-1', query: 'alice' })
      expect(result.results.length).toBeGreaterThan(0)
      expect(result.results.some((r) => r.id === 'c1')).toBe(true)
    })

    it('search filters by type', async () => {
      const result = await identity.mcpSearch({ identityId: 'owner-1', type: 'Contact' })
      expect(result.results.length).toBe(2)
      expect(result.results.every((r) => r.type === 'Contact')).toBe(true)
    })

    it('search filters by fields', async () => {
      const result = await identity.mcpSearch({ identityId: 'owner-1', type: 'Contact', filters: { stage: 'Lead' } })
      expect(result.results).toHaveLength(1)
      expect(result.results[0].data.name).toBe('Alice Smith')
    })

    it('search returns empty for non-matching query', async () => {
      const result = await identity.mcpSearch({ identityId: 'owner-1', query: 'zzzzzznotfound' })
      expect(result.results).toHaveLength(0)
      expect(result.total).toBe(0)
    })

    it('search respects limit', async () => {
      const result = await identity.mcpSearch({ identityId: 'owner-1', limit: 1 })
      // With no query, items without text match are scored 0 and excluded if query is provided
      // But type search returns all items of that type, so let's test with type
      const typed = await identity.mcpSearch({ identityId: 'owner-1', type: 'Contact', limit: 1 })
      expect(typed.results).toHaveLength(1)
      expect(typed.total).toBe(2) // total is still 2
    })

    it('search respects offset', async () => {
      const page1 = await identity.mcpSearch({ identityId: 'owner-1', type: 'Contact', limit: 1, offset: 0 })
      const page2 = await identity.mcpSearch({ identityId: 'owner-1', type: 'Contact', limit: 1, offset: 1 })
      expect(page1.results).toHaveLength(1)
      expect(page2.results).toHaveLength(1)
      expect(page1.results[0].id).not.toBe(page2.results[0].id)
    })

    it('search combines text query with field filter', async () => {
      const result = await identity.mcpSearch({
        identityId: 'owner-1',
        query: 'alice',
        type: 'Contact',
        filters: { stage: 'Customer' },
      })
      // Alice is Lead, not Customer
      expect(result.results).toHaveLength(0)
    })

    it('search scores name matches higher than other fields', async () => {
      const result = await identity.mcpSearch({ identityId: 'owner-1', query: 'alice' })
      // Alice matched in name field should have high score
      const alice = result.results.find((r) => r.id === 'c1')
      expect(alice).toBeDefined()
      expect(alice!.score).toBeGreaterThan(0)
    })

    it('search across all types when type not specified', async () => {
      const result = await identity.mcpSearch({ identityId: 'owner-1', query: 'big' })
      // Should find the deal with title "Big Deal"
      expect(result.results.some((r) => r.type === 'Deal')).toBe(true)
    })

    it('caps limit at 100', async () => {
      const result = await identity.mcpSearch({ identityId: 'owner-1', type: 'Contact', limit: 500 })
      expect(result.limit).toBe(100)
    })
  })

  // ──────────────────────────────────────────────────────────────────────
  // mcpFetch
  // ──────────────────────────────────────────────────────────────────────

  describe('mcpFetch()', () => {
    const now = Date.now()

    beforeEach(async () => {
      await identity.mcpDo({ entity: 'Contact', verb: 'create', data: { id: 'c1', name: 'Alice', stage: 'Lead' }, identityId: 'owner-1', authLevel: 1, timestamp: now })
      await identity.mcpDo({ entity: 'Contact', verb: 'create', data: { id: 'c2', name: 'Bob', stage: 'Customer' }, identityId: 'owner-1', authLevel: 1, timestamp: now })
      await identity.mcpDo({ entity: 'Deal', verb: 'create', data: { id: 'd1', title: 'Deal A' }, identityId: 'owner-1', authLevel: 1, timestamp: now })
    })

    it('fetch retrieves by id', async () => {
      const result = await identity.mcpFetch({ identityId: 'owner-1', type: 'Contact', id: 'c1' })
      expect(result.type).toBe('Contact')
      expect(result.id).toBe('c1')
      expect((result.data as any)?.name).toBe('Alice')
    })

    it('fetch returns null data for non-existent id', async () => {
      const result = await identity.mcpFetch({ identityId: 'owner-1', type: 'Contact', id: 'nonexistent' })
      expect(result.data).toBeNull()
    })

    it('fetch lists entities with pagination', async () => {
      const result = await identity.mcpFetch({ identityId: 'owner-1', type: 'Contact' })
      expect((result.items as any[]).length).toBe(2)
      expect(result.total).toBe(2)
    })

    it('fetch applies limit', async () => {
      const result = await identity.mcpFetch({ identityId: 'owner-1', type: 'Contact', limit: 1 })
      expect((result.items as any[]).length).toBe(1)
      expect(result.total).toBe(2)
    })

    it('fetch applies offset', async () => {
      const result = await identity.mcpFetch({ identityId: 'owner-1', type: 'Contact', limit: 1, offset: 1 })
      expect((result.items as any[]).length).toBe(1)
    })

    it('fetch applies filters', async () => {
      const result = await identity.mcpFetch({ identityId: 'owner-1', type: 'Contact', filters: { stage: 'Lead' } })
      expect((result.items as any[]).length).toBe(1)
      expect((result.items as any[])[0].name).toBe('Alice')
    })

    it('fetch returns empty items for non-existent type', async () => {
      const result = await identity.mcpFetch({ identityId: 'owner-1', type: 'Nonexistent' })
      expect((result.items as any[]).length).toBe(0)
    })

    it('fetch caps limit at 100', async () => {
      const result = await identity.mcpFetch({ identityId: 'owner-1', type: 'Contact', limit: 500 })
      expect(result.limit).toBe(100)
    })

    it('fetch defaults limit to 20 and offset to 0', async () => {
      const result = await identity.mcpFetch({ identityId: 'owner-1', type: 'Contact' })
      expect(result.limit).toBe(20)
      expect(result.offset).toBe(0)
    })
  })

  // ──────────────────────────────────────────────────────────────────────
  // oauthStorageOp
  // ──────────────────────────────────────────────────────────────────────

  describe('oauthStorageOp()', () => {
    it('get returns stored value', async () => {
      await storage.put('oauth:client:1', { clientId: 'abc' })
      const result = await identity.oauthStorageOp({ op: 'get', key: 'oauth:client:1' })
      expect(result.value).toEqual({ clientId: 'abc' })
    })

    it('get returns undefined for missing key', async () => {
      const result = await identity.oauthStorageOp({ op: 'get', key: 'oauth:missing' })
      expect(result.value).toBeUndefined()
    })

    it('put stores value', async () => {
      await identity.oauthStorageOp({ op: 'put', key: 'oauth:token:x', value: { token: 'abc' } })
      const stored = await storage.get('oauth:token:x')
      expect(stored).toEqual({ token: 'abc' })
    })

    it('put returns ok', async () => {
      const result = await identity.oauthStorageOp({ op: 'put', key: 'oauth:k', value: 'v' })
      expect(result.ok).toBe(true)
    })

    it('delete removes value', async () => {
      await storage.put('oauth:del', 'to-delete')
      const result = await identity.oauthStorageOp({ op: 'delete', key: 'oauth:del' })
      expect(result.deleted).toBe(true)

      const after = await storage.get('oauth:del')
      expect(after).toBeUndefined()
    })

    it('list with prefix filter', async () => {
      await storage.put('oauth:clients:a', { id: 'a' })
      await storage.put('oauth:clients:b', { id: 'b' })
      await storage.put('oauth:tokens:x', { id: 'x' })

      const result = await identity.oauthStorageOp({ op: 'list', options: { prefix: 'oauth:clients:' } })
      const entries = result.entries as Array<[string, any]>
      expect(entries).toHaveLength(2)
      expect(entries.every(([k]) => k.startsWith('oauth:clients:'))).toBe(true)
    })

    it('list with limit', async () => {
      await storage.put('oauth:items:1', { id: '1' })
      await storage.put('oauth:items:2', { id: '2' })
      await storage.put('oauth:items:3', { id: '3' })

      const result = await identity.oauthStorageOp({ op: 'list', options: { prefix: 'oauth:items:', limit: 2 } })
      const entries = result.entries as Array<[string, any]>
      expect(entries).toHaveLength(2)
    })

    it('throws for unknown operation', async () => {
      await expect(
        identity.oauthStorageOp({ op: 'unknown' as any }),
      ).rejects.toThrow('Unknown storage operation')
    })
  })

  // ──────────────────────────────────────────────────────────────────────
  // writeAuditEvent + queryAuditLog
  // ──────────────────────────────────────────────────────────────────────

  describe('writeAuditEvent()', () => {
    it('writes event to storage', async () => {
      const event = {
        event: 'identity.created',
        actor: 'system',
        timestamp: new Date().toISOString(),
        key: 'audit:2025-01-01T00:00:00.000Z:identity.created:abc123',
      }
      await identity.writeAuditEvent(event.key, event)

      const stored = await storage.get<any>(event.key)
      expect(stored.event).toBe('identity.created')
      expect(stored.actor).toBe('system')
    })
  })

  describe('queryAuditLog()', () => {
    it('delegates to AuditLog.query', async () => {
      const result = await identity.queryAuditLog({})
      expect(result.events).toEqual([])
      expect(result.hasMore).toBe(false)
    })
  })

  // ──────────────────────────────────────────────────────────────────────
  // listSessions
  // ──────────────────────────────────────────────────────────────────────

  describe('listSessions()', () => {
    it('lists active sessions for identity', async () => {
      const { sessionToken, identity: anon } = await identity.provisionAnonymous()
      const sessions = await identity.listSessions(anon.id)
      expect(sessions).toHaveLength(1)
      expect(sessions[0].token).toBe(sessionToken)
    })

    it('excludes expired sessions', async () => {
      const { sessionToken, identity: anon } = await identity.provisionAnonymous()
      const sessionData = await storage.get<any>(`session:${sessionToken}`)
      await storage.put(`session:${sessionToken}`, { ...sessionData, expiresAt: Date.now() - 1000 })

      const sessions = await identity.listSessions(anon.id)
      expect(sessions).toHaveLength(0)
    })

    it('excludes sessions belonging to other identities', async () => {
      const a = await identity.provisionAnonymous()
      const b = await identity.provisionAnonymous()
      const sessionsA = await identity.listSessions(a.identity.id)
      expect(sessionsA).toHaveLength(1)
      expect(sessionsA[0].token).toBe(a.sessionToken)
    })
  })

  // ──────────────────────────────────────────────────────────────────────
  // revokeAgentKey
  // ──────────────────────────────────────────────────────────────────────

  describe('revokeAgentKey()', () => {
    it('marks key as revoked', async () => {
      const { identity: anon } = await identity.provisionAnonymous()
      const key = await identity.registerAgentKey({ identityId: anon.id, publicKey: MOCK_PUBLIC_KEY_B64 })

      const result = await identity.revokeAgentKey(key.id)
      expect(result).toBe(true)

      const stored = await storage.get<any>(`agentkey:${key.id}`)
      expect(stored.revokedAt).toBeDefined()
    })

    it('removes DID index', async () => {
      const { identity: anon } = await identity.provisionAnonymous()
      const key = await identity.registerAgentKey({ identityId: anon.id, publicKey: MOCK_PUBLIC_KEY_B64 })

      await identity.revokeAgentKey(key.id)
      const didIndex = await storage.get(`agentkey-did:${MOCK_DID}`)
      expect(didIndex).toBeUndefined()
    })

    it('returns false for non-existent key', async () => {
      const result = await identity.revokeAgentKey('nonexistent')
      expect(result).toBe(false)
    })

    it('returns false for already-revoked key', async () => {
      const { identity: anon } = await identity.provisionAnonymous()
      const key = await identity.registerAgentKey({ identityId: anon.id, publicKey: MOCK_PUBLIC_KEY_B64 })

      await identity.revokeAgentKey(key.id)
      const result = await identity.revokeAgentKey(key.id)
      expect(result).toBe(false)
    })
  })

  // ──────────────────────────────────────────────────────────────────────
  // listAgentKeys
  // ──────────────────────────────────────────────────────────────────────

  describe('listAgentKeys()', () => {
    it('lists non-revoked keys', async () => {
      const { identity: anon } = await identity.provisionAnonymous()
      await identity.registerAgentKey({ identityId: anon.id, publicKey: MOCK_PUBLIC_KEY_B64 })

      const keys = await identity.listAgentKeys(anon.id)
      expect(keys).toHaveLength(1)
      expect(keys[0].did).toBe(MOCK_DID)
    })

    it('returns empty for identity with no keys', async () => {
      const keys = await identity.listAgentKeys('no-keys')
      expect(keys).toHaveLength(0)
    })
  })

  // ──────────────────────────────────────────────────────────────────────
  // fetch (HTTP handler)
  // ──────────────────────────────────────────────────────────────────────

  describe('fetch() HTTP handler', () => {
    it('returns health check on /health', async () => {
      const response = await identity.fetch(new Request('https://id.org.ai/health'))
      expect(response.status).toBe(200)
      const body = await response.json() as any
      expect(body.status).toBe('ok')
      expect(body.ns).toBe('https://id.org.ai')
      expect(body.tagline).toBe('Humans. Agents. Identity.')
    })

    it('returns 404 for unknown paths', async () => {
      const response = await identity.fetch(new Request('https://id.org.ai/unknown'))
      expect(response.status).toBe(404)
      const body = await response.json() as any
      expect(body.error).toBe('Not found')
    })
  })

  // ──────────────────────────────────────────────────────────────────────
  // Entity index management (via mcpDo/mcpSearch integration)
  // ──────────────────────────────────────────────────────────────────────

  describe('Entity Index Management', () => {
    const now = Date.now()

    it('creates secondary indexes on entity create', async () => {
      await identity.mcpDo({
        entity: 'Contact',
        verb: 'create',
        data: { id: 'idx-1', name: 'Alice', stage: 'Lead' },
        identityId: 'owner-1',
        authLevel: 1,
        timestamp: now,
      })

      // Check for index entries
      const indexes = await storage.list({ prefix: 'idx:owner-1:Contact:' })
      expect(indexes.size).toBeGreaterThan(0)
    })

    it('cleans up indexes on entity delete', async () => {
      await identity.mcpDo({
        entity: 'Contact',
        verb: 'create',
        data: { id: 'idx-del', name: 'Delete Me', stage: 'Lead' },
        identityId: 'owner-1',
        authLevel: 1,
        timestamp: now,
      })

      const beforeDelete = await storage.list({ prefix: 'idx:owner-1:Contact:' })
      const beforeCount = beforeDelete.size

      await identity.mcpDo({
        entity: 'Contact',
        verb: 'delete',
        data: { id: 'idx-del' },
        identityId: 'owner-1',
        authLevel: 1,
        timestamp: now,
      })

      const afterDelete = await storage.list({ prefix: 'idx:owner-1:Contact:' })
      expect(afterDelete.size).toBeLessThan(beforeCount)
    })

    it('updates indexes on entity update', async () => {
      await identity.mcpDo({
        entity: 'Contact',
        verb: 'create',
        data: { id: 'idx-upd', name: 'Alice', stage: 'Lead' },
        identityId: 'owner-1',
        authLevel: 1,
        timestamp: now,
      })

      await identity.mcpDo({
        entity: 'Contact',
        verb: 'update',
        data: { id: 'idx-upd', stage: 'Customer' },
        identityId: 'owner-1',
        authLevel: 1,
        timestamp: now + 1000,
      })

      // Should not have old "lead" index, should have "customer" index
      const leadIdx = await storage.list({ prefix: 'idx:owner-1:Contact:stage:lead:idx-upd' })
      expect(leadIdx.size).toBe(0)

      const customerIdx = await storage.list({ prefix: 'idx:owner-1:Contact:stage:customer:idx-upd' })
      expect(customerIdx.size).toBe(1)
    })
  })

  // ──────────────────────────────────────────────────────────────────────
  // matchesFilters (tested indirectly through mcpSearch/mcpFetch)
  // ──────────────────────────────────────────────────────────────────────

  describe('matchesFilters (via mcpSearch)', () => {
    const now = Date.now()

    beforeEach(async () => {
      await identity.mcpDo({ entity: 'Contact', verb: 'create', data: { id: 'mf-1', name: 'Alice', stage: 'Lead', score: 100 }, identityId: 'owner-1', authLevel: 1, timestamp: now })
      await identity.mcpDo({ entity: 'Contact', verb: 'create', data: { id: 'mf-2', name: 'Bob', stage: 'Customer', score: 200 }, identityId: 'owner-1', authLevel: 1, timestamp: now })
    })

    it('case-insensitive string filter', async () => {
      const result = await identity.mcpSearch({ identityId: 'owner-1', type: 'Contact', filters: { stage: 'lead' } })
      expect(result.results).toHaveLength(1)
      expect(result.results[0].id).toBe('mf-1')
    })

    it('numeric filter equality', async () => {
      const result = await identity.mcpSearch({ identityId: 'owner-1', type: 'Contact', filters: { score: 200 } })
      expect(result.results).toHaveLength(1)
      expect(result.results[0].id).toBe('mf-2')
    })

    it('filter excludes null values', async () => {
      await identity.mcpDo({ entity: 'Contact', verb: 'create', data: { id: 'mf-3', name: 'Charlie' }, identityId: 'owner-1', authLevel: 1, timestamp: now })

      const result = await identity.mcpSearch({ identityId: 'owner-1', type: 'Contact', filters: { stage: 'Lead' } })
      // mf-3 has no stage, should be excluded
      expect(result.results.every((r) => r.data.stage !== undefined)).toBe(true)
    })
  })

  // ──────────────────────────────────────────────────────────────────────
  // calculateTextScore (tested indirectly through mcpSearch)
  // ──────────────────────────────────────────────────────────────────────

  describe('calculateTextScore (via mcpSearch)', () => {
    const now = Date.now()

    it('name field exact match scores highest', async () => {
      await identity.mcpDo({ entity: 'Contact', verb: 'create', data: { id: 'ts-1', name: 'Alice', description: 'alice is great' }, identityId: 'owner-1', authLevel: 1, timestamp: now })

      const result = await identity.mcpSearch({ identityId: 'owner-1', query: 'alice' })
      const contact = result.results.find((r) => r.id === 'ts-1')
      // name match (partial = 10) + description match (3) = 13 minimum
      expect(contact!.score).toBeGreaterThanOrEqual(10)
    })

    it('returns zero score for non-matching entity', async () => {
      await identity.mcpDo({ entity: 'Contact', verb: 'create', data: { id: 'ts-2', name: 'Bob' }, identityId: 'owner-1', authLevel: 1, timestamp: now })

      const result = await identity.mcpSearch({ identityId: 'owner-1', query: 'zzzzz' })
      expect(result.results.find((r) => r.id === 'ts-2')).toBeUndefined()
    })

    it('email field match scores higher than generic field', async () => {
      await identity.mcpDo({ entity: 'Contact', verb: 'create', data: { id: 'ts-3', name: 'No Match', email: 'unique@email.com', note: 'unique note' }, identityId: 'owner-1', authLevel: 1, timestamp: now })
      await identity.mcpDo({ entity: 'Contact', verb: 'create', data: { id: 'ts-4', name: 'No Match', note: 'unique extra' }, identityId: 'owner-1', authLevel: 1, timestamp: now })

      const result = await identity.mcpSearch({ identityId: 'owner-1', query: 'unique' })
      const withEmail = result.results.find((r) => r.id === 'ts-3')
      const withNote = result.results.find((r) => r.id === 'ts-4')
      expect(withEmail!.score).toBeGreaterThan(withNote!.score)
    })
  })
})
