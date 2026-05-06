import { describe, it, expect, beforeEach } from 'vitest'
import { IdentityServiceImpl } from '../src/server/services/identity/service'
import { AuditServiceImpl } from '../src/server/services/audit/service'
import { MemoryStorageAdapter } from '../src/sdk/storage'
import type { StorageAdapter } from '../src/sdk/storage'
import type { Identity } from '../src/server/services/identity/types'

// ============================================================================
// Fixtures
// ============================================================================

const sampleRaw = {
  id: 'usr_abc123',
  type: 'human' as const,
  name: 'Alice Example',
  email: 'alice@example.com',
  verified: true,
  level: 2,
  claimStatus: 'claimed' as const,
  frozen: false,
  createdAt: 1700000000000,
  updatedAt: 1700000001000,
}

// ============================================================================
// Test Storage Helper
// ============================================================================

function createTestStorage(data: Map<string, unknown> = new Map()): StorageAdapter {
  return {
    async get<T = unknown>(key: string): Promise<T | undefined> {
      return data.get(key) as T | undefined
    },
    async put(key: string, value: unknown): Promise<void> {
      data.set(key, value)
    },
    async delete(key: string): Promise<boolean> {
      return data.delete(key)
    },
    async list<T = unknown>(options?: { prefix?: string; limit?: number; start?: string; reverse?: boolean }): Promise<Map<string, T>> {
      const prefix = options?.prefix ?? ''
      const result = new Map<string, T>()
      for (const [k, v] of data) {
        if (k.startsWith(prefix)) result.set(k, v as T)
      }
      return result
    },
  }
}

// ============================================================================
// Tests
// ============================================================================

describe('IdentityServiceImpl', () => {
  let storage: StorageAdapter
  let backingMap: Map<string, unknown>
  let service: IdentityServiceImpl

  beforeEach(() => {
    backingMap = new Map()
    storage = createTestStorage(backingMap)
    const audit = new AuditServiceImpl({ storage })
    service = new IdentityServiceImpl({ storage, audit })
  })

  // --------------------------------------------------------------------------
  // get()
  // --------------------------------------------------------------------------

  describe('get()', () => {
    it('returns NotFoundError for missing identity', async () => {
      const result = await service.get('usr_missing')
      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error._tag).toBe('NotFoundError')
        expect(result.error.entity).toBe('Identity')
        expect(result.error.id).toBe('usr_missing')
      }
    })

    it('returns identity when it exists', async () => {
      backingMap.set('identity:usr_abc123', sampleRaw)

      const result = await service.get('usr_abc123')
      expect(result.success).toBe(true)
      if (result.success) {
        const identity: Identity = result.data
        expect(identity.id).toBe('usr_abc123')
        expect(identity.type).toBe('human')
        expect(identity.name).toBe('Alice Example')
        expect(identity.email).toBe('alice@example.com')
        expect(identity.verified).toBe(true)
        expect(identity.level).toBe(2)
        expect(identity.claimStatus).toBe('claimed')
        expect(identity.frozen).toBe(false)
        expect(identity.createdAt).toBe(1700000000000)
        expect(identity.updatedAt).toBe(1700000001000)
      }
    })

    it('applies defaults for optional fields when absent', async () => {
      const minimal = { id: 'usr_min', type: 'tenant' as const, name: 'Bot' }
      backingMap.set('identity:usr_min', minimal)

      const result = await service.get('usr_min')
      expect(result.success).toBe(true)
      if (result.success) {
        expect(result.data.verified).toBe(false)
        expect(result.data.level).toBe(0)
        expect(result.data.claimStatus).toBe('unclaimed')
        expect(result.data.frozen).toBe(false)
        expect(typeof result.data.createdAt).toBe('number')
        expect(typeof result.data.updatedAt).toBe('number')
      }
    })
  })

  // --------------------------------------------------------------------------
  // exists()
  // --------------------------------------------------------------------------

  describe('exists()', () => {
    it('returns false for missing identity', async () => {
      const found = await service.exists('usr_missing')
      expect(found).toBe(false)
    })

    it('returns true for existing identity', async () => {
      backingMap.set('identity:usr_abc123', sampleRaw)
      const found = await service.exists('usr_abc123')
      expect(found).toBe(true)
    })
  })

  // --------------------------------------------------------------------------
  // createHuman()
  // --------------------------------------------------------------------------

  describe('createHuman()', () => {
    it('creates a human identity at level 2 / claimed', async () => {
      const result = await service.createHuman({ name: 'Bob Smith', email: 'bob@example.com' })
      expect(result.success).toBe(true)
      if (result.success) {
        const identity = result.data
        expect(identity.type).toBe('human')
        expect(identity.name).toBe('Bob Smith')
        expect(identity.email).toBe('bob@example.com')
        expect(identity.verified).toBe(true)
        expect(identity.level).toBe(2)
        expect(identity.claimStatus).toBe('claimed')
        expect(identity.frozen).toBe(false)
        expect(typeof identity.id).toBe('string')
        expect(identity.id.length).toBeGreaterThan(0)
        expect(typeof identity.createdAt).toBe('number')
      }
    })

    it('stores the identity in storage and creates email index', async () => {
      const result = await service.createHuman({ name: 'Carol', email: 'carol@example.com' })
      expect(result.success).toBe(true)
      if (result.success) {
        const id = result.data.id
        expect(backingMap.has(`identity:${id}`)).toBe(true)
        expect(backingMap.get('idx:email:carol@example.com')).toBe(id)
      }
    })

    it('stores handle index when handle is provided', async () => {
      const result = await service.createHuman({ name: 'Dave', email: 'dave@example.com', handle: 'dave' })
      expect(result.success).toBe(true)
      if (result.success) {
        const id = result.data.id
        expect(backingMap.get('idx:handle:dave')).toBe(id)
        expect(result.data.handle).toBe('dave')
      }
    })

    it('returns ValidationError for empty name', async () => {
      const result = await service.createHuman({ name: '', email: 'test@example.com' })
      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error._tag).toBe('ValidationError')
      }
    })

    it('returns ValidationError for empty email', async () => {
      const result = await service.createHuman({ name: 'Test', email: '' })
      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error._tag).toBe('ValidationError')
      }
    })

    it('returns ConflictError for duplicate email', async () => {
      await service.createHuman({ name: 'First', email: 'dup@example.com' })
      const result = await service.createHuman({ name: 'Second', email: 'dup@example.com' })
      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error._tag).toBe('ConflictError')
      }
    })

    it('returns ConflictError for duplicate handle', async () => {
      await service.createHuman({ name: 'First', email: 'first@example.com', handle: 'shared' })
      const result = await service.createHuman({ name: 'Second', email: 'second@example.com', handle: 'shared' })
      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error._tag).toBe('ConflictError')
      }
    })

    it('email uniqueness check is case-insensitive', async () => {
      await service.createHuman({ name: 'First', email: 'Case@Example.com' })
      const result = await service.createHuman({ name: 'Second', email: 'case@example.com' })
      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error._tag).toBe('ConflictError')
      }
    })
  })

  // --------------------------------------------------------------------------
  // provisionTenant()
  // --------------------------------------------------------------------------

  describe('provisionTenant()', () => {
    it('creates a tenant at level 0 / unclaimed with a clm_ token', async () => {
      const result = await service.provisionTenant({})
      expect(result.success).toBe(true)
      if (result.success) {
        const { identity, claimToken } = result.data
        expect(identity.type).toBe('tenant')
        expect(identity.verified).toBe(false)
        expect(identity.level).toBe(0)
        expect(identity.claimStatus).toBe('unclaimed')
        expect(claimToken).toMatch(/^clm_/)
        expect(typeof identity.id).toBe('string')
      }
    })

    it('uses provided name when given', async () => {
      const result = await service.provisionTenant({ name: 'my-tenant' })
      expect(result.success).toBe(true)
      if (result.success) {
        expect(result.data.identity.name).toBe('my-tenant')
      }
    })

    it('generates anon_ name when no name provided', async () => {
      const result = await service.provisionTenant({})
      expect(result.success).toBe(true)
      if (result.success) {
        expect(result.data.identity.name).toMatch(/^anon_/)
      }
    })

    it('stores the identity in storage', async () => {
      const result = await service.provisionTenant({})
      expect(result.success).toBe(true)
      if (result.success) {
        const id = result.data.identity.id
        expect(backingMap.has(`identity:${id}`)).toBe(true)
      }
    })

    it('generates unique IDs for each provisioned tenant', async () => {
      const r1 = await service.provisionTenant({})
      const r2 = await service.provisionTenant({})
      expect(r1.success && r2.success).toBe(true)
      if (r1.success && r2.success) {
        expect(r1.data.identity.id).not.toBe(r2.data.identity.id)
        expect(r1.data.claimToken).not.toBe(r2.data.claimToken)
      }
    })
  })

  // --------------------------------------------------------------------------
  // getByHandle()
  // --------------------------------------------------------------------------

  describe('getByHandle()', () => {
    it('returns identity by handle', async () => {
      const created = await service.createHuman({ name: 'Eve', email: 'eve@example.com', handle: 'eve' })
      expect(created.success).toBe(true)
      if (created.success) {
        const result = await service.getByHandle('eve')
        expect(result.success).toBe(true)
        if (result.success) {
          expect(result.data.id).toBe(created.data.id)
          expect(result.data.handle).toBe('eve')
        }
      }
    })

    it('is case-insensitive', async () => {
      await service.createHuman({ name: 'Frank', email: 'frank@example.com', handle: 'Frank' })
      const result = await service.getByHandle('frank')
      expect(result.success).toBe(true)
    })

    it('returns NotFoundError for unknown handle', async () => {
      const result = await service.getByHandle('nobody')
      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error._tag).toBe('NotFoundError')
      }
    })
  })

  // --------------------------------------------------------------------------
  // getByEmail()
  // --------------------------------------------------------------------------

  describe('getByEmail()', () => {
    it('returns identity by email', async () => {
      const created = await service.createHuman({ name: 'Grace', email: 'grace@example.com' })
      expect(created.success).toBe(true)
      if (created.success) {
        const result = await service.getByEmail('grace@example.com')
        expect(result.success).toBe(true)
        if (result.success) {
          expect(result.data.id).toBe(created.data.id)
          expect(result.data.email).toBe('grace@example.com')
        }
      }
    })

    it('is case-insensitive', async () => {
      await service.createHuman({ name: 'Hank', email: 'Hank@Example.com' })
      const result = await service.getByEmail('hank@example.com')
      expect(result.success).toBe(true)
    })

    it('returns NotFoundError for unknown email', async () => {
      const result = await service.getByEmail('nobody@example.com')
      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error._tag).toBe('NotFoundError')
      }
    })
  })

  // --------------------------------------------------------------------------
  // getByGitHubUserId()
  // --------------------------------------------------------------------------

  describe('getByGitHubUserId()', () => {
    it('returns identity after GitHub link via update', async () => {
      const created = await service.createHuman({ name: 'Ivy', email: 'ivy@example.com' })
      expect(created.success).toBe(true)
      if (created.success) {
        await service.update(created.data.id, { githubUserId: 'gh_123', githubUsername: 'ivy-gh' })
        const result = await service.getByGitHubUserId('gh_123')
        expect(result.success).toBe(true)
        if (result.success) {
          expect(result.data.id).toBe(created.data.id)
          expect(result.data.githubUserId).toBe('gh_123')
          expect(result.data.githubUsername).toBe('ivy-gh')
        }
      }
    })

    it('returns NotFoundError for unknown GitHub user ID', async () => {
      const result = await service.getByGitHubUserId('gh_unknown')
      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error._tag).toBe('NotFoundError')
      }
    })
  })

  // --------------------------------------------------------------------------
  // getByClaimToken()
  // --------------------------------------------------------------------------

  describe('getByClaimToken()', () => {
    it('returns identity by claim token after provisioning', async () => {
      const created = await service.provisionTenant({ name: 'bot' })
      expect(created.success).toBe(true)
      if (created.success) {
        const result = await service.getByClaimToken(created.data.claimToken)
        expect(result.success).toBe(true)
        if (result.success) {
          expect(result.data.id).toBe(created.data.identity.id)
        }
      }
    })

    it('returns identity by claim token after generic create', async () => {
      const created = await service.create({ type: 'tenant', name: 'bot2' })
      expect(created.success).toBe(true)
      if (created.success) {
        const result = await service.getByClaimToken(created.data.claimToken)
        expect(result.success).toBe(true)
        if (result.success) {
          expect(result.data.id).toBe(created.data.identity.id)
        }
      }
    })

    it('returns NotFoundError for unknown claim token', async () => {
      const result = await service.getByClaimToken('clm_nonexistent')
      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error._tag).toBe('NotFoundError')
      }
    })
  })

  // --------------------------------------------------------------------------
  // update()
  // --------------------------------------------------------------------------

  describe('update()', () => {
    it('updates mutable fields', async () => {
      const created = await service.createHuman({ name: 'Jack', email: 'jack@example.com' })
      expect(created.success).toBe(true)
      if (created.success) {
        const result = await service.update(created.data.id, { name: 'Jack Updated', image: 'https://example.com/jack.png' })
        expect(result.success).toBe(true)
        if (result.success) {
          expect(result.data.name).toBe('Jack Updated')
          expect(result.data.image).toBe('https://example.com/jack.png')
          expect(result.data.email).toBe('jack@example.com')
        }
      }
    })

    it('returns NotFoundError for missing identity', async () => {
      const result = await service.update('usr_missing', { name: 'Ghost' })
      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error._tag).toBe('NotFoundError')
      }
    })

    it('rejects level decrease', async () => {
      const created = await service.createHuman({ name: 'Kate', email: 'kate@example.com' })
      expect(created.success).toBe(true)
      if (created.success) {
        const result = await service.update(created.data.id, { level: 0 })
        expect(result.success).toBe(false)
        if (!result.success) {
          expect(result.error._tag).toBe('ValidationError')
        }
      }
    })

    it('allows level increase', async () => {
      const created = await service.createHuman({ name: 'Leo', email: 'leo@example.com' })
      expect(created.success).toBe(true)
      if (created.success) {
        const result = await service.update(created.data.id, { level: 3 })
        expect(result.success).toBe(true)
        if (result.success) {
          expect(result.data.level).toBe(3)
        }
      }
    })

    it('rejects update on frozen identity', async () => {
      const created = await service.createHuman({ name: 'Mia', email: 'mia@example.com' })
      expect(created.success).toBe(true)
      if (created.success) {
        // manually freeze via storage
        const raw = backingMap.get(`identity:${created.data.id}`) as Record<string, unknown>
        backingMap.set(`identity:${created.data.id}`, { ...raw, frozen: true })
        const result = await service.update(created.data.id, { name: 'Mia Frozen' })
        expect(result.success).toBe(false)
        if (!result.success) {
          expect(result.error._tag).toBe('ValidationError')
        }
      }
    })

    it('swaps handle index on update', async () => {
      const created = await service.createHuman({ name: 'Ned', email: 'ned@example.com', handle: 'ned-old' })
      expect(created.success).toBe(true)
      if (created.success) {
        const id = created.data.id
        const result = await service.update(id, { handle: 'ned-new' })
        expect(result.success).toBe(true)
        // old index removed, new index points to same id
        expect(backingMap.has('idx:handle:ned-old')).toBe(false)
        expect(backingMap.get('idx:handle:ned-new')).toBe(id)
        if (result.success) {
          expect(result.data.handle).toBe('ned-new')
        }
      }
    })

    it('returns ConflictError when new handle is already taken', async () => {
      await service.createHuman({ name: 'Oscar', email: 'oscar@example.com', handle: 'taken-handle' })
      const created = await service.createHuman({ name: 'Paula', email: 'paula@example.com', handle: 'paula' })
      expect(created.success).toBe(true)
      if (created.success) {
        const result = await service.update(created.data.id, { handle: 'taken-handle' })
        expect(result.success).toBe(false)
        if (!result.success) {
          expect(result.error._tag).toBe('ConflictError')
        }
      }
    })

    it('swaps github index on update', async () => {
      const created = await service.createHuman({ name: 'Quinn', email: 'quinn@example.com' })
      expect(created.success).toBe(true)
      if (created.success) {
        const id = created.data.id
        await service.update(id, { githubUserId: 'gh_old' })
        const result = await service.update(id, { githubUserId: 'gh_new' })
        expect(result.success).toBe(true)
        expect(backingMap.has('idx:github:gh_old')).toBe(false)
        expect(backingMap.get('idx:github:gh_new')).toBe(id)
      }
    })
  })

  // --------------------------------------------------------------------------
  // freeze()
  // --------------------------------------------------------------------------

  describe('freeze()', () => {
    it('freezes a non-frozen identity', async () => {
      const created = await service.createHuman({ name: 'Remy', email: 'remy@example.com' })
      expect(created.success).toBe(true)
      if (created.success) {
        const before = Date.now()
        const result = await service.freeze(created.data.id, 'policy violation')
        expect(result.success).toBe(true)
        if (result.success) {
          const identity = result.data
          expect(identity.frozen).toBe(true)
          expect(identity.frozenAt).toBeGreaterThanOrEqual(before)
          expect(identity.claimStatus).toBe('frozen')
        }
      }
    })

    it('returns NotFoundError for missing identity', async () => {
      const result = await service.freeze('usr_missing', 'reason')
      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error._tag).toBe('NotFoundError')
      }
    })

    it('returns AuthError when already frozen', async () => {
      const created = await service.createHuman({ name: 'Sam', email: 'sam@example.com' })
      expect(created.success).toBe(true)
      if (created.success) {
        await service.freeze(created.data.id, 'first freeze')
        const result = await service.freeze(created.data.id, 'second freeze')
        expect(result.success).toBe(false)
        if (!result.success) {
          expect(result.error._tag).toBe('AuthError')
          expect(result.error.code).toBe('forbidden')
        }
      }
    })
  })

  // --------------------------------------------------------------------------
  // unfreeze()
  // --------------------------------------------------------------------------

  describe('unfreeze()', () => {
    it('restores previous claimStatus on unfreeze', async () => {
      const created = await service.createHuman({ name: 'Tina', email: 'tina@example.com' })
      expect(created.success).toBe(true)
      if (created.success) {
        // human starts as 'claimed' — freeze then unfreeze should restore 'claimed'
        await service.freeze(created.data.id, 'test')
        const result = await service.unfreeze(created.data.id)
        expect(result.success).toBe(true)
        if (result.success) {
          const identity = result.data
          expect(identity.frozen).toBe(false)
          expect(identity.frozenAt).toBeUndefined()
          expect(identity.claimStatus).toBe('claimed')
        }
      }
    })

    it('returns AuthError when identity is not frozen', async () => {
      const created = await service.createHuman({ name: 'Uma', email: 'uma@example.com' })
      expect(created.success).toBe(true)
      if (created.success) {
        const result = await service.unfreeze(created.data.id)
        expect(result.success).toBe(false)
        if (!result.success) {
          expect(result.error._tag).toBe('AuthError')
          expect(result.error.code).toBe('forbidden')
        }
      }
    })

    it('returns NotFoundError for missing identity', async () => {
      const result = await service.unfreeze('usr_missing')
      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error._tag).toBe('NotFoundError')
      }
    })
  })

  // --------------------------------------------------------------------------
  // linkAccount()
  // --------------------------------------------------------------------------

  describe('linkAccount()', () => {
    it('links a GitHub account with status=active', async () => {
      const created = await service.createHuman({ name: 'Victor', email: 'victor@example.com' })
      expect(created.success).toBe(true)
      if (created.success) {
        const result = await service.linkAccount(created.data.id, {
          provider: 'github',
          providerAccountId: 'gh_victor_42',
          type: 'auth',
          displayName: 'victor-gh',
          email: 'victor@github.com',
        })
        expect(result.success).toBe(true)
        if (result.success) {
          const account = result.data
          expect(account.provider).toBe('github')
          expect(account.providerAccountId).toBe('gh_victor_42')
          expect(account.type).toBe('auth')
          expect(account.displayName).toBe('victor-gh')
          expect(account.status).toBe('active')
          expect(account.identityId).toBe(created.data.id)
          expect(typeof account.id).toBe('string')
          expect(typeof account.linkedAt).toBe('number')
        }
      }
    })

    it('returns NotFoundError for missing identity', async () => {
      const result = await service.linkAccount('usr_missing', {
        provider: 'github',
        providerAccountId: 'gh_999',
        type: 'auth',
        displayName: 'ghost',
      })
      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error._tag).toBe('NotFoundError')
        expect(result.error.entity).toBe('Identity')
      }
    })

    it('returns ConflictError for duplicate provider', async () => {
      const created = await service.createHuman({ name: 'Wendy', email: 'wendy@example.com' })
      expect(created.success).toBe(true)
      if (created.success) {
        await service.linkAccount(created.data.id, {
          provider: 'github',
          providerAccountId: 'gh_wendy_1',
          type: 'auth',
          displayName: 'wendy-gh',
        })
        const result = await service.linkAccount(created.data.id, {
          provider: 'github',
          providerAccountId: 'gh_wendy_2',
          type: 'auth',
          displayName: 'wendy-gh-2',
        })
        expect(result.success).toBe(false)
        if (!result.success) {
          expect(result.error._tag).toBe('ConflictError')
        }
      }
    })

    it('stores linked account in storage at linked:{id}:{provider}', async () => {
      const created = await service.createHuman({ name: 'Xavier', email: 'xavier@example.com' })
      expect(created.success).toBe(true)
      if (created.success) {
        await service.linkAccount(created.data.id, {
          provider: 'stripe',
          providerAccountId: 'cus_xavier',
          type: 'payment',
          displayName: 'xavier stripe',
        })
        const key = `linked:${created.data.id}:stripe`
        expect(backingMap.has(key)).toBe(true)
      }
    })
  })

  // --------------------------------------------------------------------------
  // unlinkAccount()
  // --------------------------------------------------------------------------

  describe('unlinkAccount()', () => {
    it('soft-revokes linked account (status=revoked)', async () => {
      const created = await service.createHuman({ name: 'Yara', email: 'yara@example.com' })
      expect(created.success).toBe(true)
      if (created.success) {
        await service.linkAccount(created.data.id, {
          provider: 'github',
          providerAccountId: 'gh_yara',
          type: 'auth',
          displayName: 'yara-gh',
        })
        const result = await service.unlinkAccount(created.data.id, 'github')
        expect(result.success).toBe(true)
        if (result.success) {
          expect(result.data.status).toBe('revoked')
          expect(result.data.provider).toBe('github')
        }
      }
    })

    it('returns NotFoundError when provider link does not exist', async () => {
      const created = await service.createHuman({ name: 'Zane', email: 'zane@example.com' })
      expect(created.success).toBe(true)
      if (created.success) {
        const result = await service.unlinkAccount(created.data.id, 'github')
        expect(result.success).toBe(false)
        if (!result.success) {
          expect(result.error._tag).toBe('NotFoundError')
        }
      }
    })
  })

  // --------------------------------------------------------------------------
  // getLinkedAccounts()
  // --------------------------------------------------------------------------

  describe('getLinkedAccounts()', () => {
    it('returns NotFoundError for nonexistent identity', async () => {
      const result = await service.getLinkedAccounts('usr_missing')
      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error._tag).toBe('NotFoundError')
      }
    })

    it('returns all linked accounts for an identity', async () => {
      const created = await service.createHuman({ name: 'Aria', email: 'aria@example.com' })
      expect(created.success).toBe(true)
      if (created.success) {
        await service.linkAccount(created.data.id, {
          provider: 'github',
          providerAccountId: 'gh_aria',
          type: 'auth',
          displayName: 'aria-gh',
        })
        await service.linkAccount(created.data.id, {
          provider: 'stripe',
          providerAccountId: 'cus_aria',
          type: 'payment',
          displayName: 'aria stripe',
        })
        const result = await service.getLinkedAccounts(created.data.id)
        expect(result.success).toBe(true)
        if (result.success) {
          expect(result.data.length).toBe(2)
          const providers = result.data.map((a) => a.provider)
          expect(providers).toContain('github')
          expect(providers).toContain('stripe')
        }
      }
    })

    it('returns empty array when identity has no linked accounts', async () => {
      const created = await service.createHuman({ name: 'Ben', email: 'ben@example.com' })
      expect(created.success).toBe(true)
      if (created.success) {
        const result = await service.getLinkedAccounts(created.data.id)
        expect(result.success).toBe(true)
        if (result.success) {
          expect(result.data).toEqual([])
        }
      }
    })
  })

  // --------------------------------------------------------------------------
  // backfillIndexes()
  // --------------------------------------------------------------------------

  describe('backfillIndexes()', () => {
    it('creates indexes for pre-existing identities that have none', async () => {
      // Seed legacy data directly — no idx: keys
      const legacyId = 'usr_legacy001'
      backingMap.set(`identity:${legacyId}`, {
        id: legacyId,
        type: 'human',
        name: 'Legacy User',
        email: 'legacy@example.com',
        handle: 'legacy',
        githubUserId: 'gh_legacy_42',
        verified: true,
        level: 2,
        claimStatus: 'claimed',
        frozen: false,
        createdAt: 1700000000000,
        updatedAt: 1700000001000,
      })

      // Confirm no indexes exist yet
      expect(backingMap.has('idx:email:legacy@example.com')).toBe(false)
      expect(backingMap.has('idx:handle:legacy')).toBe(false)
      expect(backingMap.has('idx:github:gh_legacy_42')).toBe(false)

      await service.backfillIndexes()

      // Lookups should now work
      const byEmail = await service.getByEmail('legacy@example.com')
      expect(byEmail.success).toBe(true)
      if (byEmail.success) expect(byEmail.data.id).toBe(legacyId)

      const byHandle = await service.getByHandle('legacy')
      expect(byHandle.success).toBe(true)
      if (byHandle.success) expect(byHandle.data.id).toBe(legacyId)

      const byGitHub = await service.getByGitHubUserId('gh_legacy_42')
      expect(byGitHub.success).toBe(true)
      if (byGitHub.success) expect(byGitHub.data.id).toBe(legacyId)
    })

    it('is idempotent — calling twice produces no error and lookups still work', async () => {
      const legacyId = 'usr_legacy002'
      backingMap.set(`identity:${legacyId}`, {
        id: legacyId,
        type: 'human',
        name: 'Legacy Two',
        email: 'legacy2@example.com',
        handle: 'legacy2',
        verified: true,
        level: 2,
        claimStatus: 'claimed',
        frozen: false,
        createdAt: 1700000000000,
        updatedAt: 1700000001000,
      })

      await service.backfillIndexes()
      await service.backfillIndexes() // second call — must not throw

      const byEmail = await service.getByEmail('legacy2@example.com')
      expect(byEmail.success).toBe(true)
      if (byEmail.success) expect(byEmail.data.id).toBe(legacyId)

      const byHandle = await service.getByHandle('legacy2')
      expect(byHandle.success).toBe(true)
      if (byHandle.success) expect(byHandle.data.id).toBe(legacyId)
    })
  })

  // --------------------------------------------------------------------------
  // getLinkedAccount()
  // --------------------------------------------------------------------------

  describe('getLinkedAccount()', () => {
    it('returns specific linked account by provider', async () => {
      const created = await service.createHuman({ name: 'Cleo', email: 'cleo@example.com' })
      expect(created.success).toBe(true)
      if (created.success) {
        await service.linkAccount(created.data.id, {
          provider: 'anthropic',
          providerAccountId: 'ant_cleo',
          type: 'ai',
          displayName: 'cleo anthropic',
        })
        const result = await service.getLinkedAccount(created.data.id, 'anthropic')
        expect(result.success).toBe(true)
        if (result.success) {
          expect(result.data.provider).toBe('anthropic')
          expect(result.data.providerAccountId).toBe('ant_cleo')
        }
      }
    })

    it('returns NotFoundError for missing provider link', async () => {
      const created = await service.createHuman({ name: 'Drew', email: 'drew@example.com' })
      expect(created.success).toBe(true)
      if (created.success) {
        const result = await service.getLinkedAccount(created.data.id, 'github')
        expect(result.success).toBe(false)
        if (!result.success) {
          expect(result.error._tag).toBe('NotFoundError')
        }
      }
    })
  })

  // --------------------------------------------------------------------------
  // createService()
  // --------------------------------------------------------------------------

  describe('createService()', () => {
    it('creates a service identity at level 3 / claimed', async () => {
      const result = await service.createService({ name: 'payments-service', handle: 'payments' })
      expect(result.success).toBe(true)
      if (result.success) {
        const identity = result.data
        expect(identity.type).toBe('service')
        expect(identity.name).toBe('payments-service')
        expect(identity.handle).toBe('payments')
        expect(identity.verified).toBe(true)
        expect(identity.level).toBe(3)
        expect(identity.claimStatus).toBe('claimed')
      }
    })

    it('stores handle index', async () => {
      const result = await service.createService({ name: 'my-svc', handle: 'my-svc' })
      expect(result.success).toBe(true)
      if (result.success) {
        const id = result.data.id
        expect(backingMap.get('idx:handle:my-svc')).toBe(id)
      }
    })

    it('returns ValidationError for empty name', async () => {
      const result = await service.createService({ name: '', handle: 'svc' })
      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error._tag).toBe('ValidationError')
      }
    })

    it('returns ValidationError for empty handle', async () => {
      const result = await service.createService({ name: 'svc', handle: '' })
      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error._tag).toBe('ValidationError')
      }
    })

    it('returns ConflictError for duplicate handle', async () => {
      await service.createService({ name: 'First', handle: 'shared-handle' })
      const result = await service.createService({ name: 'Second', handle: 'shared-handle' })
      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error._tag).toBe('ConflictError')
      }
    })
  })
})
