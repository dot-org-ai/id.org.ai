import { describe, it, expect, beforeEach } from 'vitest'
import { AgentServiceImpl } from '../src/server/services/agents'
import type { AgentService } from '../src/server/services/agents'
import { AuditServiceImpl } from '../src/server/services/audit'
import { MemoryStorageAdapter } from '../src/sdk/storage'

describe('AgentServiceImpl', () => {
  let storage: MemoryStorageAdapter
  let service: AgentService

  beforeEach(() => {
    storage = new MemoryStorageAdapter()
    const audit = new AuditServiceImpl({ storage })
    service = new AgentServiceImpl({ storage, audit, tenantExists: async () => true })
  })

  // ──────────────────────────────────────────────────────────────────────
  // register
  // ──────────────────────────────────────────────────────────────────────

  describe('register()', () => {
    it('creates an autonomous agent in active status', async () => {
      const result = await service.register({
        tenantId: 'tenant_1',
        name: 'crm-agent',
        publicKey: 'pubkey-aaa',
        mode: 'autonomous',
      })
      expect(result.success).toBe(true)
      if (result.success) {
        expect(result.data.agent.status).toBe('active')
        expect(result.data.agent.mode).toBe('autonomous')
        expect(result.data.agent.tenantId).toBe('tenant_1')
        expect(result.data.agent.activatedAt).toBeDefined()
        expect(result.data.agent.id).toMatch(/^agent_/)
      }
    })

    it('creates a delegated agent in pending status', async () => {
      const result = await service.register({
        tenantId: 'tenant_1',
        name: 'helper',
        publicKey: 'pubkey-bbb',
        mode: 'delegated',
      })
      expect(result.success).toBe(true)
      if (result.success) {
        expect(result.data.agent.status).toBe('pending')
        expect(result.data.agent.activatedAt).toBeUndefined()
      }
    })

    it('rejects empty name', async () => {
      const result = await service.register({
        tenantId: 'tenant_1',
        name: '',
        publicKey: 'pubkey-ccc',
        mode: 'autonomous',
      })
      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error._tag).toBe('ValidationError')
      }
    })

    it('rejects when neither publicKey nor jwksUrl is provided', async () => {
      const result = await service.register({
        tenantId: 'tenant_1',
        name: 'no-key',
        mode: 'autonomous',
      })
      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error._tag).toBe('ValidationError')
      }
    })

    it('rejects when both publicKey and jwksUrl are provided', async () => {
      const result = await service.register({
        tenantId: 'tenant_1',
        name: 'both',
        publicKey: 'pubkey-x',
        jwksUrl: 'https://example.com/jwks',
        mode: 'autonomous',
      })
      expect(result.success).toBe(false)
    })

    it('rejects duplicate public key', async () => {
      await service.register({ tenantId: 'tenant_1', name: 'a', publicKey: 'dup-key', mode: 'autonomous' })
      const result = await service.register({ tenantId: 'tenant_2', name: 'b', publicKey: 'dup-key', mode: 'autonomous' })
      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error._tag).toBe('ConflictError')
      }
    })

    it('returns NotFoundError when tenant does not exist', async () => {
      const audit = new AuditServiceImpl({ storage })
      const strict = new AgentServiceImpl({ storage, audit, tenantExists: async () => false })
      const result = await strict.register({
        tenantId: 'nope',
        name: 'a',
        publicKey: 'pubkey-z',
        mode: 'autonomous',
      })
      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error._tag).toBe('NotFoundError')
      }
    })

    it('indexes by tenant for list()', async () => {
      await service.register({ tenantId: 'tenant_x', name: 'a', publicKey: 'k1', mode: 'autonomous' })
      await service.register({ tenantId: 'tenant_x', name: 'b', publicKey: 'k2', mode: 'autonomous' })
      const list = await service.list('tenant_x')
      expect(list.length).toBe(2)
      expect(list.map((a) => a.name).sort()).toEqual(['a', 'b'])
    })

    it('indexes by publicKey for getByPublicKey()', async () => {
      const reg = await service.register({ tenantId: 't', name: 'a', publicKey: 'lookup-key', mode: 'autonomous' })
      expect(reg.success).toBe(true)
      const found = await service.getByPublicKey('lookup-key')
      expect(found.success).toBe(true)
      if (found.success && reg.success) {
        expect(found.data.id).toBe(reg.data.agent.id)
      }
    })
  })

  // ──────────────────────────────────────────────────────────────────────
  // get / list / getByPublicKey
  // ──────────────────────────────────────────────────────────────────────

  describe('get()', () => {
    it('returns NotFoundError for missing agent', async () => {
      const result = await service.get('agent_does_not_exist')
      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error._tag).toBe('NotFoundError')
      }
    })
  })

  describe('list()', () => {
    it('returns empty for tenant with no agents', async () => {
      expect(await service.list('empty')).toEqual([])
    })

    it('prunes agents revoked over 30 days ago', async () => {
      const reg = await service.register({ tenantId: 't', name: 'old', publicKey: 'k-old', mode: 'autonomous' })
      expect(reg.success).toBe(true)
      if (!reg.success) return
      // Manually mutate to simulate old revocation
      const ancient = Date.now() - 31 * 24 * 60 * 60 * 1000
      await storage.put(`agent:${reg.data.agent.id}`, { ...reg.data.agent, status: 'revoked', revokedAt: ancient })

      const list = await service.list('t')
      expect(list).toEqual([])
    })

    it('keeps recently revoked agents in list', async () => {
      const reg = await service.register({ tenantId: 't', name: 'recent', publicKey: 'k-recent', mode: 'autonomous' })
      expect(reg.success).toBe(true)
      if (!reg.success) return
      await service.revoke(reg.data.agent.id)
      const list = await service.list('t')
      expect(list.length).toBe(1)
      expect(list[0]?.status).toBe('revoked')
    })
  })

  // ──────────────────────────────────────────────────────────────────────
  // updateStatus
  // ──────────────────────────────────────────────────────────────────────

  describe('updateStatus()', () => {
    it('approves a pending delegated agent', async () => {
      const reg = await service.register({ tenantId: 't', name: 'p', publicKey: 'k-p', mode: 'delegated' })
      expect(reg.success).toBe(true)
      if (!reg.success) return

      const result = await service.updateStatus(reg.data.agent.id, { status: 'active' })
      expect(result.success).toBe(true)
      if (result.success) {
        expect(result.data.status).toBe('active')
        expect(result.data.activatedAt).toBeDefined()
      }
    })

    it('rejects invalid transition (active → pending)', async () => {
      const reg = await service.register({ tenantId: 't', name: 'a', publicKey: 'k', mode: 'autonomous' })
      expect(reg.success).toBe(true)
      if (!reg.success) return

      const result = await service.updateStatus(reg.data.agent.id, { status: 'pending' })
      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error._tag).toBe('ValidationError')
      }
    })

    it('rejects transition from terminal state', async () => {
      const reg = await service.register({ tenantId: 't', name: 'a', publicKey: 'k', mode: 'autonomous' })
      expect(reg.success).toBe(true)
      if (!reg.success) return
      await service.revoke(reg.data.agent.id)

      const result = await service.updateStatus(reg.data.agent.id, { status: 'active' })
      expect(result.success).toBe(false)
    })

    it('returns NotFoundError for unknown agent', async () => {
      const result = await service.updateStatus('agent_missing', { status: 'active' })
      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error._tag).toBe('NotFoundError')
      }
    })
  })

  // ──────────────────────────────────────────────────────────────────────
  // revoke
  // ──────────────────────────────────────────────────────────────────────

  describe('revoke()', () => {
    it('marks agent as revoked and clears pubkey index', async () => {
      const reg = await service.register({ tenantId: 't', name: 'a', publicKey: 'revokable', mode: 'autonomous' })
      expect(reg.success).toBe(true)
      if (!reg.success) return

      const result = await service.revoke(reg.data.agent.id, 'compromised')
      expect(result.success).toBe(true)
      if (result.success) {
        expect(result.data.status).toBe('revoked')
        expect(result.data.revokedAt).toBeDefined()
      }

      // pubkey lookup should miss
      const lookup = await service.getByPublicKey('revokable')
      expect(lookup.success).toBe(false)
    })

    it('rejects double-revoke', async () => {
      const reg = await service.register({ tenantId: 't', name: 'a', publicKey: 'k', mode: 'autonomous' })
      expect(reg.success).toBe(true)
      if (!reg.success) return
      await service.revoke(reg.data.agent.id)
      const second = await service.revoke(reg.data.agent.id)
      expect(second.success).toBe(false)
    })
  })

  // ──────────────────────────────────────────────────────────────────────
  // reactivate
  // ──────────────────────────────────────────────────────────────────────

  describe('reactivate()', () => {
    it('moves expired agent back to active and resets lastUsedAt', async () => {
      const reg = await service.register({ tenantId: 't', name: 'a', publicKey: 'k', mode: 'autonomous' })
      expect(reg.success).toBe(true)
      if (!reg.success) return
      await service.updateStatus(reg.data.agent.id, { status: 'expired' })

      const result = await service.reactivate(reg.data.agent.id)
      expect(result.success).toBe(true)
      if (result.success) {
        expect(result.data.status).toBe('active')
        expect(result.data.lastUsedAt).toBeDefined()
      }
    })

    it('rejects reactivating a non-expired agent', async () => {
      const reg = await service.register({ tenantId: 't', name: 'a', publicKey: 'k', mode: 'autonomous' })
      expect(reg.success).toBe(true)
      if (!reg.success) return

      const result = await service.reactivate(reg.data.agent.id)
      expect(result.success).toBe(false)
    })

    it('revokes (instead of reactivating) if absoluteLifetime exceeded', async () => {
      const reg = await service.register({
        tenantId: 't',
        name: 'a',
        publicKey: 'k',
        mode: 'autonomous',
        absoluteLifetimeMs: 1, // tiny budget
      })
      expect(reg.success).toBe(true)
      if (!reg.success) return
      await service.updateStatus(reg.data.agent.id, { status: 'expired' })
      // wait past the absolute lifetime
      await new Promise((r) => setTimeout(r, 5))

      const result = await service.reactivate(reg.data.agent.id)
      expect(result.success).toBe(false)

      const after = await service.get(reg.data.agent.id)
      expect(after.success).toBe(true)
      if (after.success) {
        expect(after.data.status).toBe('revoked')
      }
    })
  })

  // ──────────────────────────────────────────────────────────────────────
  // touch
  // ──────────────────────────────────────────────────────────────────────

  describe('touch()', () => {
    it('updates lastUsedAt for active agents', async () => {
      const reg = await service.register({ tenantId: 't', name: 'a', publicKey: 'k', mode: 'autonomous' })
      expect(reg.success).toBe(true)
      if (!reg.success) return

      await service.touch(reg.data.agent.id)
      const after = await service.get(reg.data.agent.id)
      expect(after.success).toBe(true)
      if (after.success) {
        expect(after.data.lastUsedAt).toBeDefined()
      }
    })

    it('is a no-op for revoked agents', async () => {
      const reg = await service.register({ tenantId: 't', name: 'a', publicKey: 'k', mode: 'autonomous' })
      expect(reg.success).toBe(true)
      if (!reg.success) return
      await service.revoke(reg.data.agent.id)
      const beforeTouch = await service.get(reg.data.agent.id)

      await service.touch(reg.data.agent.id)
      const afterTouch = await service.get(reg.data.agent.id)

      // lastUsedAt should be unchanged (undefined → undefined)
      if (beforeTouch.success && afterTouch.success) {
        expect(afterTouch.data.lastUsedAt).toBe(beforeTouch.data.lastUsedAt)
      }
    })

    it('is a no-op for missing agents', async () => {
      // Should not throw
      await expect(service.touch('agent_missing')).resolves.toBeUndefined()
    })
  })
})
