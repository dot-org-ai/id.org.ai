/**
 * AgentServiceImpl — implementation of AgentWriter.
 *
 * Storage:
 *   agent:{id}                       → Agent
 *   agent-by-tenant:{tenantId}       → string[]   // agent IDs under a tenant
 *   agent-by-pubkey:{base64-pubkey}  → agent ID
 *
 * Lifecycle expiry (sessionTtl/maxLifetime/absoluteLifetime ticking) is NOT
 * enforced inside this service in id-ax7. The fields are stored; a separate
 * issue (paired with AAP wire surface) will run the expiry sweep.
 */

import { Ok, Err } from '../../../sdk/foundation/result'
import type { Result } from '../../../sdk/foundation/result'
import { NotFoundError, ValidationError, ConflictError, AuthError } from '../../../sdk/foundation/errors'
import type { StorageAdapter } from '../../../sdk/storage'
import type { AuditService } from '../audit/service'
import type {
  AgentService,
  Agent,
  AgentInfo,
  AgentMode,
  AgentStatus,
  RegisterAgentInput,
  RegisterAgentResult,
  UpdateAgentStatusInput,
} from './types'
import {
  DEFAULT_SESSION_TTL_MS,
  DEFAULT_MAX_LIFETIME_MS,
  DEFAULT_ABSOLUTE_LIFETIME_MS,
} from './types'

// ============================================================================
// State transition table (AAP §5.4)
// ============================================================================

const ALLOWED_TRANSITIONS: Record<AgentStatus, AgentStatus[]> = {
  pending: ['active', 'rejected', 'revoked'],
  active: ['expired', 'revoked', 'claimed'],
  expired: ['active', 'revoked'], // active via reactivate()
  revoked: [], // terminal
  rejected: [], // terminal
  claimed: [], // terminal (AAP-strict mode only)
}

// ============================================================================
// Implementation
// ============================================================================

export class AgentServiceImpl implements AgentService {
  private storage: StorageAdapter
  private audit: AuditService
  private tenantExists: (id: string) => Promise<boolean>

  constructor({
    storage,
    audit,
    tenantExists,
  }: {
    storage: StorageAdapter
    audit: AuditService
    tenantExists?: (id: string) => Promise<boolean>
  }) {
    this.storage = storage
    this.audit = audit
    this.tenantExists = tenantExists ?? (async () => true)
  }

  // --------------------------------------------------------------------------
  // Reader
  // --------------------------------------------------------------------------

  async get(id: string): Promise<Result<Agent, NotFoundError>> {
    const raw = await this.storage.get<Agent>(`agent:${id}`)
    if (!raw) return Err(new NotFoundError('Agent', id))
    return Ok(raw)
  }

  async list(tenantId: string): Promise<AgentInfo[]> {
    const ids = (await this.storage.get<string[]>(`agent-by-tenant:${tenantId}`)) ?? []
    const agents: AgentInfo[] = []

    const thirtyDaysAgo = Date.now() - 30 * 24 * 60 * 60 * 1000

    for (const id of ids) {
      const agent = await this.storage.get<Agent>(`agent:${id}`)
      if (!agent) continue
      // Prune long-revoked agents from list responses (matches agent-keys behaviour)
      if (agent.revokedAt && agent.revokedAt < thirtyDaysAgo) continue

      agents.push({
        id: agent.id,
        tenantId: agent.tenantId,
        name: agent.name,
        status: agent.status,
        mode: agent.mode,
        capabilities: agent.capabilities,
        createdAt: agent.createdAt,
        activatedAt: agent.activatedAt,
        expiresAt: agent.expiresAt,
        lastUsedAt: agent.lastUsedAt,
        revokedAt: agent.revokedAt,
      })
    }

    return agents
  }

  async getByPublicKey(publicKey: string): Promise<Result<Agent, NotFoundError>> {
    const id = await this.storage.get<string>(`agent-by-pubkey:${publicKey}`)
    if (!id) return Err(new NotFoundError('Agent', publicKey))
    return this.get(id)
  }

  // --------------------------------------------------------------------------
  // Writer
  // --------------------------------------------------------------------------

  async register(input: RegisterAgentInput): Promise<Result<RegisterAgentResult, ValidationError | ConflictError | NotFoundError>> {
    if (!input.name || input.name.trim() === '') {
      return Err(new ValidationError('name', 'Name must not be empty'))
    }
    if (!input.publicKey && !input.jwksUrl) {
      return Err(new ValidationError('publicKey', 'Either publicKey or jwksUrl must be provided'))
    }
    if (input.publicKey && input.jwksUrl) {
      return Err(new ValidationError('publicKey', 'publicKey and jwksUrl are mutually exclusive'))
    }

    const tenantOk = await this.tenantExists(input.tenantId)
    if (!tenantOk) return Err(new NotFoundError('Tenant', input.tenantId))

    if (input.publicKey) {
      const existingId = await this.storage.get<string>(`agent-by-pubkey:${input.publicKey}`)
      if (existingId) {
        return Err(new ConflictError('Agent', `An agent with this public key already exists: ${existingId}`))
      }
    }

    const id = `agent_${crypto.randomUUID().replace(/-/g, '').slice(0, 16)}`
    const now = Date.now()
    // delegated agents start pending (await user approval); autonomous start active
    const initialStatus: AgentStatus = input.mode === 'autonomous' ? 'active' : 'pending'

    const agent: Agent = {
      id,
      tenantId: input.tenantId,
      name: input.name,
      publicKey: input.publicKey,
      jwksUrl: input.jwksUrl,
      status: initialStatus,
      mode: input.mode,
      capabilities: input.capabilities ?? [],
      createdAt: now,
      activatedAt: initialStatus === 'active' ? now : undefined,
      sessionTtlMs: input.sessionTtlMs ?? DEFAULT_SESSION_TTL_MS,
      maxLifetimeMs: input.maxLifetimeMs ?? DEFAULT_MAX_LIFETIME_MS,
      absoluteLifetimeMs: input.absoluteLifetimeMs ?? DEFAULT_ABSOLUTE_LIFETIME_MS,
    }

    await this.storage.put(`agent:${id}`, agent)

    if (input.publicKey) {
      await this.storage.put(`agent-by-pubkey:${input.publicKey}`, id)
    }

    const tenantAgentsKey = `agent-by-tenant:${input.tenantId}`
    const existingIds = (await this.storage.get<string[]>(tenantAgentsKey)) ?? []
    existingIds.push(id)
    await this.storage.put(tenantAgentsKey, existingIds)

    await this.audit.logFireAndForget({
      event: 'agent.registered',
      actor: id,
      tenantId: input.tenantId,
      target: id,
      metadata: { mode: input.mode, status: initialStatus, capabilities: agent.capabilities },
    })

    return Ok({ agent })
  }

  async updateStatus(id: string, input: UpdateAgentStatusInput): Promise<Result<Agent, NotFoundError | ValidationError | AuthError>> {
    const agent = await this.storage.get<Agent>(`agent:${id}`)
    if (!agent) return Err(new NotFoundError('Agent', id))

    const allowed = ALLOWED_TRANSITIONS[agent.status]
    if (!allowed.includes(input.status)) {
      return Err(new ValidationError('status', `Invalid transition: ${agent.status} → ${input.status}`))
    }

    const now = Date.now()
    const updated: Agent = {
      ...agent,
      status: input.status,
      // If transitioning into active for the first time, set activatedAt
      activatedAt: input.status === 'active' && !agent.activatedAt ? now : agent.activatedAt,
      // If transitioning to revoked, set revokedAt
      revokedAt: input.status === 'revoked' ? now : agent.revokedAt,
    }

    await this.storage.put(`agent:${id}`, updated)

    await this.audit.logFireAndForget({
      event: `agent.${input.status}`,
      actor: id,
      tenantId: agent.tenantId,
      target: id,
      metadata: { from: agent.status, to: input.status, reason: input.reason },
    })

    return Ok(updated)
  }

  async revoke(id: string, reason?: string): Promise<Result<Agent, NotFoundError | AuthError>> {
    const agent = await this.storage.get<Agent>(`agent:${id}`)
    if (!agent) return Err(new NotFoundError('Agent', id))

    if (agent.status === 'revoked') {
      return Err(new AuthError('forbidden', 'Agent is already revoked'))
    }

    const now = Date.now()
    const updated: Agent = {
      ...agent,
      status: 'revoked',
      revokedAt: now,
    }

    await this.storage.put(`agent:${id}`, updated)
    if (agent.publicKey) {
      // Remove the pubkey reverse index so the agent can no longer authenticate
      await this.storage.delete(`agent-by-pubkey:${agent.publicKey}`)
    }

    await this.audit.logFireAndForget({
      event: 'agent.revoked',
      actor: id,
      tenantId: agent.tenantId,
      target: id,
      metadata: { reason, from: agent.status },
    })

    return Ok(updated)
  }

  async reactivate(id: string): Promise<Result<Agent, NotFoundError | ValidationError>> {
    const agent = await this.storage.get<Agent>(`agent:${id}`)
    if (!agent) return Err(new NotFoundError('Agent', id))

    if (agent.status !== 'expired') {
      return Err(new ValidationError('status', `Cannot reactivate agent with status '${agent.status}' — only 'expired' is reactivable`))
    }

    // Check absoluteLifetime — if exceeded, transition to revoked instead
    const now = Date.now()
    const absoluteLimit = agent.createdAt + agent.absoluteLifetimeMs
    if (now >= absoluteLimit) {
      const revoked: Agent = { ...agent, status: 'revoked', revokedAt: now }
      await this.storage.put(`agent:${id}`, revoked)
      if (agent.publicKey) {
        await this.storage.delete(`agent-by-pubkey:${agent.publicKey}`)
      }
      await this.audit.logFireAndForget({
        event: 'agent.revoked',
        actor: id,
        tenantId: agent.tenantId,
        target: id,
        metadata: { reason: 'absoluteLifetime exceeded on reactivation attempt' },
      })
      return Err(new ValidationError('lifetime', 'Absolute lifetime exceeded; agent has been permanently revoked'))
    }

    const updated: Agent = {
      ...agent,
      status: 'active',
      activatedAt: now,
      lastUsedAt: now,
      expiresAt: undefined,
    }

    await this.storage.put(`agent:${id}`, updated)

    await this.audit.logFireAndForget({
      event: 'agent.reactivated',
      actor: id,
      tenantId: agent.tenantId,
      target: id,
    })

    return Ok(updated)
  }

  async touch(id: string): Promise<void> {
    const agent = await this.storage.get<Agent>(`agent:${id}`)
    if (!agent) return
    if (agent.status !== 'active') return
    agent.lastUsedAt = Date.now()
    await this.storage.put(`agent:${id}`, agent)
  }
}
