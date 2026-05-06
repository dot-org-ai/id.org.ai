/**
 * IdentityDO — The root identity Durable Object
 *
 * ns: https://id.org.ai
 * tagline: "Humans. Agents. Identity."
 *
 * id.org.ai is an open identity standard for the agent era.
 * Any platform (.do, .studio, headless.ly, third-party apps) can
 * build on top of it.
 *
 * This DO provides:
 *   - Universal identity (human/agent/service)
 *   - OAuth 2.1 provider ("Login with id.org.ai")
 *   - MCP authentication for AI agents
 *   - Linked accounts (GitHub, Stripe, Anthropic, etc.)
 *   - Claim-by-commit (anonymous → GitHub-linked via git push)
 *   - API key management with rate limiting
 *   - Organization and member management
 *   - Rate limit tracking per identity
 *   - Session validation and lifecycle
 */

import { DurableObject } from 'cloudflare:workers'
// errorJson/ErrorCode no longer needed — fetch() is health-check only, all routes are RPC
// crypto/keys imports removed — now handled by KeyService (Phase 5)
import { DurableObjectStorageAdapter } from './storage-adapter'
import type { StorageAdapter } from '../../sdk/storage'
import type { AuditEvent, AuditQueryOptions, StoredAuditEvent } from '../../sdk/audit'
import { AuditServiceImpl } from '../services/audit'
import type { AuditService } from '../services/audit'
import { EntityStoreServiceImpl } from '../services/entity-store'
import type { EntityStoreService } from '../services/entity-store'
import { IdentityServiceImpl } from '../services/identity/service'
import { KeyServiceImpl } from '../services/keys'
import { SessionServiceImpl } from '../services/auth/service'
import { AgentServiceImpl } from '../services/agents'
import type { AgentService, Agent, AgentInfo, AgentMode, AgentStatus, RegisterAgentInput } from '../services/agents'
import { seedDefaultClients } from '../../sdk/oauth/clients'
import type { SessionData as AuthSessionData } from '../services/auth/types'
import { refreshWorkOSAccessToken } from '../../sdk/workos'
import { isClaimedBranch } from '../../sdk/claim/policy'

// ============================================================================
// Types — re-exported from sdk/types
// ============================================================================

export type {
  IdentityStub,
  Identity,
  IdentityType,
  CapabilityLevel,
  ClaimStatus,
  LinkedAccount,
  SessionData,
} from '../../sdk/types'

export type { Agent, AgentInfo, AgentStatus, AgentMode, RegisterAgentInput } from '../services/agents'

import type { Identity, CapabilityLevel, ClaimStatus, IdentityType } from '../../sdk/types'

export interface IdentityEnv {
  // KV for sessions
  SESSIONS: KVNamespace

  // Signing secrets
  AUTH_SECRET: string
  JWKS_SECRET: string

  // GitHub App (claim-by-commit)
  GITHUB_APP_ID?: string
  GITHUB_APP_PRIVATE_KEY?: string
  GITHUB_WEBHOOK_SECRET?: string
}

// ============================================================================
// IdentityDO
// ============================================================================

export class IdentityDO extends DurableObject<IdentityEnv> {
  readonly ns = 'https://id.org.ai'

  constructor(ctx: DurableObjectState, env: IdentityEnv) {
    super(ctx, env)
    ctx.blockConcurrencyWhile(async () => {
      const done = await ctx.storage.get<boolean>('_idx_backfilled')
      if (!done) {
        await this.identityService.backfillIndexes()
        await ctx.storage.put('_idx_backfilled', true)
      }
    })
  }

  // ── RPC Method Routing ──────────────────────────────────────
  // getIdentity()          → this.identityService              (Phase 4)
  // createIdentity()       → this.identityService              (Phase 4)
  // provisionAnonymous()   → this.identityService + DO session (Phase 4)
  // freezeIdentity()       → this.identityService + DO cleanup (Phase 4)
  // auditEvent()           → this.auditService.logFireAndForget
  // queryAuditLog()        → this.auditService                (Phase 2)
  // mcpDo/Search/Fetch     → this.entityStore                 (Phase 3)
  // createApiKey()         → this.keyService.apiKeys           (Phase 5)
  // listApiKeys()          → this.keyService.apiKeys           (Phase 5)
  // revokeApiKey()         → this.keyService.apiKeys           (Phase 5)
  // validateApiKey()       → this.keyService.apiKeys           (Phase 5)
  // registerAgentKey()     → this.keyService.agentKeys         (Phase 5)
  // verifyAgentSignature() → this.keyService.agentKeys         (Phase 5)
  // listAgentKeys()        → this.keyService.agentKeys         (Phase 5)
  // revokeAgentKey()       → this.keyService.agentKeys         (Phase 5)
  // checkRateLimit()       → this.keyService.rateLimit         (Phase 5)
  // claim()                → direct (Phase 8)
  // getSession()           → this.sessionService              (Phase 6)
  // listSessions()         → this.sessionService              (Phase 6)
  // findSessionForIdentity → this.sessionService              (Phase 6)

  // ─── Service Layer ────────────────────────────────────────────────────

  private _storageAdapter?: StorageAdapter

  private get storageAdapter(): StorageAdapter {
    if (!this._storageAdapter) {
      this._storageAdapter = new DurableObjectStorageAdapter(this.ctx.storage)
    }
    return this._storageAdapter
  }

  private _auditService?: AuditService

  private get auditService(): AuditService {
    if (!this._auditService) {
      this._auditService = new AuditServiceImpl({ storage: this.storageAdapter })
    }
    return this._auditService
  }

  private _entityStore?: EntityStoreService

  private get entityStore(): EntityStoreService {
    if (!this._entityStore) {
      this._entityStore = new EntityStoreServiceImpl({ storage: this.storageAdapter })
    }
    return this._entityStore
  }

  private _identityService?: IdentityServiceImpl

  private get identityService(): IdentityServiceImpl {
    if (!this._identityService) {
      this._identityService = new IdentityServiceImpl({ storage: this.storageAdapter, audit: this.auditService })
    }
    return this._identityService
  }

  private _keyService?: KeyServiceImpl

  private get keyService(): KeyServiceImpl {
    if (!this._keyService) {
      this._keyService = new KeyServiceImpl({
        storage: this.storageAdapter,
        audit: this.auditService,
        identity: this.identityService,
      })
    }
    return this._keyService
  }

  private _sessionService?: SessionServiceImpl

  private get sessionService(): SessionServiceImpl {
    if (!this._sessionService) {
      this._sessionService = new SessionServiceImpl({ storage: this.storageAdapter, identityReader: this.identityService })
    }
    return this._sessionService
  }

  private _agentService?: AgentService

  private get agentService(): AgentService {
    if (!this._agentService) {
      this._agentService = new AgentServiceImpl({
        storage: this.storageAdapter,
        audit: this.auditService,
        tenantExists: (id: string) => this.identityService.exists(id),
      })
    }
    return this._agentService
  }

  // ─── Identity Management ──────────────────────────────────────────────

  async createIdentity(data: {
    type: IdentityType
    name: string
    email?: string
    handle?: string
    capabilities?: string[]
    ownerId?: string
    level?: CapabilityLevel
    id?: string
  }): Promise<Identity> {
    const result = await this.identityService.create(data)
    if (!result.success) throw new Error(result.error.message)
    return result.data.identity
  }

  async getIdentity(id: string): Promise<Identity | null> {
    const result = await this.identityService.get(id)
    if (!result.success) return null
    return result.data
  }

  // ─── Anonymous Provisioning ───────────────────────────────────────────

  async provisionAnonymous(presetIdentityId?: string): Promise<{
    identity: Identity
    sessionToken: string
    claimToken: string
  }> {
    const result = await this.identityService.create({
      type: 'tenant',
      name: `anon_${crypto.randomUUID().slice(0, 8)}`,
      level: 1,
      id: presetIdentityId,
    })
    if (!result.success) throw new Error(result.error.message)

    const { identity, claimToken } = result.data

    // Session creation delegated to SessionService (Phase 6)
    const sessionResult = await this.sessionService.create(identity.id, 1, 86400000)
    if (!sessionResult.success) throw new Error('Failed to create session')
    const sessionToken = sessionResult.data.token

    return { identity, sessionToken, claimToken }
  }

  // ─── Claim-by-Commit ─────────────────────────────────────────────────

  async claim(data: {
    claimToken: string
    githubUserId: string
    githubUsername: string
    githubEmail?: string
    repo?: string
    branch?: string
    defaultBranch?: string
  }): Promise<{ success: boolean; identity?: Identity; error?: string }> {
    const lookupResult = await this.identityService.getByClaimToken(data.claimToken)
    if (!lookupResult.success) {
      return { success: false, error: 'Invalid claim token' }
    }

    const target = lookupResult.data
    if (target.claimStatus === 'claimed') {
      return { success: false, error: 'Tenant already claimed' }
    }

    const claimed = isClaimedBranch(data.branch, data.defaultBranch)
    const claimStatus: ClaimStatus = claimed ? 'claimed' : 'pending'

    const updateResult = await this.identityService.update(target.id, {
      claimStatus,
      level: claimed ? 2 : target.level,
      githubUserId: data.githubUserId,
      githubUsername: data.githubUsername,
      email: data.githubEmail ?? target.email,
    })
    if (!updateResult.success) {
      return { success: false, error: updateResult.error.message }
    }

    // linkAccount enforces a single account per provider. If the agent claims
    // again from a different repo before the first claim is finalised, the
    // second link is a soft no-op — we keep the original record.
    await this.identityService.linkAccount(target.id, {
      provider: 'github',
      providerAccountId: data.githubUserId,
      type: 'auth',
      displayName: data.githubUsername,
      email: data.githubEmail,
      metadata: data.repo ? { repo: data.repo } : undefined,
    })

    return { success: true, identity: updateResult.data }
  }

  // ─── Claim Token Verification ────────────────────────────────────────

  async verifyClaimToken(token: string): Promise<{
    valid: boolean
    identityId?: string
    status?: ClaimStatus
    level?: CapabilityLevel
    stats?: { entities: number; events: number; createdAt: number; expiresAt?: number }
  }> {
    if (!token.startsWith('clm_')) {
      return { valid: false }
    }

    const lookupResult = await this.identityService.getByClaimToken(token)
    if (!lookupResult.success) {
      return { valid: false }
    }

    const identity = lookupResult.data

    // Count entities and events for this identity
    const entities = await this.ctx.storage.list({ prefix: `entity:${identity.id}:` })
    const events = await this.ctx.storage.list({ prefix: `event:${identity.id}:` })

    const session = await this.findSessionForIdentity(identity.id)

    return {
      valid: true,
      identityId: identity.id,
      status: identity.claimStatus,
      level: identity.level,
      stats: {
        entities: entities.size,
        events: events.size,
        createdAt: identity.createdAt,
        expiresAt: session?.expiresAt,
      },
    }
  }

  // ─── Session Management ─────────────────────────────────────────────

  async getSession(token: string): Promise<{
    valid: boolean
    identityId?: string
    level?: CapabilityLevel
    expiresAt?: number
  }> {
    return this.sessionService.get(token)
  }

  async listSessions(identityId: string): Promise<Array<{
    token: string
    createdAt: number
    expiresAt: number
  }>> {
    return this.sessionService.list(identityId)
  }

  private async findSessionForIdentity(identityId: string): Promise<AuthSessionData | null> {
    return this.sessionService.findForIdentity(identityId)
  }

  // ─── Freeze Identity ────────────────────────────────────────────────

  async freezeIdentity(id: string): Promise<{
    frozen: boolean
    stats: { entities: number; events: number; sessions: number }
    expiresAt: number
  }> {
    // Identity state change delegated to IdentityServiceImpl (Phase 4)
    const result = await this.identityService.freeze(id, 'user-initiated')
    if (!result.success) throw new Error(result.error.message)

    // Session cleanup delegated to SessionService (Phase 6)
    const sessionCount = await this.sessionService.deleteAllForIdentity(id)

    // Stats counting stays in DO (cross-domain concern)
    const entityEntries = await this.ctx.storage.list({ prefix: `entity:${id}:` })
    const eventEntries = await this.ctx.storage.list({ prefix: `event:${id}:` })

    return {
      frozen: true,
      stats: {
        entities: entityEntries.size,
        events: eventEntries.size,
        sessions: sessionCount,
      },
      expiresAt: result.data.frozenAt! + 30 * 24 * 60 * 60 * 1000,
    }
  }

  // ─── Rate Limiting (delegated to KeyService — Phase 5) ────────────────

  async checkRateLimit(identityId: string, level: CapabilityLevel): Promise<{
    allowed: boolean
    remaining: number
    resetAt: number
  }> {
    return this.keyService.rateLimit.check(identityId, level)
  }

  // ─── API Key Management (delegated to KeyService — Phase 5) ───────────

  async createApiKey(data: {
    name: string
    identityId: string
    scopes?: string[]
    expiresAt?: string
  }): Promise<{ id: string; key: string; name: string; prefix: string; scopes: string[]; createdAt: string; expiresAt?: string }> {
    const result = await this.keyService.apiKeys.create(data)
    if (!result.success) throw new Error(result.error.message)
    return result.data
  }

  async listApiKeys(identityId: string): Promise<Array<{
    id: string; name: string; prefix: string; scopes: string[]; status: string;
    createdAt: string; expiresAt?: string; lastUsedAt?: string
  }>> {
    return this.keyService.apiKeys.list(identityId)
  }

  async revokeApiKey(keyId: string, identityId: string): Promise<{
    id: string; status: string; revokedAt: string; key?: string
  } | null> {
    const result = await this.keyService.apiKeys.revoke(keyId, identityId)
    if (!result.success) return null
    return result.data
  }

  async validateApiKey(key: string): Promise<{
    valid: boolean
    identityId?: string
    scopes?: string[]
    level?: CapabilityLevel
  }> {
    const result = await this.keyService.apiKeys.validate(key)
    if (!result.success) return { valid: false }
    return result.data
  }

  // ─── Agent Key Management (delegated to KeyService — Phase 5) ─────────

  async registerAgentKey(data: {
    identityId: string
    publicKey: string
    label?: string
  }): Promise<{ id: string; did: string }> {
    const result = await this.keyService.agentKeys.register(data)
    if (!result.success) throw new Error(result.error.message)
    return result.data
  }

  async verifyAgentSignature(data: {
    did: string
    message: string
    signature: string
  }): Promise<{ valid: boolean; identityId?: string }> {
    const result = await this.keyService.agentKeys.verify(data)
    if (!result.success) return { valid: false }
    return result.data
  }

  async listAgentKeys(identityId: string): Promise<Array<{
    id: string
    did: string
    label?: string
    createdAt: number
    revokedAt?: number
  }>> {
    return this.keyService.agentKeys.list(identityId)
  }

  async revokeAgentKey(keyId: string): Promise<boolean> {
    const result = await this.keyService.agentKeys.revoke(keyId)
    if (!result.success) return false
    return result.data
  }

  // ─── OAuth Client Seeding ──────────────────────────────────────────

  // All three RPC names seed the same default-client list. The names exist for
  // historical reasons (separate seeding paths used to live in the IdentityDO);
  // the canonical owner is now src/sdk/oauth/clients.ts.

  async ensureCliClient(): Promise<void> {
    await seedDefaultClients(this.ctx.storage)
  }

  async ensureOAuthDoClient(): Promise<void> {
    await seedDefaultClients(this.ctx.storage)
  }

  async ensureWebClients(): Promise<void> {
    await seedDefaultClients(this.ctx.storage)
  }

  // ─── OAuth Storage (RPC) ───────────────────────────────────────────

  async oauthStorageOp(op: {
    op: 'get' | 'put' | 'delete' | 'list'
    key?: string
    value?: unknown
    options?: { expirationTtl?: number; prefix?: string; limit?: number }
  }): Promise<Record<string, unknown>> {
    if (op.op === 'get' && op.key) {
      const value = await this.ctx.storage.get(op.key)
      return { value: value ?? undefined }
    }

    if (op.op === 'put' && op.key) {
      await this.ctx.storage.put(op.key, op.value)
      return { ok: true }
    }

    if (op.op === 'delete' && op.key) {
      const deleted = await this.ctx.storage.delete(op.key)
      return { deleted }
    }

    if (op.op === 'list') {
      const opts: { prefix?: string; limit?: number } = {}
      if (op.options?.prefix) opts.prefix = op.options.prefix
      if (op.options?.limit) opts.limit = op.options.limit
      const entries = await this.ctx.storage.list(opts)
      return { entries: Array.from(entries.entries()) }
    }

    throw new Error(`Unknown storage operation: ${op.op}`)
  }

  // ─── Agents (RPC) ────────────────────────────────────────────────────

  async registerAgent(input: RegisterAgentInput): Promise<{ success: boolean; agent?: Agent; error?: string }> {
    const result = await this.agentService.register(input)
    if (!result.success) return { success: false, error: result.error.message }
    return { success: true, agent: result.data.agent }
  }

  async getAgent(id: string): Promise<Agent | null> {
    const result = await this.agentService.get(id)
    if (!result.success) return null
    return result.data
  }

  async listAgents(tenantId: string): Promise<AgentInfo[]> {
    return this.agentService.list(tenantId)
  }

  async getAgentByPublicKey(publicKey: string): Promise<Agent | null> {
    const result = await this.agentService.getByPublicKey(publicKey)
    if (!result.success) return null
    return result.data
  }

  async updateAgentStatus(id: string, status: AgentStatus, reason?: string): Promise<{ success: boolean; agent?: Agent; error?: string }> {
    const result = await this.agentService.updateStatus(id, { status, reason })
    if (!result.success) return { success: false, error: result.error.message }
    return { success: true, agent: result.data }
  }

  async revokeAgent(id: string, reason?: string): Promise<{ success: boolean; agent?: Agent; error?: string }> {
    const result = await this.agentService.revoke(id, reason)
    if (!result.success) return { success: false, error: result.error.message }
    return { success: true, agent: result.data }
  }

  async reactivateAgent(id: string): Promise<{ success: boolean; agent?: Agent; error?: string }> {
    const result = await this.agentService.reactivate(id)
    if (!result.success) return { success: false, error: result.error.message }
    return { success: true, agent: result.data }
  }

  async touchAgent(id: string): Promise<void> {
    await this.agentService.touch(id)
  }

  // ─── Audit Log (RPC) ────────────────────────────────────────────────

  async auditEvent(event: Omit<AuditEvent, 'timestamp'> & { timestamp?: string }): Promise<void> {
    await this.auditService.logFireAndForget(event)
  }

  async queryAuditLog(options: AuditQueryOptions): Promise<{ events: StoredAuditEvent[]; total: number; cursor?: string; hasMore: boolean }> {
    return this.auditService.query(options)
  }

  // ─── MCP Do (RPC) ──────────────────────────────────────────────────

  async mcpDo(params: {
    entity: string
    verb: string
    data: Record<string, unknown>
    identityId?: string
    authLevel: number
    timestamp: number
  }): Promise<{ success: boolean; entity: string; verb: string; result?: Record<string, unknown>; events?: unknown[]; error?: string }> {
    if (params.authLevel < 1) {
      return { success: false, entity: params.entity, verb: params.verb, error: 'L1+ authentication required for entity operations' }
    }

    const entityId = params.data.id as string ?? crypto.randomUUID()
    const owner = params.identityId ?? 'global'

    if (params.verb === 'create') {
      const record = {
        ...params.data,
        id: entityId,
        $type: params.entity,
        createdAt: params.timestamp,
        updatedAt: params.timestamp,
      }
      const putResult = await this.entityStore.put(owner, params.entity, entityId, record)
      if (!putResult.success) return { success: false, entity: params.entity, verb: params.verb, error: putResult.error.message }

      const eventKey = `event:${owner}:${crypto.randomUUID()}`
      await this.ctx.storage.put(eventKey, {
        type: `${params.entity}.${params.verb}ed`,
        entityType: params.entity,
        entityId,
        verb: params.verb,
        data: record,
        timestamp: params.timestamp,
      })

      await this.auditService.logFireAndForget({
        event: 'entity.create',
        actor: params.identityId,
        target: entityId,
        metadata: { entity: params.entity, owner },
      })

      return {
        success: true,
        entity: params.entity,
        verb: params.verb,
        result: record,
        events: [
          { type: `${params.verb}ing`, entity: params.entity, verb: params.verb, timestamp: new Date(params.timestamp).toISOString() },
          { type: `${params.verb}ed`, entity: params.entity, verb: params.verb, timestamp: new Date(params.timestamp).toISOString() },
        ],
      }
    }

    if (params.verb === 'update') {
      const getResult = await this.entityStore.get(owner, params.entity, entityId)
      if (!getResult.success) {
        return { success: false, entity: params.entity, verb: params.verb, error: `${params.entity} not found: ${entityId}` }
      }
      const existing = getResult.data
      await this.entityStore.deleteIndexes(owner, params.entity, entityId, existing)
      const record = { ...existing, ...params.data, $type: params.entity, updatedAt: params.timestamp }
      const putResult = await this.entityStore.put(owner, params.entity, entityId, record)
      if (!putResult.success) return { success: false, entity: params.entity, verb: params.verb, error: putResult.error.message }

      await this.auditService.logFireAndForget({
        event: 'entity.update',
        actor: params.identityId,
        target: entityId,
        metadata: { entity: params.entity, owner },
      })

      return {
        success: true,
        entity: params.entity,
        verb: params.verb,
        result: record,
        events: [
          { type: 'updating', entity: params.entity, verb: params.verb, timestamp: new Date(params.timestamp).toISOString() },
          { type: 'updated', entity: params.entity, verb: params.verb, timestamp: new Date(params.timestamp).toISOString() },
        ],
      }
    }

    if (params.verb === 'delete') {
      const deleteResult = await this.entityStore.delete(owner, params.entity, entityId)
      const deleted = deleteResult.success ? deleteResult.data.deleted : false

      await this.auditService.logFireAndForget({
        event: 'entity.delete',
        actor: params.identityId,
        target: entityId,
        metadata: { entity: params.entity, owner, deleted },
      })

      return {
        success: true,
        entity: params.entity,
        verb: params.verb,
        result: { id: entityId, deleted },
        events: [
          { type: 'deleting', entity: params.entity, verb: params.verb, timestamp: new Date(params.timestamp).toISOString() },
          { type: 'deleted', entity: params.entity, verb: params.verb, timestamp: new Date(params.timestamp).toISOString() },
        ],
      }
    }

    if (params.verb === 'get') {
      const getResult = await this.entityStore.get(owner, params.entity, entityId)
      const existing = getResult.success ? getResult.data : null
      return {
        success: true,
        entity: params.entity,
        verb: params.verb,
        result: existing ?? { id: entityId },
      }
    }

    // Custom verbs (qualify, close, advance, etc.)
    const getResult = await this.entityStore.get(owner, params.entity, entityId)
    const existing = getResult.success ? getResult.data : null
    if (existing) {
      await this.entityStore.deleteIndexes(owner, params.entity, entityId, existing)
    }

    const record = { ...(existing ?? {}), ...params.data, id: entityId, $type: params.entity, updatedAt: params.timestamp }
    const putResult = await this.entityStore.put(owner, params.entity, entityId, record)
    if (!putResult.success) return { success: false, entity: params.entity, verb: params.verb, error: putResult.error.message }

    const eventKey = `event:${owner}:${crypto.randomUUID()}`
    await this.ctx.storage.put(eventKey, {
      type: `${params.entity}.${params.verb}ed`,
      entityType: params.entity,
      entityId,
      verb: params.verb,
      data: record,
      timestamp: params.timestamp,
    })

    await this.auditService.logFireAndForget({
      event: `entity.${params.verb}`,
      actor: params.identityId,
      target: entityId,
      metadata: { entity: params.entity, owner },
    })

    return {
      success: true,
      entity: params.entity,
      verb: params.verb,
      result: record,
      events: [
        { type: `${params.verb}ing`, entity: params.entity, verb: params.verb, timestamp: new Date(params.timestamp).toISOString() },
        { type: `${params.verb}ed`, entity: params.entity, verb: params.verb, timestamp: new Date(params.timestamp).toISOString() },
      ],
    }
  }

  // ─── MCP Search (RPC) ────────────────────────────────────────────────

  async mcpSearch(params: {
    identityId: string
    query?: string
    type?: string
    filters?: Record<string, unknown>
    limit?: number
    offset?: number
  }): Promise<{ results: Array<{ type: string; id: string; data: Record<string, unknown>; score: number }>; total: number; limit: number; offset: number }> {
    const owner = params.identityId ?? 'global'
    const limit = Math.min(params.limit ?? 20, 100)
    const offset = params.offset ?? 0
    const query = params.query?.trim() ?? ''

    if (query || (params.type && (params.filters || query))) {
      // Text search path (with optional type/filters)
      const searchResult = await this.entityStore.search(owner, query, {
        type: params.type,
        filters: params.filters,
        limit,
        offset,
      })
      return { results: searchResult.results, total: searchResult.total, limit, offset }
    }

    // Filter-only path (no query text)
    if (params.type) {
      const queryResult = await this.entityStore.query(owner, params.type, { filters: params.filters, limit, offset })
      const results = queryResult.items.map((item) => ({
        type: params.type!,
        id: String(item.id ?? ''),
        data: item,
        score: 1,
      }))
      return { results, total: queryResult.total, limit, offset }
    }

    // No query, no type — return empty
    return { results: [], total: 0, limit, offset }
  }

  // ─── MCP Fetch (RPC) ─────────────────────────────────────────────────

  async mcpFetch(params: {
    identityId: string
    type: string
    id?: string
    filters?: Record<string, unknown>
    limit?: number
    offset?: number
  }): Promise<Record<string, unknown>> {
    const owner = params.identityId ?? 'global'

    if (params.id) {
      const result = await this.entityStore.get(owner, params.type, params.id)
      return { type: params.type, id: params.id, data: result.success ? result.data : null }
    }

    const limit = Math.min(params.limit ?? 20, 100)
    const offset = params.offset ?? 0
    const queryResult = await this.entityStore.query(owner, params.type, { filters: params.filters, limit, offset })

    return { type: params.type, items: queryResult.items, total: queryResult.total, limit, offset }
  }

  // ─── HTTP Handler (health check only) ─────────────────────────────────

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url)

    if (url.pathname === '/health') {
      return Response.json({
        status: 'ok',
        ns: this.ns,
        tagline: 'Humans. Agents. Identity.',
      })
    }

    return Response.json({ error: 'Not found', message: 'Use Workers RPC to call IdentityDO methods directly' }, { status: 404 })
  }

  // ─── WorkOS Widget Token Support ────────────────────────────────────

  async storeWorkOSRefreshToken(token: string): Promise<void> {
    await this.ctx.storage.put('workos:refresh_token', token)
  }

  async clearWorkOSRefreshToken(): Promise<void> {
    await this.ctx.storage.delete('workos:refresh_token')
    await this.ctx.storage.delete('workos:cached_access_token')
    await this.ctx.storage.delete('workos:cached_token_expiry')
    await this.ctx.storage.delete('workos:cached_token_org')
  }

  async refreshWorkOSToken(
    credentials: { clientId: string; apiKey: string },
    organizationId?: string,
  ): Promise<string> {
    // Check cache first
    const cachedToken = await this.ctx.storage.get<string>('workos:cached_access_token')
    const cachedExpiry = await this.ctx.storage.get<number>('workos:cached_token_expiry')
    const cachedOrg = await this.ctx.storage.get<string | undefined>('workos:cached_token_org')

    if (cachedToken && cachedExpiry && cachedExpiry > Date.now() + 30_000 && cachedOrg === organizationId) {
      return cachedToken
    }

    // Need to refresh
    const refreshToken = await this.ctx.storage.get<string>('workos:refresh_token')
    if (!refreshToken) {
      throw new Error('No WorkOS refresh token stored — user must re-authenticate')
    }

    try {
      const result = await refreshWorkOSAccessToken(
        credentials.clientId,
        credentials.apiKey,
        refreshToken,
        organizationId,
      )

      // Store rotated refresh token
      if (result.refresh_token) {
        await this.ctx.storage.put('workos:refresh_token', result.refresh_token)
      }

      // Cache access token
      const expiresIn = result.expires_in ?? 300
      await this.ctx.storage.put('workos:cached_access_token', result.access_token)
      await this.ctx.storage.put('workos:cached_token_expiry', Date.now() + expiresIn * 1000)
      await this.ctx.storage.put('workos:cached_token_org', organizationId)

      return result.access_token
    } catch (err) {
      // If refresh failed with 401 (token revoked/expired), clear stored tokens
      if (err instanceof Error && err.message.includes('401')) {
        await this.clearWorkOSRefreshToken()
      }
      throw err
    }
  }
}
