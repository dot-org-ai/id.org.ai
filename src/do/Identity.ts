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
import { publicKeyToDID, didToPublicKey, pemToPublicKey, verify as ed25519Verify, base64Decode, base64Encode, isValidDID } from '../crypto/keys'
// errorJson/ErrorCode no longer needed — fetch() is health-check only, all routes are RPC
import type { AuditQueryOptions, StoredAuditEvent } from '../audit'
import { AuditServiceImpl } from '../services/audit'
import type { AuditService } from '../services/audit'
import { EntityStoreServiceImpl } from '../services/entity-store'
import type { EntityStoreService } from '../services/entity-store'
import { IdentityServiceImpl } from '../services/identity/service'
import { refreshWorkOSAccessToken } from '../workos'

// ============================================================================
// Types
// ============================================================================

/**
 * IdentityStub — the RPC interface for IdentityDO.
 *
 * All consumers use this type instead of the concrete class or `{ fetch() }`.
 * Workers RPC calls these methods directly on the DO stub — no HTTP overhead,
 * no X-Worker-Auth headers, no JSON serialization/deserialization.
 */
export interface IdentityStub {
  // Identity
  getIdentity(id: string): Promise<Identity | null>
  provisionAnonymous(presetIdentityId?: string): Promise<{ identity: Identity; sessionToken: string; claimToken: string }>
  claim(data: { claimToken: string; githubUserId: string; githubUsername: string; githubEmail?: string; repo?: string; branch?: string }): Promise<{ success: boolean; identity?: Identity; error?: string }>

  // Auth
  getSession(token: string): Promise<{ valid: boolean; identityId?: string; level?: CapabilityLevel; expiresAt?: number }>
  validateApiKey(key: string): Promise<{ valid: boolean; identityId?: string; scopes?: string[]; level?: CapabilityLevel }>
  createApiKey(data: { name: string; identityId: string; scopes?: string[]; expiresAt?: string }): Promise<{ id: string; key: string; name: string; prefix: string; scopes: string[]; createdAt: string; expiresAt?: string }>
  listApiKeys(identityId: string): Promise<Array<{ id: string; name: string; prefix: string; scopes: string[]; status: string; createdAt: string; expiresAt?: string; lastUsedAt?: string }>>
  revokeApiKey(keyId: string, identityId: string): Promise<{ id: string; status: string; revokedAt: string; key?: string } | null>
  checkRateLimit(identityId: string, level: CapabilityLevel): Promise<{ allowed: boolean; remaining: number; resetAt: number }>
  verifyClaimToken(token: string): Promise<{ valid: boolean; identityId?: string; status?: ClaimStatus; level?: CapabilityLevel; stats?: { entities: number; events: number; createdAt: number; expiresAt?: number } }>
  freezeIdentity(id: string): Promise<{ frozen: boolean; stats: { entities: number; events: number; sessions: number }; expiresAt: number }>

  // MCP
  mcpSearch(params: { identityId: string; query?: string; type?: string; filters?: Record<string, unknown>; limit?: number; offset?: number }): Promise<{ results: Array<{ type: string; id: string; data: Record<string, unknown>; score: number }>; total: number; limit: number; offset: number }>
  mcpFetch(params: { identityId: string; type: string; id?: string; filters?: Record<string, unknown>; limit?: number; offset?: number }): Promise<Record<string, unknown>>
  mcpDo(params: { entity: string; verb: string; data: Record<string, unknown>; identityId?: string; authLevel: number; timestamp: number }): Promise<{ success: boolean; entity: string; verb: string; result?: Record<string, unknown>; events?: unknown[]; error?: string }>

  // OAuth
  ensureCliClient(): Promise<void>
  ensureOAuthDoClient(): Promise<void>
  ensureWebClients(): Promise<void>
  oauthStorageOp(op: { op: 'get' | 'put' | 'delete' | 'list'; key?: string; value?: unknown; options?: { expirationTtl?: number; prefix?: string; limit?: number } }): Promise<Record<string, unknown>>

  // Audit
  writeAuditEvent(key: string, event: StoredAuditEvent): Promise<void>
  queryAuditLog(options: AuditQueryOptions): Promise<{ events: StoredAuditEvent[]; cursor?: string; hasMore: boolean }>

  // WorkOS widget token support
  storeWorkOSRefreshToken(token: string): Promise<void>
  refreshWorkOSToken(credentials: { clientId: string; apiKey: string }, organizationId?: string): Promise<string>
  clearWorkOSRefreshToken(): Promise<void>
}

export type IdentityType = 'human' | 'agent' | 'service'

export type ClaimStatus = 'unclaimed' | 'pending' | 'claimed' | 'frozen' | 'expired'

export type CapabilityLevel = 0 | 1 | 2 | 3

export interface Identity {
  id: string
  type: IdentityType
  name: string
  handle?: string
  email?: string
  image?: string
  verified: boolean
  level: CapabilityLevel
  claimStatus: ClaimStatus
  frozen?: boolean
  frozenAt?: number
  githubUserId?: string
  githubUsername?: string
}

export interface LinkedAccount {
  id: string
  provider: string
  type: 'auth' | 'payment' | 'ai' | 'platform' | 'service'
  displayName?: string
  status: 'active' | 'pending' | 'expired' | 'revoked'
}

export interface SessionData {
  identityId: string
  level: CapabilityLevel
  createdAt: number
  expiresAt: number
}

export interface RateLimitEntry {
  identityId: string
  windowStart: number
  requestCount: number
}

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
// Rate limit configuration by capability level
// ============================================================================

const RATE_LIMITS: Record<CapabilityLevel, { maxRequests: number; windowMs: number }> = {
  0: { maxRequests: 30, windowMs: 60_000 },
  1: { maxRequests: 100, windowMs: 60_000 },
  2: { maxRequests: 1000, windowMs: 60_000 },
  3: { maxRequests: Infinity, windowMs: 60_000 },
}

// ============================================================================
// IdentityDO
// ============================================================================

export class IdentityDO extends DurableObject<IdentityEnv> {
  readonly ns = 'https://id.org.ai'

  // ── RPC Method Routing ──────────────────────────────────────
  // getIdentity()       → this.identityService.get()            (Phase 4)
  // createIdentity()    → this.identityService.create()         (Phase 4)
  // provisionAnonymous()→ this.identityService.create() + DO session (Phase 4)
  // freezeIdentity()    → this.identityService.freeze() + DO session cleanup (Phase 4)
  // writeAuditEvent()   → this.auditService                   (Phase 2)
  // queryAuditLog()     → this.auditService                   (Phase 2)
  // mcpDo/Search/Fetch  → this.entityStore                    (Phase 3)
  // claim()             → direct (Phase 8)
  // getSession()        → direct (Phase 6)
  // createApiKey()      → direct (Phase 5)

  // ─── Service Layer ────────────────────────────────────────────────────

  private _auditService?: AuditService

  private get auditService(): AuditService {
    if (!this._auditService) {
      this._auditService = new AuditServiceImpl({ storage: this.ctx.storage })
    }
    return this._auditService
  }

  private _entityStore?: EntityStoreService

  private get entityStore(): EntityStoreService {
    if (!this._entityStore) {
      this._entityStore = new EntityStoreServiceImpl({ storage: this.ctx.storage })
    }
    return this._entityStore
  }

  private _identityService?: IdentityServiceImpl

  private get identityService(): IdentityServiceImpl {
    if (!this._identityService) {
      this._identityService = new IdentityServiceImpl({ storage: this.ctx.storage, audit: this.auditService })
    }
    return this._identityService
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
      type: 'agent',
      name: `anon_${crypto.randomUUID().slice(0, 8)}`,
      level: 1,
      id: presetIdentityId,
    })
    if (!result.success) throw new Error(result.error.message)

    const { identity, claimToken } = result.data
    const sessionToken = `ses_${crypto.randomUUID().replace(/-/g, '')}`

    await this.ctx.storage.put(`session:${sessionToken}`, {
      identityId: identity.id,
      level: 1,
      createdAt: Date.now(),
      expiresAt: Date.now() + 24 * 60 * 60 * 1000, // 24h TTL
    })

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
  }): Promise<{ success: boolean; identity?: Identity; error?: string }> {
    // Find identity by claim token
    const entries = await this.ctx.storage.list<any>({ prefix: 'identity:' })
    let targetId: string | null = null
    let targetData: any = null

    for (const [key, value] of entries) {
      if (value.claimToken === data.claimToken) {
        targetId = value.id
        targetData = value
        break
      }
    }

    if (!targetId || !targetData) {
      return { success: false, error: 'Invalid claim token' }
    }

    if (targetData.claimStatus === 'claimed') {
      return { success: false, error: 'Tenant already claimed' }
    }

    // Determine claim status based on branch
    const claimStatus: ClaimStatus = data.branch === 'main' || data.branch === 'master'
      ? 'claimed'
      : 'pending'

    // Upgrade identity
    await this.ctx.storage.put(`identity:${targetId}`, {
      ...targetData,
      claimStatus,
      level: claimStatus === 'claimed' ? 2 : targetData.level,
      githubUserId: data.githubUserId,
      githubUsername: data.githubUsername,
      email: data.githubEmail ?? targetData.email,
      repo: data.repo,
      claimedAt: Date.now(),
    })

    // Link GitHub account
    await this.ctx.storage.put(`linked:${targetId}:github`, {
      provider: 'github',
      providerAccountId: data.githubUserId,
      type: 'auth',
      displayName: data.githubUsername,
      email: data.githubEmail,
      status: 'active',
      createdAt: Date.now(),
    })

    const identity = await this.getIdentity(targetId)
    return { success: true, identity: identity! }
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

    const entries = await this.ctx.storage.list<any>({ prefix: 'identity:' })
    for (const [, value] of entries) {
      if (value.claimToken === token) {
        // Count entities and events for this identity
        const entityPrefix = `entity:${value.id}:`
        const eventPrefix = `event:${value.id}:`
        const entities = await this.ctx.storage.list({ prefix: entityPrefix })
        const events = await this.ctx.storage.list({ prefix: eventPrefix })

        const session = await this.findSessionForIdentity(value.id)
        const expiresAt = session?.expiresAt

        return {
          valid: true,
          identityId: value.id,
          status: value.claimStatus ?? 'unclaimed',
          level: value.level ?? 0,
          stats: {
            entities: entities.size,
            events: events.size,
            createdAt: value.createdAt,
            expiresAt,
          },
        }
      }
    }

    return { valid: false }
  }

  // ─── Session Management ─────────────────────────────────────────────

  async getSession(token: string): Promise<{
    valid: boolean
    identityId?: string
    level?: CapabilityLevel
    expiresAt?: number
  }> {
    if (!token.startsWith('ses_')) {
      return { valid: false }
    }

    const session = await this.ctx.storage.get<SessionData>(`session:${token}`)
    if (!session) {
      return { valid: false }
    }

    if (Date.now() > session.expiresAt) {
      // Clean up expired session
      await this.ctx.storage.delete(`session:${token}`)
      return { valid: false }
    }

    // Verify the identity still exists and is not frozen
    const identity = await this.ctx.storage.get<any>(`identity:${session.identityId}`)
    if (!identity || identity.frozen) {
      return { valid: false }
    }

    return {
      valid: true,
      identityId: session.identityId,
      level: session.level,
      expiresAt: session.expiresAt,
    }
  }

  async listSessions(identityId: string): Promise<Array<{
    token: string
    createdAt: number
    expiresAt: number
  }>> {
    const entries = await this.ctx.storage.list<SessionData>({ prefix: 'session:' })
    const sessions: Array<{ token: string; createdAt: number; expiresAt: number }> = []
    const now = Date.now()

    for (const [key, value] of entries) {
      if (value.identityId === identityId && value.expiresAt > now) {
        sessions.push({
          token: key.slice('session:'.length),
          createdAt: value.createdAt,
          expiresAt: value.expiresAt,
        })
      }
    }

    return sessions
  }

  private async findSessionForIdentity(identityId: string): Promise<SessionData | null> {
    const entries = await this.ctx.storage.list<SessionData>({ prefix: 'session:' })
    for (const [, value] of entries) {
      if (value.identityId === identityId) {
        return value
      }
    }
    return null
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

    // Session cleanup stays in DO until Auth service extraction (Phase 6)
    const sessions = await this.listSessions(id)
    for (const session of sessions) {
      await this.ctx.storage.delete(`session:${session.token}`)
    }

    // Stats counting stays in DO (cross-domain concern)
    const entityEntries = await this.ctx.storage.list({ prefix: `entity:${id}:` })
    const eventEntries = await this.ctx.storage.list({ prefix: `event:${id}:` })

    return {
      frozen: true,
      stats: {
        entities: entityEntries.size,
        events: eventEntries.size,
        sessions: sessions.length,
      },
      expiresAt: result.data.frozenAt! + 30 * 24 * 60 * 60 * 1000,
    }
  }

  // ─── Rate Limiting ──────────────────────────────────────────────────

  async checkRateLimit(identityId: string, level: CapabilityLevel): Promise<{
    allowed: boolean
    remaining: number
    resetAt: number
  }> {
    const config = RATE_LIMITS[level]
    if (config.maxRequests === Infinity) {
      return { allowed: true, remaining: Infinity, resetAt: 0 }
    }

    const key = `rateLimit:${identityId}`
    const now = Date.now()
    const entry = await this.ctx.storage.get<RateLimitEntry>(key)

    if (!entry || now - entry.windowStart > config.windowMs) {
      // New window — record first request
      await this.ctx.storage.put(key, {
        identityId,
        windowStart: now,
        requestCount: 1,
      } satisfies RateLimitEntry)
      return {
        allowed: true,
        remaining: config.maxRequests - 1,
        resetAt: now + config.windowMs,
      }
    }

    const remaining = config.maxRequests - entry.requestCount - 1
    const resetAt = entry.windowStart + config.windowMs

    if (entry.requestCount >= config.maxRequests) {
      return { allowed: false, remaining: 0, resetAt }
    }

    // Increment counter
    await this.ctx.storage.put(key, {
      ...entry,
      requestCount: entry.requestCount + 1,
    })

    return { allowed: true, remaining: Math.max(0, remaining), resetAt }
  }

  // ─── API Key Management ───────────────────────────────────────────────

  static readonly VALID_SCOPES = new Set(['read', 'write', 'admin'])

  async createApiKey(data: {
    name: string
    identityId: string
    scopes?: string[]
    expiresAt?: string
  }): Promise<{ id: string; key: string; name: string; prefix: string; scopes: string[]; createdAt: string; expiresAt?: string }> {
    if (!data.name) throw new Error('name is required')

    const scopes = data.scopes ?? ['read', 'write']
    for (const s of scopes) {
      if (!IdentityDO.VALID_SCOPES.has(s)) throw new Error(`Invalid scope: ${s}`)
    }

    if (data.expiresAt) {
      const expiry = new Date(data.expiresAt).getTime()
      if (expiry <= Date.now()) throw new Error('expiresAt must be in the future')
    }

    const id = crypto.randomUUID()
    const key = `hly_sk_${crypto.randomUUID().replace(/-/g, '')}${crypto.randomUUID().replace(/-/g, '')}`
    const prefix = key.slice(0, 15)
    const now = new Date().toISOString()

    await this.ctx.storage.put(`apikey:${id}`, {
      id,
      key,
      name: data.name,
      prefix,
      identityId: data.identityId,
      scopes,
      status: 'active',
      createdAt: now,
      expiresAt: data.expiresAt ?? undefined,
      requestCount: 0,
    })

    // Index by key for lookup
    await this.ctx.storage.put(`apikey-lookup:${key}`, id)

    const result: { id: string; key: string; name: string; prefix: string; scopes: string[]; createdAt: string; expiresAt?: string } = {
      id, key, name: data.name, prefix, scopes, createdAt: now,
    }
    if (data.expiresAt) result.expiresAt = data.expiresAt
    return result
  }

  async listApiKeys(identityId: string): Promise<Array<{
    id: string; name: string; prefix: string; scopes: string[]; status: string;
    createdAt: string; expiresAt?: string; lastUsedAt?: string
  }>> {
    const entries = await this.ctx.storage.list<any>({ prefix: 'apikey:' })
    const keys: Array<{
      id: string; name: string; prefix: string; scopes: string[]; status: string;
      createdAt: string; expiresAt?: string; lastUsedAt?: string
    }> = []

    for (const [key, value] of entries) {
      if (key.startsWith('apikey-lookup:')) continue
      if (value.identityId !== identityId) continue
      keys.push({
        id: value.id,
        name: value.name,
        prefix: value.prefix ?? (value.key ? value.key.slice(0, 15) : ''),
        scopes: value.scopes ?? ['read', 'write'],
        status: value.status ?? (value.enabled === false ? 'revoked' : 'active'),
        createdAt: value.createdAt ?? new Date(0).toISOString(),
        expiresAt: value.expiresAt,
        lastUsedAt: value.lastUsedAt,
      })
    }

    return keys
  }

  async revokeApiKey(keyId: string, identityId: string): Promise<{
    id: string; status: string; revokedAt: string; key?: string
  } | null> {
    const apiKey = await this.ctx.storage.get<any>(`apikey:${keyId}`)
    if (!apiKey) return null
    if (apiKey.identityId !== identityId) return null

    const revokedAt = new Date().toISOString()
    await this.ctx.storage.put(`apikey:${keyId}`, {
      ...apiKey,
      status: 'revoked',
      enabled: false,
      revokedAt,
    })

    // Remove lookup index so the key can't be used for auth
    if (apiKey.key) {
      await this.ctx.storage.delete(`apikey-lookup:${apiKey.key}`)
    }

    return { id: keyId, status: 'revoked', revokedAt, key: apiKey.key }
  }

  async validateApiKey(key: string): Promise<{
    valid: boolean
    identityId?: string
    scopes?: string[]
    level?: CapabilityLevel
  }> {
    const id = await this.ctx.storage.get<string>(`apikey-lookup:${key}`)
    if (!id) return { valid: false }

    const apiKey = await this.ctx.storage.get<any>(`apikey:${id}`)
    if (!apiKey) return { valid: false }
    if (apiKey.status === 'revoked' || apiKey.enabled === false) return { valid: false }

    // Check expiry
    if (apiKey.expiresAt) {
      const expiry = new Date(apiKey.expiresAt).getTime()
      if (Date.now() > expiry) return { valid: false }
    }

    const identity = await this.getIdentity(apiKey.identityId)
    if (!identity) return { valid: false }

    // Update last used
    const now = new Date().toISOString()
    await this.ctx.storage.put(`apikey:${id}`, {
      ...apiKey,
      lastUsedAt: now,
      requestCount: (apiKey.requestCount ?? 0) + 1,
    })

    return {
      valid: true,
      identityId: apiKey.identityId,
      scopes: apiKey.scopes,
      level: identity.level,
    }
  }

  // ─── Agent Key Management ───────────────────────────────────────────

  /**
   * Register an Ed25519 public key for an agent identity.
   *
   * Accepts the public key in base64, PEM, or raw hex format.
   * Computes the DID (did:agent:ed25519:{base58pubkey}) and stores
   * the key in DO storage indexed by both key ID and DID.
   */
  async registerAgentKey(data: {
    identityId: string
    publicKey: string // base64 or PEM format
    label?: string
  }): Promise<{ id: string; did: string }> {
    // Verify the identity exists
    const identity = await this.getIdentity(data.identityId)
    if (!identity) {
      throw new Error('Identity not found')
    }

    // Parse the public key — accept PEM or base64
    let rawPublicKey: Uint8Array
    try {
      if (data.publicKey.includes('-----BEGIN PUBLIC KEY-----')) {
        rawPublicKey = pemToPublicKey(data.publicKey)
      } else {
        rawPublicKey = base64Decode(data.publicKey)
      }
    } catch (err: any) {
      throw new Error(`Invalid public key format: ${err.message}`)
    }

    if (rawPublicKey.length !== 32) {
      throw new Error(`Expected 32-byte Ed25519 public key, got ${rawPublicKey.length} bytes`)
    }

    // Compute DID
    const did = publicKeyToDID(rawPublicKey)

    // Check for duplicate DID
    const existingKey = await this.ctx.storage.get<any>(`agentkey-did:${did}`)
    if (existingKey) {
      throw new Error(`An agent key with DID ${did} is already registered`)
    }

    // Store the key
    const id = crypto.randomUUID()
    const keyRecord = {
      id,
      identityId: data.identityId,
      publicKey: base64Encode(rawPublicKey),
      algorithm: 'Ed25519',
      did,
      label: data.label,
      createdAt: Date.now(),
      revokedAt: null as number | null,
    }

    await this.ctx.storage.put(`agentkey:${id}`, keyRecord)
    // Index by DID for fast lookup during verification
    await this.ctx.storage.put(`agentkey-did:${did}`, id)
    // Index by identity for listing
    const identityKeysKey = `agentkeys:${data.identityId}`
    const existingIds = await this.ctx.storage.get<string[]>(identityKeysKey) ?? []
    existingIds.push(id)
    await this.ctx.storage.put(identityKeysKey, existingIds)

    return { id, did }
  }

  /**
   * Verify a signed request from an agent.
   *
   * Resolves the DID to a stored public key, then verifies the Ed25519
   * signature over the provided message. Returns the identity ID on success.
   */
  async verifyAgentSignature(data: {
    did: string
    message: string
    signature: string // base64
  }): Promise<{ valid: boolean; identityId?: string }> {
    // Validate DID format
    if (!isValidDID(data.did)) {
      return { valid: false }
    }

    // Look up the key by DID
    const keyId = await this.ctx.storage.get<string>(`agentkey-did:${data.did}`)
    if (!keyId) {
      return { valid: false }
    }

    const keyRecord = await this.ctx.storage.get<any>(`agentkey:${keyId}`)
    if (!keyRecord || keyRecord.revokedAt) {
      return { valid: false }
    }

    // Verify the identity is not frozen
    const identity = await this.getIdentity(keyRecord.identityId)
    if (!identity || identity.frozen) {
      return { valid: false }
    }

    // Verify the Ed25519 signature
    try {
      const publicKey = didToPublicKey(data.did)
      const messageBytes = new TextEncoder().encode(data.message)
      const signatureBytes = base64Decode(data.signature)

      const valid = await ed25519Verify(messageBytes, signatureBytes, publicKey)
      if (!valid) {
        return { valid: false }
      }

      return { valid: true, identityId: keyRecord.identityId }
    } catch {
      return { valid: false }
    }
  }

  /**
   * List all agent keys for an identity.
   *
   * Returns non-revoked keys by default. Revoked keys are excluded
   * unless they were revoked within the last 30 days (for audit).
   */
  async listAgentKeys(identityId: string): Promise<Array<{
    id: string
    did: string
    label?: string
    createdAt: number
    revokedAt?: number
  }>> {
    const keyIds = await this.ctx.storage.get<string[]>(`agentkeys:${identityId}`) ?? []
    const keys: Array<{ id: string; did: string; label?: string; createdAt: number; revokedAt?: number }> = []

    for (const keyId of keyIds) {
      const keyRecord = await this.ctx.storage.get<any>(`agentkey:${keyId}`)
      if (!keyRecord) continue

      // Include non-revoked keys and recently-revoked keys (last 30 days)
      const thirtyDaysAgo = Date.now() - 30 * 24 * 60 * 60 * 1000
      if (keyRecord.revokedAt && keyRecord.revokedAt < thirtyDaysAgo) continue

      keys.push({
        id: keyRecord.id,
        did: keyRecord.did,
        label: keyRecord.label,
        createdAt: keyRecord.createdAt,
        revokedAt: keyRecord.revokedAt ?? undefined,
      })
    }

    return keys
  }

  /**
   * Revoke an agent key.
   *
   * Marks the key as revoked (does not delete it, for audit trail).
   * Removes the DID index so the key can no longer be used for verification.
   */
  async revokeAgentKey(keyId: string): Promise<boolean> {
    const keyRecord = await this.ctx.storage.get<any>(`agentkey:${keyId}`)
    if (!keyRecord) {
      return false
    }

    if (keyRecord.revokedAt) {
      return false // Already revoked
    }

    // Mark as revoked
    keyRecord.revokedAt = Date.now()
    await this.ctx.storage.put(`agentkey:${keyId}`, keyRecord)

    // Remove DID index so verification fails immediately
    await this.ctx.storage.delete(`agentkey-did:${keyRecord.did}`)

    return true
  }

  // ─── OAuth Client Seeding ──────────────────────────────────────────

  async ensureCliClient(): Promise<void> {
    const existing = await this.ctx.storage.get('client:id_org_ai_cli')
    if (existing) return

    await this.ctx.storage.put('client:id_org_ai_cli', {
      id: 'id_org_ai_cli',
      name: 'id.org.ai CLI',
      redirectUris: [],
      grantTypes: ['urn:ietf:params:oauth:grant-type:device_code'],
      responseTypes: [],
      scopes: ['openid', 'profile', 'email', 'offline_access'],
      trusted: true,
      tokenEndpointAuthMethod: 'none',
      createdAt: Date.now(),
    })
  }

  async ensureOAuthDoClient(): Promise<void> {
    const existing = await this.ctx.storage.get('client:oauth_do_cli')
    if (existing) return

    await this.ctx.storage.put('client:oauth_do_cli', {
      id: 'oauth_do_cli',
      name: 'oauth.do CLI',
      redirectUris: [],
      grantTypes: ['urn:ietf:params:oauth:grant-type:device_code'],
      responseTypes: [],
      scopes: ['openid', 'profile', 'email', 'offline_access'],
      trusted: true,
      tokenEndpointAuthMethod: 'none',
      createdAt: Date.now(),
    })
  }

  async ensureWebClients(): Promise<void> {
    const clients = [
      {
        id: 'id_org_ai_dash',
        name: 'id.org.ai Dashboard',
        redirectUris: ['https://id.org.ai/dash/profile'],
        grantTypes: ['authorization_code'],
        responseTypes: ['code'],
        scopes: ['openid', 'profile', 'email'],
        trusted: true,
        tokenEndpointAuthMethod: 'none',
        createdAt: Date.now(),
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
        createdAt: Date.now(),
      },
    ]

    for (const client of clients) {
      const existing = await this.ctx.storage.get(`client:${client.id}`)
      if (!existing) {
        await this.ctx.storage.put(`client:${client.id}`, client)
      }
    }
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

  // ─── Audit Log (RPC) ────────────────────────────────────────────────

  // ── RPC Method Routing ──────────────────────────────────────────────────
  // queryAuditLog()   → this.auditService  (Phase 2)
  // writeAuditEvent() → raw storage.put    (legacy, to be migrated)
  // mcpDo()          → this.entityStore   (Phase 3, MCP layer moves in Phase 11)
  // mcpSearch()      → this.entityStore   (Phase 3, MCP layer moves in Phase 11)
  // mcpFetch()       → this.entityStore   (Phase 3, MCP layer moves in Phase 11)

  async writeAuditEvent(key: string, event: StoredAuditEvent): Promise<void> {
    await this.ctx.storage.put(key, event)
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
      return {
        success: true,
        entity: params.entity,
        verb: params.verb,
        result: { id: entityId, deleted: deleteResult.success ? deleteResult.data.deleted : false },
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
