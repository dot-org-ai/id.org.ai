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
import { AuditLog } from '../audit'
import type { AuditQueryOptions, StoredAuditEvent } from '../audit'

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

  // OAuth Storage
  oauthStorageOp(op: { op: 'get' | 'put' | 'delete' | 'list'; key?: string; value?: unknown; options?: { expirationTtl?: number; prefix?: string; limit?: number } }): Promise<Record<string, unknown>>

  // Audit
  writeAuditEvent(key: string, event: StoredAuditEvent): Promise<void>
  queryAuditLog(options: AuditQueryOptions): Promise<{ events: StoredAuditEvent[]; cursor?: string; hasMore: boolean }>
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
    const id = data.id ?? crypto.randomUUID()
    const claimToken = `clm_${crypto.randomUUID().replace(/-/g, '')}`
    const level = data.level ?? 0

    await this.ctx.storage.put(`identity:${id}`, {
      id,
      type: data.type,
      name: data.name,
      email: data.email,
      handle: data.handle,
      capabilities: data.capabilities,
      ownerId: data.ownerId,
      verified: false,
      level,
      claimStatus: 'unclaimed' as ClaimStatus,
      claimToken,
      createdAt: Date.now(),
    })

    return {
      id,
      type: data.type,
      name: data.name,
      handle: data.handle,
      email: data.email,
      verified: false,
      level,
      claimStatus: 'unclaimed',
    }
  }

  async getIdentity(id: string): Promise<Identity | null> {
    const data = await this.ctx.storage.get<any>(`identity:${id}`)
    if (!data) return null
    return {
      id: data.id,
      type: data.type,
      name: data.name,
      handle: data.handle,
      email: data.email,
      image: data.image,
      verified: data.verified ?? false,
      level: data.level ?? 0,
      claimStatus: data.claimStatus ?? 'unclaimed',
      frozen: data.frozen ?? false,
      frozenAt: data.frozenAt,
    }
  }

  // ─── Anonymous Provisioning ───────────────────────────────────────────

  async provisionAnonymous(presetIdentityId?: string): Promise<{
    identity: Identity
    sessionToken: string
    claimToken: string
  }> {
    const identity = await this.createIdentity({
      type: 'agent',
      name: `anon_${crypto.randomUUID().slice(0, 8)}`,
      level: 1,
      id: presetIdentityId,
    })

    const sessionToken = `ses_${crypto.randomUUID().replace(/-/g, '')}`
    const data = await this.ctx.storage.get<any>(`identity:${identity.id}`)

    await this.ctx.storage.put(`session:${sessionToken}`, {
      identityId: identity.id,
      level: 1,
      createdAt: Date.now(),
      expiresAt: Date.now() + 24 * 60 * 60 * 1000, // 24h TTL
    })

    return {
      identity,
      sessionToken,
      claimToken: data.claimToken,
    }
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
    const data = await this.ctx.storage.get<any>(`identity:${id}`)
    if (!data) {
      throw new Error('Identity not found')
    }

    // Count related data
    const entityEntries = await this.ctx.storage.list({ prefix: `entity:${id}:` })
    const eventEntries = await this.ctx.storage.list({ prefix: `event:${id}:` })
    const sessions = await this.listSessions(id)

    // Expire all sessions for this identity
    for (const session of sessions) {
      await this.ctx.storage.delete(`session:${session.token}`)
    }

    // Mark as frozen with 30-day data preservation window
    const frozenAt = Date.now()
    const expiresAt = frozenAt + 30 * 24 * 60 * 60 * 1000 // 30 days

    await this.ctx.storage.put(`identity:${id}`, {
      ...data,
      frozen: true,
      frozenAt,
      dataExpiresAt: expiresAt,
      claimStatus: 'frozen' as ClaimStatus,
    })

    return {
      frozen: true,
      stats: {
        entities: entityEntries.size,
        events: eventEntries.size,
        sessions: sessions.length,
      },
      expiresAt,
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

  async writeAuditEvent(key: string, event: StoredAuditEvent): Promise<void> {
    await this.ctx.storage.put(key, event)
  }

  async queryAuditLog(options: AuditQueryOptions): Promise<{ events: StoredAuditEvent[]; cursor?: string; hasMore: boolean }> {
    const auditLog = new AuditLog(this.ctx.storage)
    return auditLog.query(options)
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
    const storageKey = `entity:${owner}:${params.entity}:${entityId}`

    if (params.verb === 'create') {
      const record = {
        ...params.data,
        id: entityId,
        $type: params.entity,
        createdAt: params.timestamp,
        updatedAt: params.timestamp,
      }
      await this.putEntityWithIndexes(owner, params.entity, entityId, record)

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
      const existing = await this.ctx.storage.get<Record<string, unknown>>(storageKey)
      if (!existing) {
        return { success: false, entity: params.entity, verb: params.verb, error: `${params.entity} not found: ${entityId}` }
      }

      await this.deleteIndexesForEntity(owner, params.entity, entityId, existing)
      const record = { ...existing, ...params.data, $type: params.entity, updatedAt: params.timestamp }
      await this.putEntityWithIndexes(owner, params.entity, entityId, record)

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
      const existing = await this.ctx.storage.get<Record<string, unknown>>(storageKey)
      await this.deleteEntityWithIndexes(owner, params.entity, entityId, existing)
      return {
        success: true,
        entity: params.entity,
        verb: params.verb,
        result: { id: entityId, deleted: true },
        events: [
          { type: 'deleting', entity: params.entity, verb: params.verb, timestamp: new Date(params.timestamp).toISOString() },
          { type: 'deleted', entity: params.entity, verb: params.verb, timestamp: new Date(params.timestamp).toISOString() },
        ],
      }
    }

    // Custom verbs (qualify, close, advance, etc.)
    const existing = await this.ctx.storage.get<Record<string, unknown>>(storageKey)
    if (existing) {
      await this.deleteIndexesForEntity(owner, params.entity, entityId, existing)
    }

    const record = { ...(existing ?? {}), ...params.data, id: entityId, $type: params.entity, updatedAt: params.timestamp }
    await this.putEntityWithIndexes(owner, params.entity, entityId, record)

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
    const queryLower = params.query?.toLowerCase().trim() ?? ''

    let results: Array<{ type: string; id: string; data: Record<string, unknown>; score: number }> = []

    if (params.type) {
      const prefix = `entity:${owner}:${params.type}:`
      const entries = await this.ctx.storage.list<Record<string, unknown>>({ prefix })

      for (const [, value] of entries) {
        if (!value || typeof value !== 'object') continue
        const entityData = value as Record<string, unknown>
        if (params.filters && !this.matchesFilters(entityData, params.filters)) continue
        let score = 1
        if (queryLower) {
          score = this.calculateTextScore(entityData, queryLower)
          if (score === 0) continue
        }
        results.push({ type: params.type, id: String(entityData.id ?? ''), data: entityData, score })
      }
    } else if (params.filters && Object.keys(params.filters).length > 0) {
      const prefix = `entity:${owner}:`
      const entries = await this.ctx.storage.list<Record<string, unknown>>({ prefix })

      for (const [key, value] of entries) {
        if (!value || typeof value !== 'object') continue
        const entityData = value as Record<string, unknown>
        const parts = key.split(':')
        const entityType = parts[2]
        if (!this.matchesFilters(entityData, params.filters)) continue
        let score = 1
        if (queryLower) {
          score = this.calculateTextScore(entityData, queryLower)
          if (score === 0) continue
        }
        results.push({ type: entityType, id: String(entityData.id ?? ''), data: entityData, score })
      }
    } else if (queryLower) {
      const prefix = `entity:${owner}:`
      const entries = await this.ctx.storage.list<Record<string, unknown>>({ prefix })

      for (const [key, value] of entries) {
        if (!value || typeof value !== 'object') continue
        const entityData = value as Record<string, unknown>
        const parts = key.split(':')
        const entityType = parts[2]
        const score = this.calculateTextScore(entityData, queryLower)
        if (score === 0) continue
        results.push({ type: entityType, id: String(entityData.id ?? ''), data: entityData, score })
      }
    }

    results.sort((a, b) => b.score - a.score)
    const total = results.length
    results = results.slice(offset, offset + limit)

    return { results, total, limit, offset }
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
      const storageKey = `entity:${owner}:${params.type}:${params.id}`
      const data = await this.ctx.storage.get<Record<string, unknown>>(storageKey)
      return { type: params.type, id: params.id, data: data ?? null }
    }

    const prefix = `entity:${owner}:${params.type}:`
    const entries = await this.ctx.storage.list<Record<string, unknown>>({ prefix })
    const limit = Math.min(params.limit ?? 20, 100)
    const offset = params.offset ?? 0

    let items: Record<string, unknown>[] = []
    for (const [, value] of entries) {
      if (!value || typeof value !== 'object') continue
      const entityData = value as Record<string, unknown>
      if (params.filters && !this.matchesFilters(entityData, params.filters)) continue
      items.push(entityData)
    }

    const total = items.length
    items = items.slice(offset, offset + limit)

    return { type: params.type, items, total, limit, offset }
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

  // ─── Entity Index Management ─────────────────────────────────────────
  // Maintains secondary indexes for queryable entity storage.
  //
  // Storage layout:
  //   entity:{owner}:{type}:{id}  → full JSON record
  //   idx:{owner}:{type}:{field}:{value}:{id} → true
  //
  // Indexed fields: any string or enum field that is not 'id', 'metadata',
  // or a JSON blob. This allows field-based lookups like
  //   "all Contacts where stage = 'Lead'"

  /** Fields that should not be indexed (JSON blobs, binary, internal) */
  private static readonly NON_INDEXED_FIELDS = new Set([
    'id', 'metadata', 'properties', 'config', 'targeting', 'variants',
    'steps', 'trigger', 'filters', 'fields', '$type',
  ])

  /** Returns the index keys for a given entity record */
  private indexKeysForEntity(
    owner: string,
    entityType: string,
    entityId: string,
    record: Record<string, unknown>,
  ): Map<string, true> {
    const keys = new Map<string, true>()
    for (const [field, value] of Object.entries(record)) {
      if (IdentityDO.NON_INDEXED_FIELDS.has(field)) continue
      if (value === null || value === undefined) continue
      if (typeof value === 'object') continue // skip arrays and nested objects
      // Normalize index value: lowercase string, truncate to 128 chars
      const normalized = String(value).toLowerCase().slice(0, 128)
      keys.set(`idx:${owner}:${entityType}:${field}:${normalized}:${entityId}`, true)
    }
    return keys
  }

  /** Store an entity and its secondary indexes */
  private async putEntityWithIndexes(
    owner: string,
    entityType: string,
    entityId: string,
    record: Record<string, unknown>,
  ): Promise<void> {
    const storageKey = `entity:${owner}:${entityType}:${entityId}`
    const indexes = this.indexKeysForEntity(owner, entityType, entityId, record)

    // Batch put: entity + all index entries
    const batch = new Map<string, unknown>()
    batch.set(storageKey, record)
    for (const [key, val] of indexes) {
      batch.set(key, val)
    }
    await this.ctx.storage.put(Object.fromEntries(batch))
  }

  /** Delete index entries for an entity record */
  private async deleteIndexesForEntity(
    owner: string,
    entityType: string,
    entityId: string,
    record: Record<string, unknown>,
  ): Promise<void> {
    const indexes = this.indexKeysForEntity(owner, entityType, entityId, record)
    if (indexes.size > 0) {
      await this.ctx.storage.delete([...indexes.keys()])
    }
  }

  /** Delete an entity and its secondary indexes */
  private async deleteEntityWithIndexes(
    owner: string,
    entityType: string,
    entityId: string,
    record: Record<string, unknown> | null | undefined,
  ): Promise<void> {
    const storageKey = `entity:${owner}:${entityType}:${entityId}`
    if (record) {
      const indexes = this.indexKeysForEntity(owner, entityType, entityId, record)
      const keysToDelete = [storageKey, ...indexes.keys()]
      await this.ctx.storage.delete(keysToDelete)
    } else {
      await this.ctx.storage.delete(storageKey)
    }
  }

  /** Check if an entity record matches a set of field filters */
  private matchesFilters(
    record: Record<string, unknown>,
    filters: Record<string, unknown>,
  ): boolean {
    for (const [field, expected] of Object.entries(filters)) {
      const actual = record[field]
      if (actual === undefined || actual === null) return false
      // Case-insensitive string comparison
      if (typeof actual === 'string' && typeof expected === 'string') {
        if (actual.toLowerCase() !== expected.toLowerCase()) return false
      } else if (actual !== expected) {
        return false
      }
    }
    return true
  }

  /** Calculate a text relevance score for an entity against a query */
  private calculateTextScore(
    record: Record<string, unknown>,
    queryLower: string,
  ): number {
    let score = 0
    for (const [field, value] of Object.entries(record)) {
      if (value === null || value === undefined || typeof value === 'object') continue
      const strValue = String(value).toLowerCase()
      if (!strValue.includes(queryLower)) continue

      // Weight certain fields higher
      if (field === 'name' || field === 'title' || field === 'subject') {
        score += strValue === queryLower ? 20 : 10
      } else if (field === 'email' || field === 'slug' || field === 'key') {
        score += strValue === queryLower ? 15 : 8
      } else if (field === 'description' || field === 'body') {
        score += 3
      } else if (field === '$type') {
        score += 5
      } else {
        score += 2
      }
    }
    return score
  }
}
