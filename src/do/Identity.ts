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

// ============================================================================
// Types
// ============================================================================

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
  // D1 Database
  DB: D1Database

  // KV for sessions
  SESSIONS: KVNamespace

  // WorkOS (human auth)
  WORKOS_API_KEY: string
  WORKOS_CLIENT_ID: string

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
  }): Promise<Identity> {
    const id = crypto.randomUUID()
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

  async provisionAnonymous(): Promise<{
    identity: Identity
    sessionToken: string
    claimToken: string
  }> {
    const identity = await this.createIdentity({
      type: 'agent',
      name: `anon_${crypto.randomUUID().slice(0, 8)}`,
      level: 1,
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

  async createApiKey(data: {
    name: string
    identityId: string
    scopes?: string[]
  }): Promise<{ id: string; key: string }> {
    const id = crypto.randomUUID()
    const key = `oai_${crypto.randomUUID().replace(/-/g, '')}${crypto.randomUUID().replace(/-/g, '')}`

    await this.ctx.storage.put(`apikey:${id}`, {
      id,
      key,
      name: data.name,
      identityId: data.identityId,
      scopes: data.scopes,
      enabled: true,
      createdAt: Date.now(),
      requestCount: 0,
    })

    // Index by key for lookup
    await this.ctx.storage.put(`apikey-lookup:${key}`, id)

    return { id, key }
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
    if (!apiKey || !apiKey.enabled) return { valid: false }

    const identity = await this.getIdentity(apiKey.identityId)
    if (!identity) return { valid: false }

    // Update last used
    await this.ctx.storage.put(`apikey:${id}`, {
      ...apiKey,
      lastUsedAt: Date.now(),
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

  // ─── Internal Auth Check ────────────────────────────────────────────
  // Verifies that a request came through the worker's auth middleware by
  // checking the X-Worker-Auth header against the AUTH_SECRET binding.
  // This prevents direct-to-DO requests from bypassing authentication.

  private isInternalRequest(request: Request): boolean {
    const workerAuth = request.headers.get('X-Worker-Auth')
    if (!workerAuth) return false
    const expectedSecret = this.env.AUTH_SECRET
    if (!expectedSecret) return false
    // Constant-time-ish comparison
    if (workerAuth.length !== expectedSecret.length) return false
    let mismatch = 0
    for (let i = 0; i < workerAuth.length; i++) {
      mismatch |= workerAuth.charCodeAt(i) ^ expectedSecret.charCodeAt(i)
    }
    return mismatch === 0
  }

  private getCallerIdentityId(request: Request): string | null {
    return request.headers.get('X-Identity-Id') ?? null
  }

  private getCallerAuthLevel(request: Request): number {
    const level = request.headers.get('X-Auth-Level')
    return level ? parseInt(level, 10) : -1
  }

  // ─── HTTP Handler ─────────────────────────────────────────────────────

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url)
    const isInternal = this.isInternalRequest(request)

    if (url.pathname === '/health') {
      return Response.json({
        status: 'ok',
        ns: this.ns,
        tagline: 'Humans. Agents. Identity.',
      })
    }

    // ── OAuth Storage (internal only — used by OAuthProvider via worker) ──

    if (url.pathname === '/api/oauth-storage' && request.method === 'POST') {
      if (!isInternal) {
        return Response.json({ error: 'unauthorized' }, { status: 403 })
      }

      const body = await request.json() as {
        op: string
        key?: string
        value?: unknown
        options?: { expirationTtl?: number; prefix?: string; limit?: number }
      }

      if (body.op === 'get' && body.key) {
        const value = await this.ctx.storage.get(body.key)
        return Response.json({ value: value ?? undefined })
      }

      if (body.op === 'put' && body.key) {
        await this.ctx.storage.put(body.key, body.value)
        return Response.json({ ok: true })
      }

      if (body.op === 'delete' && body.key) {
        const deleted = await this.ctx.storage.delete(body.key)
        return Response.json({ deleted })
      }

      if (body.op === 'list') {
        const opts: { prefix?: string; limit?: number } = {}
        if (body.options?.prefix) opts.prefix = body.options.prefix
        if (body.options?.limit) opts.limit = body.options.limit
        const entries = await this.ctx.storage.list(opts)
        return Response.json({ entries: Array.from(entries.entries()) })
      }

      return Response.json({ error: 'unknown_op' }, { status: 400 })
    }

    // ── Provision — intentionally open (creates anonymous tenants) ─────

    if (url.pathname === '/api/provision' && request.method === 'POST') {
      const result = await this.provisionAnonymous()
      return Response.json(result)
    }

    // ── Claim — internal only (called from GitHub webhook handler) ─────

    if (url.pathname === '/api/claim' && request.method === 'POST') {
      if (!isInternal) {
        return Response.json({ error: 'unauthorized', message: 'Claim must be initiated via GitHub webhook' }, { status: 403 })
      }
      const body = await request.json() as any
      const result = await this.claim(body)
      return Response.json(result, { status: result.success ? 200 : 400 })
    }

    // ── Validate Key — internal only (called by MCPAuth) ──────────────

    if (url.pathname === '/api/validate-key' && request.method === 'POST') {
      if (!isInternal) {
        return Response.json({ error: 'unauthorized' }, { status: 403 })
      }
      const { key } = await request.json() as { key: string }
      const result = await this.validateApiKey(key)
      return Response.json(result)
    }

    // ── Identity Lookup — internal only ────────────────────────────────

    if (url.pathname.startsWith('/api/identity/') && request.method === 'GET') {
      if (!isInternal) {
        return Response.json({ error: 'unauthorized' }, { status: 403 })
      }
      const id = url.pathname.slice('/api/identity/'.length)
      const identity = await this.getIdentity(id)
      if (!identity) return Response.json({ error: 'not_found' }, { status: 404 })
      return Response.json(identity)
    }

    // ── Claim Token Verification — internal only ──────────────────────

    if (url.pathname === '/api/verify-claim' && request.method === 'POST') {
      if (!isInternal) {
        return Response.json({ error: 'unauthorized' }, { status: 403 })
      }
      const { token } = await request.json() as { token: string }
      if (!token) return Response.json({ error: 'missing_token' }, { status: 400 })
      const result = await this.verifyClaimToken(token)
      return Response.json(result, { status: result.valid ? 200 : 404 })
    }

    // ── Session Validation — internal only (called by MCPAuth) ────────

    if (url.pathname.startsWith('/api/session/') && request.method === 'GET') {
      if (!isInternal) {
        return Response.json({ error: 'unauthorized' }, { status: 403 })
      }
      const token = url.pathname.slice('/api/session/'.length)
      if (!token) return Response.json({ error: 'missing_token' }, { status: 400 })
      const result = await this.getSession(token)
      return Response.json(result, { status: result.valid ? 200 : 401 })
    }

    // ── Freeze Identity — requires auth + own identity ────────────────

    if (url.pathname.startsWith('/api/freeze/') && request.method === 'POST') {
      if (!isInternal) {
        return Response.json({ error: 'unauthorized' }, { status: 403 })
      }
      const id = url.pathname.slice('/api/freeze/'.length)
      if (!id) return Response.json({ error: 'missing_id' }, { status: 400 })

      // Verify caller is freezing their own identity
      const callerId = this.getCallerIdentityId(request)
      if (callerId && callerId !== id) {
        return Response.json({ error: 'forbidden', message: 'Can only freeze your own identity' }, { status: 403 })
      }

      try {
        const result = await this.freezeIdentity(id)
        return Response.json(result)
      } catch (err: any) {
        return Response.json({ error: err.message }, { status: 404 })
      }
    }

    // ── Rate Limit Check — internal only (called by MCPAuth) ──────────

    if (url.pathname.startsWith('/api/rate-limit/') && request.method === 'GET') {
      if (!isInternal) {
        return Response.json({ error: 'unauthorized' }, { status: 403 })
      }
      const id = url.pathname.slice('/api/rate-limit/'.length)
      if (!id) return Response.json({ error: 'missing_id' }, { status: 400 })

      const identity = await this.getIdentity(id)
      if (!identity) return Response.json({ error: 'not_found' }, { status: 404 })

      const result = await this.checkRateLimit(id, identity.level)
      return Response.json({ ...result, level: identity.level })
    }

    // ── List Sessions — requires auth + own identity ──────────────────

    if (url.pathname.startsWith('/api/sessions/') && request.method === 'GET') {
      if (!isInternal) {
        return Response.json({ error: 'unauthorized' }, { status: 403 })
      }
      const identityId = url.pathname.slice('/api/sessions/'.length)
      if (!identityId) return Response.json({ error: 'missing_id' }, { status: 400 })

      // Only allow listing own sessions
      const callerId = this.getCallerIdentityId(request)
      if (callerId && callerId !== identityId) {
        return Response.json({ error: 'forbidden', message: 'Can only list your own sessions' }, { status: 403 })
      }

      const sessions = await this.listSessions(identityId)
      return Response.json({ sessions })
    }

    // ── Agent Key Management ──────────────────────────────────────────

    // POST /api/agent-keys — Register a new agent key (requires auth)
    if (url.pathname === '/api/agent-keys' && request.method === 'POST') {
      if (!isInternal) {
        return Response.json({ error: 'unauthorized' }, { status: 403 })
      }
      const authLevel = this.getCallerAuthLevel(request)
      if (authLevel < 1) {
        return Response.json({ error: 'authentication_required', message: 'L1+ authentication required to register agent keys' }, { status: 401 })
      }
      try {
        const body = await request.json() as {
          identityId: string
          publicKey: string
          label?: string
        }

        if (!body.identityId || !body.publicKey) {
          return Response.json({ error: 'identityId and publicKey are required' }, { status: 400 })
        }

        // Verify caller owns the identity they're registering a key for
        const callerId = this.getCallerIdentityId(request)
        if (callerId && callerId !== body.identityId) {
          return Response.json({ error: 'forbidden', message: 'Can only register keys for your own identity' }, { status: 403 })
        }

        const result = await this.registerAgentKey(body)
        return Response.json(result, { status: 201 })
      } catch (err: any) {
        return Response.json({ error: err.message }, { status: 400 })
      }
    }

    // GET /api/agent-keys/:identityId — List agent keys for an identity
    if (url.pathname.startsWith('/api/agent-keys/') && request.method === 'GET') {
      if (!isInternal) {
        return Response.json({ error: 'unauthorized' }, { status: 403 })
      }
      const identityId = url.pathname.slice('/api/agent-keys/'.length)
      if (!identityId) return Response.json({ error: 'missing_identity_id' }, { status: 400 })

      // Only allow listing own agent keys
      const callerId = this.getCallerIdentityId(request)
      if (callerId && callerId !== identityId) {
        return Response.json({ error: 'forbidden', message: 'Can only list your own agent keys' }, { status: 403 })
      }

      const keys = await this.listAgentKeys(identityId)
      return Response.json({ keys })
    }

    // DELETE /api/agent-keys/:keyId — Revoke an agent key (requires auth)
    if (url.pathname.startsWith('/api/agent-keys/') && request.method === 'DELETE') {
      if (!isInternal) {
        return Response.json({ error: 'unauthorized' }, { status: 403 })
      }
      const authLevel = this.getCallerAuthLevel(request)
      if (authLevel < 1) {
        return Response.json({ error: 'authentication_required', message: 'L1+ authentication required to revoke agent keys' }, { status: 401 })
      }
      const keyId = url.pathname.slice('/api/agent-keys/'.length)
      if (!keyId) return Response.json({ error: 'missing_key_id' }, { status: 400 })

      const revoked = await this.revokeAgentKey(keyId)
      if (!revoked) {
        return Response.json({ error: 'Key not found or already revoked' }, { status: 404 })
      }

      return Response.json({ revoked: true, keyId })
    }

    // POST /api/verify-signature — Verify a signed request from an agent (internal)
    if (url.pathname === '/api/verify-signature' && request.method === 'POST') {
      if (!isInternal) {
        return Response.json({ error: 'unauthorized' }, { status: 403 })
      }
      try {
        const body = await request.json() as {
          did: string
          message: string
          signature: string
        }

        if (!body.did || !body.message || !body.signature) {
          return Response.json({ error: 'did, message, and signature are required' }, { status: 400 })
        }

        const result = await this.verifyAgentSignature(body)
        return Response.json(result, { status: result.valid ? 200 : 401 })
      } catch (err: any) {
        return Response.json({ error: err.message }, { status: 400 })
      }
    }

    // ── MCP Do Handler ──────────────────────────────────────────────────
    // Handles entity operations from the MCP do tool (requires auth L1+)

    if (url.pathname === '/api/mcp-do' && request.method === 'POST') {
      if (!isInternal) {
        return Response.json({ error: 'unauthorized' }, { status: 403 })
      }
      const authLevel = this.getCallerAuthLevel(request)
      if (authLevel < 1) {
        return Response.json({ error: 'authentication_required', message: 'L1+ authentication required for entity operations' }, { status: 401 })
      }
      try {
        const body = await request.json() as {
          entity: string
          verb: string
          data: Record<string, unknown>
          identityId?: string
          timestamp: number
        }

        const entityId = body.data.id as string ?? crypto.randomUUID()
        const storageKey = `entity:${body.identityId ?? 'global'}:${body.entity}:${entityId}`

        if (body.verb === 'create') {
          const record = {
            ...body.data,
            id: entityId,
            createdAt: body.timestamp,
            updatedAt: body.timestamp,
          }
          await this.ctx.storage.put(storageKey, record)

          // Store event
          const eventKey = `event:${body.identityId ?? 'global'}:${crypto.randomUUID()}`
          await this.ctx.storage.put(eventKey, {
            type: `${body.entity}.${body.verb}ed`,
            entityType: body.entity,
            entityId,
            verb: body.verb,
            data: record,
            timestamp: body.timestamp,
          })

          return Response.json({
            success: true,
            entity: body.entity,
            verb: body.verb,
            result: record,
            events: [
              { type: `${body.verb}ing`, entity: body.entity, verb: body.verb, timestamp: new Date(body.timestamp).toISOString() },
              { type: `${body.verb}ed`, entity: body.entity, verb: body.verb, timestamp: new Date(body.timestamp).toISOString() },
            ],
          })
        }

        if (body.verb === 'update') {
          const existing = await this.ctx.storage.get<Record<string, unknown>>(storageKey)
          if (!existing) {
            return Response.json({ error: 'Entity not found' }, { status: 404 })
          }

          const record = { ...existing, ...body.data, updatedAt: body.timestamp }
          await this.ctx.storage.put(storageKey, record)

          return Response.json({
            success: true,
            entity: body.entity,
            verb: body.verb,
            result: record,
            events: [
              { type: 'updating', entity: body.entity, verb: body.verb, timestamp: new Date(body.timestamp).toISOString() },
              { type: 'updated', entity: body.entity, verb: body.verb, timestamp: new Date(body.timestamp).toISOString() },
            ],
          })
        }

        if (body.verb === 'delete') {
          await this.ctx.storage.delete(storageKey)
          return Response.json({
            success: true,
            entity: body.entity,
            verb: body.verb,
            result: { id: entityId, deleted: true },
            events: [
              { type: 'deleting', entity: body.entity, verb: body.verb, timestamp: new Date(body.timestamp).toISOString() },
              { type: 'deleted', entity: body.entity, verb: body.verb, timestamp: new Date(body.timestamp).toISOString() },
            ],
          })
        }

        // For custom verbs (qualify, close, advance, etc.), treat as update with verb-specific event
        const existing = await this.ctx.storage.get<Record<string, unknown>>(storageKey)
        const record = { ...(existing ?? {}), ...body.data, id: entityId, updatedAt: body.timestamp }
        await this.ctx.storage.put(storageKey, record)

        // Store event for the custom verb
        const eventKey = `event:${body.identityId ?? 'global'}:${crypto.randomUUID()}`
        await this.ctx.storage.put(eventKey, {
          type: `${body.entity}.${body.verb}ed`,
          entityType: body.entity,
          entityId,
          verb: body.verb,
          data: record,
          timestamp: body.timestamp,
        })

        return Response.json({
          success: true,
          entity: body.entity,
          verb: body.verb,
          result: record,
          events: [
            { type: `${body.verb}ing`, entity: body.entity, verb: body.verb, timestamp: new Date(body.timestamp).toISOString() },
            { type: `${body.verb}ed`, entity: body.entity, verb: body.verb, timestamp: new Date(body.timestamp).toISOString() },
          ],
        })
      } catch (err: any) {
        return Response.json({ error: err.message }, { status: 500 })
      }
    }

    return Response.json({ error: 'not_found', ns: this.ns }, { status: 404 })
  }
}
