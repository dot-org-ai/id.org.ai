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
 */

import { DurableObject } from 'cloudflare:workers'

// ============================================================================
// Types
// ============================================================================

export type IdentityType = 'human' | 'agent' | 'service'

export type ClaimStatus = 'unclaimed' | 'pending' | 'claimed'

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
}

export interface LinkedAccount {
  id: string
  provider: string
  type: 'auth' | 'payment' | 'ai' | 'platform' | 'service'
  displayName?: string
  status: 'active' | 'pending' | 'expired' | 'revoked'
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

  // ─── HTTP Handler ─────────────────────────────────────────────────────

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url)

    if (url.pathname === '/health') {
      return Response.json({
        status: 'ok',
        ns: this.ns,
        tagline: 'Humans. Agents. Identity.',
      })
    }

    if (url.pathname === '/api/provision' && request.method === 'POST') {
      const result = await this.provisionAnonymous()
      return Response.json(result)
    }

    if (url.pathname === '/api/claim' && request.method === 'POST') {
      const body = await request.json() as any
      const result = await this.claim(body)
      return Response.json(result, { status: result.success ? 200 : 400 })
    }

    if (url.pathname === '/api/validate-key' && request.method === 'POST') {
      const { key } = await request.json() as { key: string }
      const result = await this.validateApiKey(key)
      return Response.json(result)
    }

    if (url.pathname.startsWith('/api/identity/') && request.method === 'GET') {
      const id = url.pathname.slice('/api/identity/'.length)
      const identity = await this.getIdentity(id)
      if (!identity) return Response.json({ error: 'not_found' }, { status: 404 })
      return Response.json(identity)
    }

    return Response.json({ error: 'not_found', ns: this.ns }, { status: 404 })
  }
}
