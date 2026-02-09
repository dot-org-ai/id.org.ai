/**
 * MCP Authentication for id.org.ai
 *
 * Provides three-tier authentication for MCP connections:
 *   - Level 0: No auth (anonymous, read-only, 30 req/min)
 *   - Level 1: Session token (sandboxed, read+write, 100 req/min)
 *   - Level 2+: API key or Bearer token (claimed/production, 1000+ req/min)
 *
 * Every _meta response includes the current level and upgrade instructions.
 * This is the key innovation: no auth required to start using the product.
 *
 * Design principles:
 *   - No sandbox distinction: anonymous tenants ARE production tenants
 *   - Progressive capability: every response includes upgrade path
 *   - Freeze, don't delete: expired tenants freeze with 30-day data preservation
 */

import type { CapabilityLevel, IdentityStub } from '../do/Identity'

// ============================================================================
// Types
// ============================================================================

export interface MCPAuthResult {
  authenticated: boolean
  identityId?: string
  level: 0 | 1 | 2 | 3
  scopes: string[]
  capabilities: string[]
  rateLimit?: {
    allowed: boolean
    remaining: number
    resetAt: number
    limit: number
  }
  error?: string
  upgrade?: {
    nextLevel: number
    action: string
    description: string
    url: string
  }
}

// Scopes available at each level
const LEVEL_SCOPES: Record<CapabilityLevel, string[]> = {
  0: ['read', 'search', 'fetch', 'explore'],
  1: ['read', 'write', 'search', 'fetch', 'explore', 'do', 'try', 'claim'],
  2: ['read', 'write', 'search', 'fetch', 'explore', 'do', 'try', 'export', 'webhook', 'invite'],
  3: ['read', 'write', 'search', 'fetch', 'explore', 'do', 'try', 'export', 'webhook', 'invite', 'admin', 'billing'],
}

// Capabilities (MCP tools) at each level
const LEVEL_CAPABILITIES: Record<CapabilityLevel, string[]> = {
  0: ['explore', 'search', 'fetch'],
  1: ['explore', 'search', 'fetch', 'try', 'do'],
  2: ['explore', 'search', 'fetch', 'try', 'do'],
  3: ['explore', 'search', 'fetch', 'try', 'do'],
}

// Rate limits per minute by level
const RATE_LIMITS: Record<CapabilityLevel, number> = {
  0: 30,
  1: 100,
  2: 1000,
  3: Infinity,
}

// ============================================================================
// MCPAuth
// ============================================================================

export class MCPAuth {
  private identityStub: IdentityStub

  constructor(identityStub: IdentityStub) {
    this.identityStub = identityStub
  }

  /**
   * Return the L0 anonymous auth result.
   * Used when no identity stub is available (no credentials provided).
   */
  static anonymousResult(): MCPAuthResult {
    return {
      authenticated: false,
      level: 0,
      scopes: LEVEL_SCOPES[0],
      capabilities: LEVEL_CAPABILITIES[0],
      rateLimit: {
        allowed: true,
        remaining: RATE_LIMITS[0],
        resetAt: Date.now() + 60_000,
        limit: RATE_LIMITS[0],
      },
      upgrade: {
        nextLevel: 1,
        action: 'provision',
        description: 'POST to provision endpoint to get a session token with write access',
        url: 'https://id.org.ai/api/provision',
      },
    }
  }

  /**
   * Authenticate an MCP request.
   *
   * Three-tier strategy:
   *   1. Check for API key (X-API-Key header or Bearer oai_*) -> L2+
   *   2. Check for session token (Bearer ses_*) -> L1
   *   3. No auth -> L0 anonymous with auto-provision hint
   *
   * Every result includes scopes, capabilities, rate limit info,
   * and an upgrade path to the next level.
   */
  async authenticate(request: Request): Promise<MCPAuthResult> {
    // ── L2+: API key authentication ────────────────────────────────────
    const apiKey = this.extractApiKey(request)
    if (apiKey) {
      return this.authenticateApiKey(apiKey)
    }

    // ── L1: Session token authentication ───────────────────────────────
    const sessionToken = this.extractSessionToken(request)
    if (sessionToken) {
      return this.authenticateSession(sessionToken)
    }

    // ── L0: No auth — anonymous access ─────────────────────────────────
    return MCPAuth.anonymousResult()
  }

  /**
   * Validate an API key (oai_* prefix) against the IdentityDO.
   * Returns L2 or L3 auth result based on the identity level.
   */
  private async authenticateApiKey(key: string): Promise<MCPAuthResult> {
    const data = await this.identityStub.validateApiKey(key)

    if (!data.valid || !data.identityId) {
      return {
        authenticated: false,
        level: 0,
        scopes: LEVEL_SCOPES[0],
        capabilities: LEVEL_CAPABILITIES[0],
        error: 'Invalid API key',
        upgrade: {
          nextLevel: 1,
          action: 'provision',
          description: 'POST to provision endpoint to get a fresh session',
          url: 'https://id.org.ai/api/provision',
        },
      }
    }

    const level = data.level ?? 2
    const effectiveLevel = Math.max(2, level) as CapabilityLevel

    // Check rate limit
    const rateLimit = await this.checkRateLimit(data.identityId, effectiveLevel)

    if (!rateLimit.allowed) {
      return {
        authenticated: true,
        identityId: data.identityId,
        level: effectiveLevel,
        scopes: data.scopes ?? LEVEL_SCOPES[effectiveLevel],
        capabilities: LEVEL_CAPABILITIES[effectiveLevel],
        rateLimit,
        error: 'Rate limit exceeded',
      }
    }

    const result: MCPAuthResult = {
      authenticated: true,
      identityId: data.identityId,
      level: effectiveLevel,
      scopes: data.scopes ?? LEVEL_SCOPES[effectiveLevel],
      capabilities: LEVEL_CAPABILITIES[effectiveLevel],
      rateLimit,
    }

    // Even L2 users get an upgrade hint to L3
    if (effectiveLevel < 3) {
      result.upgrade = {
        nextLevel: 3,
        action: 'subscribe',
        description: 'Subscribe to a plan for unlimited access and production integrations',
        url: 'https://headless.ly/pricing',
      }
    }

    return result
  }

  /**
   * Validate a session token (ses_* prefix) against the IdentityDO.
   * Returns L1 auth result with write scopes and claim upgrade hint.
   */
  private async authenticateSession(token: string): Promise<MCPAuthResult> {
    const data = await this.identityStub.getSession(token)

    if (!data.valid || !data.identityId) {
      return {
        authenticated: false,
        level: 0,
        scopes: LEVEL_SCOPES[0],
        capabilities: LEVEL_CAPABILITIES[0],
        error: 'Invalid or expired session token',
        upgrade: {
          nextLevel: 1,
          action: 'provision',
          description: 'POST to provision endpoint to get a new session',
          url: 'https://id.org.ai/api/provision',
        },
      }
    }

    const level = (data.level ?? 1) as CapabilityLevel

    // Check rate limit
    const rateLimit = await this.checkRateLimit(data.identityId, level)

    if (!rateLimit.allowed) {
      return {
        authenticated: true,
        identityId: data.identityId,
        level,
        scopes: LEVEL_SCOPES[level],
        capabilities: LEVEL_CAPABILITIES[level],
        rateLimit,
        error: 'Rate limit exceeded',
      }
    }

    return {
      authenticated: true,
      identityId: data.identityId,
      level,
      scopes: LEVEL_SCOPES[level],
      capabilities: LEVEL_CAPABILITIES[level],
      rateLimit,
      upgrade: {
        nextLevel: 2,
        action: 'claim',
        description: 'Commit a GitHub Action workflow to claim this tenant and unlock persistence',
        url: 'https://id.org.ai/claim',
      },
    }
  }

  /**
   * Check rate limit for an identity at a given capability level.
   * Delegates to the IdentityDO which tracks request counts per window.
   */
  async checkRateLimit(identityId: string, level: CapabilityLevel): Promise<{
    allowed: boolean
    remaining: number
    resetAt: number
    limit: number
  }> {
    const limit = RATE_LIMITS[level]
    if (limit === Infinity) {
      return { allowed: true, remaining: Infinity, resetAt: 0, limit: Infinity }
    }

    try {
      const data = await this.identityStub.checkRateLimit(identityId, level)
      return {
        allowed: data.allowed,
        remaining: data.remaining,
        resetAt: data.resetAt,
        limit,
      }
    } catch {
      // If rate limit check fails, allow the request but with conservative limits
      return { allowed: true, remaining: 1, resetAt: Date.now() + 60_000, limit }
    }
  }

  /**
   * Build the _meta object for MCP protocol responses.
   *
   * Includes authentication level, capabilities, rate limit info,
   * and upgrade instructions. This is attached to every MCP response
   * so agents always know their current level and how to upgrade.
   */
  static buildMetaStatic(auth: MCPAuthResult): Record<string, unknown> {
    const meta: Record<string, unknown> = {
      auth: {
        level: auth.level,
        authenticated: auth.authenticated,
        scopes: auth.scopes,
        capabilities: auth.capabilities,
      },
    }

    if (auth.identityId) {
      (meta.auth as Record<string, unknown>).identityId = auth.identityId
    }

    if (auth.rateLimit) {
      meta.rateLimit = {
        limit: auth.rateLimit.limit,
        remaining: auth.rateLimit.remaining,
        resetAt: new Date(auth.rateLimit.resetAt).toISOString(),
      }
    }

    if (auth.upgrade) {
      meta.upgrade = auth.upgrade
    }

    if (auth.error) {
      meta.error = auth.error
    }

    return meta
  }

  /**
   * Instance method that delegates to the static version.
   * Kept for backward compatibility.
   */
  buildMeta(auth: MCPAuthResult): Record<string, unknown> {
    return MCPAuth.buildMetaStatic(auth)
  }

  // ─── Token Extraction ─────────────────────────────────────────────────

  private extractApiKey(request: Request): string | null {
    // X-API-Key header (preferred)
    const header = request.headers.get('x-api-key')
    if (header?.startsWith('oai_')) return header

    // Authorization: Bearer oai_*
    const auth = request.headers.get('authorization')
    if (auth?.startsWith('Bearer oai_')) return auth.slice(7)

    // Query parameter fallback (for MCP tool calls)
    try {
      const url = new URL(request.url)
      const keyParam = url.searchParams.get('api_key')
      if (keyParam?.startsWith('oai_')) return keyParam
    } catch {
      // Invalid URL, skip query param extraction
    }

    return null
  }

  private extractSessionToken(request: Request): string | null {
    const auth = request.headers.get('authorization')
    if (auth?.startsWith('Bearer ses_')) return auth.slice(7)
    return null
  }
}
