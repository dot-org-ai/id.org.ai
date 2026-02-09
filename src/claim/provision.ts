/**
 * Anonymous Tenant Provisioning
 *
 * Creates a real (not mock) sandbox tenant when an agent connects
 * to the MCP endpoint without authentication.
 *
 * Key principle: no sandbox distinction. Anonymous tenants ARE production
 * tenants — same Durable Object, same schema, same event log. The only
 * differences are entity limits and integration access.
 *
 * Freeze, don't delete: expired tenants freeze with 30-day data preservation.
 * The freeze response shows what the agent built — driving the claim conversion.
 */

export interface ProvisionResult {
  tenantId: string
  identityId: string
  sessionToken: string
  claimToken: string
  level: 1
  limits: {
    maxEntities: number
    ttlHours: number
    maxRequestsPerMinute: number
  }
  upgrade: {
    nextLevel: 2
    action: 'claim'
    description: 'Commit a GitHub Action workflow to claim this tenant'
    url: string
  }
}

export interface FreezeResult {
  frozen: boolean
  identityId: string
  stats: {
    entities: number
    events: number
    sessions: number
  }
  claimUrl: string
  expiresAt: string
  message: string
}

export interface TenantStatus {
  identityId: string
  level: number
  claimStatus: string
  frozen: boolean
  stats?: {
    entities: number
    events: number
    createdAt: string
    expiresAt?: string
  }
  upgrade?: {
    nextLevel: number
    action: string
    url: string
  }
}

export class ClaimService {
  private identityStub: { fetch(input: string | Request): Promise<Response> }
  private authSecret: string

  constructor(identityStub: { fetch(input: string | Request): Promise<Response> }, authSecret?: string) {
    this.identityStub = identityStub
    this.authSecret = authSecret ?? ''
  }

  private internalHeaders(): Record<string, string> {
    return this.authSecret ? { 'X-Worker-Auth': this.authSecret } : {}
  }

  /**
   * Provision an anonymous sandbox tenant.
   *
   * Calls IdentityDO.provisionAnonymous() via its HTTP interface.
   * Returns a session token (for ongoing requests) and a claim token
   * (for later claiming via GitHub commit).
   */
  async provision(): Promise<ProvisionResult> {
    const res = await this.identityStub.fetch(
      new Request('https://id.org.ai/api/provision', { method: 'POST', headers: { ...this.internalHeaders() } })
    )

    if (!res.ok) {
      const body = await res.text()
      throw new Error(`Provision failed (${res.status}): ${body}`)
    }

    const data = await res.json() as {
      identity: { id: string; name: string; level: number }
      sessionToken: string
      claimToken: string
    }

    return {
      tenantId: data.identity.name,
      identityId: data.identity.id,
      sessionToken: data.sessionToken,
      claimToken: data.claimToken,
      level: 1,
      limits: {
        maxEntities: 1000,
        ttlHours: 24,
        maxRequestsPerMinute: 100,
      },
      upgrade: {
        nextLevel: 2,
        action: 'claim',
        description: 'Commit a GitHub Action workflow to claim this tenant',
        url: `https://id.org.ai/claim/${data.claimToken}`,
      },
    }
  }

  /**
   * Freeze an expired anonymous tenant.
   *
   * Data is preserved in the Durable Object for 30 days.
   * The freeze response shows what the agent built to drive claiming.
   */
  async freeze(identityId: string): Promise<FreezeResult> {
    const res = await this.identityStub.fetch(
      new Request(`https://id.org.ai/api/freeze/${identityId}`, { method: 'POST', headers: { ...this.internalHeaders() } })
    )

    if (!res.ok) {
      const body = await res.text()
      throw new Error(`Freeze failed (${res.status}): ${body}`)
    }

    const data = await res.json() as {
      frozen: boolean
      stats: { entities: number; events: number; sessions: number }
      expiresAt: number
    }

    return {
      frozen: data.frozen,
      identityId,
      stats: data.stats,
      claimUrl: `https://id.org.ai/claim/${identityId}`,
      expiresAt: new Date(data.expiresAt).toISOString(),
      message: data.stats.entities > 0
        ? `Your tenant has been frozen with ${data.stats.entities} entities and ${data.stats.events} events preserved. Claim within 30 days to keep your data.`
        : 'Your tenant has been frozen. Claim within 30 days to reactivate.',
    }
  }

  /**
   * Get the current status of a tenant by claim token.
   */
  async getStatus(claimToken: string): Promise<TenantStatus> {
    const res = await this.identityStub.fetch(
      new Request('https://id.org.ai/api/verify-claim', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...this.internalHeaders() },
        body: JSON.stringify({ token: claimToken }),
      })
    )

    const data = await res.json() as {
      valid: boolean
      identityId?: string
      status?: string
      level?: number
      stats?: { entities: number; events: number; createdAt: number; expiresAt?: number }
    }

    if (!data.valid || !data.identityId) {
      throw new Error('Invalid or expired claim token')
    }

    const isFrozen = data.status === 'frozen'
    const level = data.level ?? 0

    const status: TenantStatus = {
      identityId: data.identityId,
      level,
      claimStatus: data.status ?? 'unclaimed',
      frozen: isFrozen,
    }

    if (data.stats) {
      status.stats = {
        entities: data.stats.entities,
        events: data.stats.events,
        createdAt: new Date(data.stats.createdAt).toISOString(),
        expiresAt: data.stats.expiresAt ? new Date(data.stats.expiresAt).toISOString() : undefined,
      }
    }

    // Suggest upgrade path based on current level
    if (level < 2) {
      status.upgrade = {
        nextLevel: level + 1,
        action: level === 0 ? 'provision' : 'claim',
        url: level === 0
          ? 'https://id.org.ai/api/provision'
          : `https://id.org.ai/claim/${claimToken}`,
      }
    }

    return status
  }
}
