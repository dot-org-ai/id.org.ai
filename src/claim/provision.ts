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

import type { IdentityStub } from '../do/Identity'

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
  private identityStub: IdentityStub

  constructor(identityStub: IdentityStub) {
    this.identityStub = identityStub
  }

  /**
   * Provision an anonymous sandbox tenant via direct RPC.
   */
  async provision(): Promise<ProvisionResult> {
    const data = await this.identityStub.provisionAnonymous()

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
   * Freeze an expired anonymous tenant via direct RPC.
   */
  async freeze(identityId: string): Promise<FreezeResult> {
    const data = await this.identityStub.freezeIdentity(identityId)

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
   * Get the current status of a tenant by claim token via direct RPC.
   */
  async getStatus(claimToken: string): Promise<TenantStatus> {
    const data = await this.identityStub.verifyClaimToken(claimToken)

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
