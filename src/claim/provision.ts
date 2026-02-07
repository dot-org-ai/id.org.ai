/**
 * Anonymous Tenant Provisioning
 *
 * Creates a real (not mock) sandbox tenant when an agent connects
 * to the MCP endpoint without authentication.
 *
 * Key principle: no sandbox distinction. Anonymous tenants ARE production
 * tenants — same Durable Object, same schema, same event log. The only
 * differences are entity limits and integration access.
 */

export interface ProvisionResult {
  tenantId: string
  sessionToken: string
  claimToken: string
  level: 1
  limits: {
    maxEntities: number
    ttlHours: number
  }
}

export class ClaimService {
  /**
   * Provision an anonymous sandbox tenant.
   *
   * Returns a session token (for ongoing requests) and a claim token
   * (for later claiming via GitHub commit).
   */
  async provision(): Promise<ProvisionResult> {
    const tenantId = `anon_${crypto.randomUUID().slice(0, 8)}`
    const sessionToken = `ses_${crypto.randomUUID().replace(/-/g, '')}`
    const claimToken = `clm_${crypto.randomUUID().replace(/-/g, '')}`

    // TODO: Create anonymous identity in IdentityDO
    // TODO: Provision tenant Durable Object

    return {
      tenantId,
      sessionToken,
      claimToken,
      level: 1,
      limits: {
        maxEntities: 1000,
        ttlHours: 24,
      },
    }
  }

  /**
   * Freeze an expired anonymous tenant.
   *
   * Data is preserved in R2 cold storage for 30 days.
   * The freeze response shows what the agent built to drive claiming.
   */
  async freeze(tenantId: string): Promise<{
    frozen: boolean
    stats: { contacts: number; deals: number; tasks: number; events: number }
    claimUrl: string
    expiresAt: string
  }> {
    // TODO: Read entity counts from tenant DO
    // TODO: Move data to R2 cold storage
    // TODO: Mark identity as frozen

    return {
      frozen: true,
      stats: { contacts: 0, deals: 0, tasks: 0, events: 0 },
      claimUrl: `https://id.org.ai/claim/${tenantId}`,
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
    }
  }
}
