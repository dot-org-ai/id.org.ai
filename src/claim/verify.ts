/**
 * Claim Token Verification
 *
 * Validates claim tokens against the IdentityDO and returns
 * full tenant status including entity/event stats.
 *
 * Token format: clm_<32-hex-chars>
 * Statuses: unclaimed | pending | claimed | frozen | expired
 */

export interface ClaimStatus {
  valid: boolean
  identityId?: string
  status?: 'unclaimed' | 'pending' | 'claimed' | 'frozen' | 'expired'
  level?: number
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

/**
 * Verify a claim token against the IdentityDO.
 *
 * @param claimToken - The claim token to verify (must start with clm_)
 * @param identityStub - DurableObject stub for the IdentityDO
 * @returns Full claim status with stats and upgrade path
 */
export async function verifyClaim(
  claimToken: string,
  identityStub: { fetch(input: string | Request): Promise<Response> },
  authSecret?: string,
): Promise<ClaimStatus> {
  // Validate token format
  if (!claimToken || !claimToken.startsWith('clm_')) {
    return { valid: false }
  }

  // Validate minimum length (clm_ + at least 16 chars)
  if (claimToken.length < 20) {
    return { valid: false }
  }

  // Look up in IdentityDO via /api/verify-claim
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  if (authSecret) headers['X-Worker-Auth'] = authSecret
  const res = await identityStub.fetch(
    new Request('https://id.org.ai/api/verify-claim', {
      method: 'POST',
      headers,
      body: JSON.stringify({ token: claimToken }),
    })
  )

  if (!res.ok) {
    return { valid: false }
  }

  const data = await res.json() as {
    valid: boolean
    identityId?: string
    status?: 'unclaimed' | 'pending' | 'claimed' | 'frozen' | 'expired'
    level?: number
    stats?: {
      entities: number
      events: number
      createdAt: number
      expiresAt?: number
    }
  }

  if (!data.valid) {
    return { valid: false }
  }

  const result: ClaimStatus = {
    valid: true,
    identityId: data.identityId,
    status: data.status,
    level: data.level,
  }

  // Convert timestamps to ISO strings for the public interface
  if (data.stats) {
    result.stats = {
      entities: data.stats.entities,
      events: data.stats.events,
      createdAt: new Date(data.stats.createdAt).toISOString(),
      expiresAt: data.stats.expiresAt
        ? new Date(data.stats.expiresAt).toISOString()
        : undefined,
    }
  }

  // Include upgrade path for non-claimed tenants
  const level = data.level ?? 0
  if (data.status !== 'claimed' && level < 3) {
    if (level === 0) {
      result.upgrade = {
        nextLevel: 1,
        action: 'provision',
        url: 'https://id.org.ai/api/provision',
      }
    } else if (level === 1) {
      result.upgrade = {
        nextLevel: 2,
        action: 'claim',
        url: `https://id.org.ai/claim/${claimToken}`,
      }
    } else if (level === 2) {
      result.upgrade = {
        nextLevel: 3,
        action: 'subscribe',
        url: 'https://headless.ly/pricing',
      }
    }
  }

  return result
}
