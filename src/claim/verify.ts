/**
 * Claim Token Verification
 *
 * Validates claim tokens and returns tenant status.
 */

export interface ClaimStatus {
  valid: boolean
  tenantId?: string
  status?: 'unclaimed' | 'pending' | 'claimed' | 'frozen' | 'expired'
  stats?: {
    entities: number
    events: number
    createdAt: string
    expiresAt?: string
  }
}

export async function verifyClaim(claimToken: string): Promise<ClaimStatus> {
  if (!claimToken.startsWith('clm_')) {
    return { valid: false }
  }

  // TODO: Look up claim token in IdentityDO
  return { valid: false }
}
