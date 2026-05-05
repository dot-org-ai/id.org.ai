/**
 * Claim Token Verification
 *
 * Validates claim tokens against the IdentityDO and returns
 * full tenant status including entity/event stats.
 *
 * Token format: clm_<32-hex-chars>
 * Statuses: unclaimed | pending | claimed | frozen | expired
 */

import type { IdentityStub } from '../types'
import { upgradePathFor, upgradeUrl } from './policy'

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
    /** Optional. Worker callers attach a per-host URL; library leaves it blank. */
    url?: string
  }
}

/**
 * Verify a claim token against the IdentityDO via RPC.
 *
 * @param claimToken - The claim token to verify (must start with clm_)
 * @param identityStub - IdentityDO stub (Workers RPC)
 * @returns Full claim status with stats and upgrade path
 */
export async function verifyClaim(
  claimToken: string,
  identityStub: IdentityStub,
  origin?: string,
): Promise<ClaimStatus> {
  // Validate token format
  if (!claimToken || !claimToken.startsWith('clm_')) {
    return { valid: false }
  }

  // Validate minimum length (clm_ + at least 16 chars)
  if (claimToken.length < 20) {
    return { valid: false }
  }

  // Look up via direct RPC call
  const data = await identityStub.verifyClaimToken(claimToken)

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

  // Single source of truth for upgrade-path policy.
  const path = upgradePathFor((data.level ?? 0) as 0 | 1 | 2 | 3, data.status, claimToken)
  if (path) {
    result.upgrade = {
      nextLevel: path.nextLevel,
      action: path.action,
      url: origin ? upgradeUrl(path, origin) : undefined,
    }
  }

  return result
}
