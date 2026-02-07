/**
 * Claim-by-Commit Service
 *
 * Orchestrates the Connect → Operate → Claim flow:
 *   1. provision() — creates anonymous sandbox tenant
 *   2. claim() — links anonymous tenant to GitHub identity
 *   3. verify() — checks claim token validity and tenant status
 *   4. freeze() — freezes expired anonymous tenants (data preserved 30 days)
 *   5. getStatus() — returns full tenant status by claim token
 */

export { ClaimService } from './provision'
export type { ProvisionResult, FreezeResult, TenantStatus } from './provision'
export { verifyClaim } from './verify'
export type { ClaimStatus } from './verify'
