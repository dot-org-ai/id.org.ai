/**
 * Claim Policy — pure state machine for the Connect → Operate → Claim flow.
 *
 * URL-free by design. The library owns *what* the next step is; the worker
 * (or other caller) owns *where* it lives, since URLs come from the inbound
 * request host (id.org.ai, auth.org.ai, or a custom domain).
 *
 * Scope: L0→L1 (provision) and L1→L2 (claim). L2→L3 is downstream product
 * surface (e.g. headless.ly, hq.com.ai) and not represented here.
 */
import type { JWTPayload } from 'jose'
import type { CapabilityLevel, ClaimStatus } from '../types'

/**
 * Where a tenant goes next. `pathTemplate` is the worker-relative path the
 * caller appends to its origin to build a full URL.
 */
export interface UpgradePath {
  nextLevel: 1 | 2
  action: 'provision' | 'claim'
  pathTemplate: '/api/provision' | `/claim/${string}`
}

/**
 * Pure: given current level + claim status, return the next step or null.
 * No URLs, no host knowledge — callers attach their own origin.
 */
export function upgradePathFor(
  level: CapabilityLevel,
  status: ClaimStatus | undefined,
  claimToken?: string,
): UpgradePath | null {
  if (status === 'claimed') return null
  if (level === 0) {
    return { nextLevel: 1, action: 'provision', pathTemplate: '/api/provision' }
  }
  if (level === 1 && claimToken) {
    return { nextLevel: 2, action: 'claim', pathTemplate: `/claim/${claimToken}` }
  }
  return null
}

/**
 * Build a full URL for an upgrade step, given the inbound origin.
 * Worker callers pass `new URL(c.req.url).origin`.
 */
export function upgradeUrl(path: UpgradePath, origin: string): string {
  return `${origin}${path.pathTemplate}`
}

/**
 * A push to the repo's default branch finalises the claim ('claimed').
 * Anything else stays 'pending'.
 *
 * If the caller knows the default branch (from GitHub OIDC), pass it.
 * Otherwise fall back to the main/master heuristic.
 */
export function isClaimedBranch(branch: string | undefined, defaultBranch?: string): boolean {
  if (!branch) return false
  if (defaultBranch) return branch === defaultBranch
  return branch === 'main' || branch === 'master'
}

/**
 * Fields extracted from a GitHub Actions OIDC token.
 * See https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect#understanding-the-oidc-token
 */
export interface GitHubClaim {
  githubUserId: string
  githubUsername: string
  repo: string
  branch: string
  defaultBranch?: string
}

/**
 * Pull claim params from an OIDC payload, falling back to body fields when
 * present. Concentrates the field-name knowledge (`actor_id`, `actor`,
 * `repository`, `ref`, `repository_default_branch`) in one place.
 */
export function parseGitHubOIDC(
  oidcPayload: JWTPayload,
  body: {
    githubUserId?: string
    githubUsername?: string
    repo?: string
    branch?: string
  } = {},
): GitHubClaim {
  const githubUserId = body.githubUserId || (oidcPayload.actor_id as string) || ''
  const githubUsername = body.githubUsername || (oidcPayload.actor as string) || ''
  const repo = body.repo || (oidcPayload.repository as string) || ''
  const ref = (oidcPayload.ref as string) ?? ''
  const branch = body.branch || ref.replace('refs/heads/', '') || ''
  const defaultBranch =
    typeof oidcPayload.repository_default_branch === 'string'
      ? oidcPayload.repository_default_branch
      : undefined
  return { githubUserId, githubUsername, repo, branch, defaultBranch }
}
