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
 *
 * Ids are strings (GitHub sends them as strings; numbers are stringified).
 * `repositoryId` and `repositoryOwnerId` are stable across renames and
 * transfers-by-name, so the claim binds to them rather than to `repo`.
 */
export interface GitHubClaim {
  githubUserId: string
  githubUsername: string
  repo: string
  repositoryId: string
  repositoryOwnerId: string
  branch: string
  defaultBranch?: string
}

/** What a claim request body may say about the GitHub side. Never authoritative. */
export interface GitHubClaimBody {
  githubUserId?: string
  githubUsername?: string
  repo?: string
  branch?: string
}

function claimString(value: unknown): string {
  if (typeof value === 'string') return value
  if (typeof value === 'number' && Number.isFinite(value)) return String(value)
  return ''
}

/**
 * Pull claim params from a *verified* OIDC payload. Concentrates the
 * field-name knowledge (`actor_id`, `actor`, `repository`, `repository_id`,
 * `repository_owner_id`, `ref`, `repository_default_branch`) in one place.
 *
 * The verified claims are the only source (H1). The claim token travels in a
 * committed workflow file and is public in any public repo, so a request body
 * that could override these would let anyone holding *any* GitHub OIDC token
 * claim the tenant as any user, from any branch. Callers that want to notice
 * a disagreeing body use {@link bodyClaimMismatches}.
 *
 * `branch` is set only for a branch ref (`refs/heads/…`); a tag or pull-request
 * ref yields '' and so can never finalise a claim.
 */
export function parseGitHubOIDC(oidcPayload: JWTPayload): GitHubClaim {
  const ref = claimString(oidcPayload.ref)
  const branch = ref.startsWith('refs/heads/') ? ref.slice('refs/heads/'.length) : ''
  const defaultBranch =
    typeof oidcPayload.repository_default_branch === 'string'
      ? oidcPayload.repository_default_branch
      : undefined
  return {
    githubUserId: claimString(oidcPayload.actor_id),
    githubUsername: claimString(oidcPayload.actor),
    repo: claimString(oidcPayload.repository),
    repositoryId: claimString(oidcPayload.repository_id),
    repositoryOwnerId: claimString(oidcPayload.repository_owner_id),
    branch,
    defaultBranch,
  }
}

/**
 * The OIDC claims a claim-by-commit needs, by their GitHub names, that the
 * parsed token lacks. Empty means the token can be used.
 */
export function missingGitHubOIDCClaims(claim: GitHubClaim): string[] {
  const missing: string[] = []
  if (!claim.githubUserId) missing.push('actor_id')
  if (!claim.repo) missing.push('repository')
  if (!claim.repositoryId) missing.push('repository_id')
  if (!claim.repositoryOwnerId) missing.push('repository_owner_id')
  return missing
}

/**
 * Body fields that disagree with the verified claims. They are ignored either
 * way; this exists so the caller can record the disagreement (an honest
 * `dot-org-ai/id` action repeats the OIDC values, so a mismatch is a signal).
 */
export function bodyClaimMismatches(claim: GitHubClaim, body: GitHubClaimBody): Array<keyof GitHubClaimBody> {
  const out: Array<keyof GitHubClaimBody> = []
  for (const key of ['githubUserId', 'githubUsername', 'repo', 'branch'] as const) {
    const value = body[key]
    if (value !== undefined && value !== null && value !== '' && String(value) !== claim[key]) out.push(key)
  }
  return out
}

/**
 * The repository a claim token is bound to. Recorded by the first claim that
 * uses the token (pending or final); every later claim must come from it.
 * `repositoryId`/`repositoryOwnerId` are absent only on a binding recovered
 * from a claim left pending before bindings existed, which names `repo` alone.
 */
export interface ClaimBinding {
  repo: string
  repositoryId?: string
  repositoryOwnerId?: string
  boundAt: number
}

/** The repository a claim says it comes from (verified OIDC claims or a signed webhook). */
export interface ClaimRepository {
  repo?: string
  repositoryId?: string
  repositoryOwnerId?: string
}

/**
 * Pure: may a claim from `incoming` proceed against `bound`?
 *   - 'missing'  — the claim names no repository, so it cannot be bound: refuse.
 *   - 'bind'     — nothing bound yet: proceed, and bind to `incoming`.
 *   - 'match'    — same repository (by id, and by owner id when both are known;
 *                  by case-insensitive name for a name-only legacy binding).
 *   - 'mismatch' — another repository: refuse.
 */
export function matchClaimBinding(
  bound: ClaimBinding | null | undefined,
  incoming: ClaimRepository,
): 'missing' | 'bind' | 'match' | 'mismatch' {
  if (!incoming.repositoryId && !incoming.repo) return 'missing'
  if (!bound) return 'bind'
  if (bound.repositoryId) {
    if (incoming.repositoryId !== bound.repositoryId) return 'mismatch'
    if (bound.repositoryOwnerId && incoming.repositoryOwnerId !== bound.repositoryOwnerId) return 'mismatch'
    return 'match'
  }
  if (!incoming.repo || incoming.repo.toLowerCase() !== bound.repo.toLowerCase()) return 'mismatch'
  return 'match'
}
