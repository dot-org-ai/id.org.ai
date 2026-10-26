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
 * If the caller knows the default branch, pass it: the signed push webhook
 * carries `repository.default_branch`, and the owner may name it when they
 * bind the claim (`POST /api/claim/bind`). GitHub's Actions OIDC token does
 * not carry it. Otherwise fall back to the main/master heuristic.
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
  /** OIDC `event_name`: the event that started the workflow run. */
  eventName: string
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
 * `repository_owner_id`, `ref`, `event_name`) in one place. The token carries
 * no default branch; see {@link isClaimedBranch}.
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
  return {
    githubUserId: claimString(oidcPayload.actor_id),
    githubUsername: claimString(oidcPayload.actor),
    repo: claimString(oidcPayload.repository),
    repositoryId: claimString(oidcPayload.repository_id),
    repositoryOwnerId: claimString(oidcPayload.repository_owner_id),
    branch,
    eventName: claimString(oidcPayload.event_name),
  }
}

/**
 * The workflow events a claim may come from. `push` is what the claim
 * workflow runs on; `workflow_dispatch` can only be started by someone with
 * write access to the repository. Events such as `pull_request_target`,
 * `workflow_run` or `issue_comment` run in the repository but carry an
 * outside contributor as `actor`, so they could link a stranger's GitHub
 * account to the tenant: refused.
 */
export const CLAIM_EVENTS: readonly string[] = ['push', 'workflow_dispatch']

export function isClaimEvent(eventName: string | undefined): boolean {
  return !!eventName && CLAIM_EVENTS.includes(eventName)
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
  if (!claim.eventName) missing.push('event_name')
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
 * The repository a claim token is bound to; every claim must come from it.
 *
 * The binding is written, in order of preference:
 *   1. before the token is published, by its owner: `POST /api/claim/bind`,
 *      authenticated by the tenant's session token, which is never committed
 *      (`id.org.ai claim` does this from `git remote get-url origin`). This
 *      names `repo` alone (and, optionally, `defaultBranch`); the first real
 *      claim from that repo adds the stable ids.
 *   2. Legacy path: by the first claim that uses an unbound token (trust on
 *      first use). Whoever claims first binds the token, so a token published
 *      before its owner's first claim can be taken by anyone who copies it.
 *      Kept so the claim page, older CLIs and hand-written workflows still
 *      work; `id.org.ai claim` always pre-binds.
 *   3. Recovered from a claim left pending before bindings existed, which
 *      names `repo` alone (from the linked GitHub account).
 */
export interface ClaimBinding {
  repo: string
  repositoryId?: string
  repositoryOwnerId?: string
  /** Named by the owner at bind time; used when the claim itself carries none. */
  defaultBranch?: string
  /** True when the owner bound the token before publishing it (path 1). */
  preBound?: boolean
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

/**
 * A GitHub `owner/name`. Owner: letters, digits and hyphens (1-39). Name:
 * letters, digits, `.`, `_` and `-` (1-100), and not `.` or `..`.
 */
const GITHUB_REPO = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})\/[A-Za-z0-9._-]{1,100}$/

export function isGitHubRepoName(repo: unknown): repo is string {
  if (typeof repo !== 'string' || !GITHUB_REPO.test(repo)) return false
  const name = repo.slice(repo.indexOf('/') + 1)
  return name !== '.' && name !== '..'
}

/**
 * The `owner/name` of a github.com remote URL, or null for anything else.
 * Accepts `https://github.com/o/r(.git)`, `git@github.com:o/r(.git)` and
 * `ssh://git@github.com/o/r(.git)` (with or without credentials or a port).
 */
export function githubRepoFromRemote(remoteUrl: string): string | null {
  const url = remoteUrl.trim()
  let path: string | null = null
  const scp = /^(?:[^@/\s]+@)?github\.com:(.+)$/i.exec(url)
  if (scp) {
    path = scp[1]
  } else {
    try {
      const parsed = new URL(url)
      if (!['https:', 'http:', 'ssh:', 'git:', 'git+ssh:'].includes(parsed.protocol)) return null
      if (parsed.hostname.toLowerCase() !== 'github.com') return null
      path = parsed.pathname
    } catch {
      return null
    }
  }
  const repo = path.replace(/^\/+/, '').replace(/\/+$/, '').replace(/\.git$/i, '')
  return isGitHubRepoName(repo) ? repo : null
}

/**
 * A plausible git branch name (a subset of `git check-ref-format --branch`):
 * printable ASCII without spaces, `~^:?*[\\`, `..`, `@{`, a leading `-` or
 * `/`, or a trailing `/`, `.` or `.lock`; at most 255 characters.
 */
export function isGitBranchName(branch: unknown): branch is string {
  if (typeof branch !== 'string' || branch.length === 0 || branch.length > 255) return false
  if (!/^[\x21-\x7e]+$/.test(branch)) return false
  if (/[~^:?*[\\]/.test(branch) || branch.includes('..') || branch.includes('@{') || branch.includes('//')) return false
  if (branch.startsWith('-') || branch.startsWith('/') || branch.endsWith('/') || branch.endsWith('.') || branch.endsWith('.lock')) return false
  return true
}
