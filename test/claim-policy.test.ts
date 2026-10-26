/**
 * Claim Policy — pure-module unit tests.
 *
 * These cover the URL-free state machine and GitHub OIDC parsing. They run
 * fast (no Workers runtime) and protect against regressions in the upgrade
 * rules — historically duplicated in three files.
 */
import { describe, it, expect } from 'vitest'
import {
  upgradePathFor,
  upgradeUrl,
  isClaimedBranch,
  matchClaimBinding,
  bodyClaimMismatches,
  missingGitHubOIDCClaims,
  parseGitHubOIDC,
} from '../src/sdk/claim/policy'

describe('upgradePathFor', () => {
  it('returns provision for L0', () => {
    const path = upgradePathFor(0, 'unclaimed')
    expect(path).toEqual({ nextLevel: 1, action: 'provision', pathTemplate: '/api/provision' })
  })

  it('returns claim for L1 with a claim token', () => {
    const path = upgradePathFor(1, 'unclaimed', 'clm_abc123')
    expect(path).toEqual({ nextLevel: 2, action: 'claim', pathTemplate: '/claim/clm_abc123' })
  })

  it('returns null for L1 without a claim token (caller cannot build a URL)', () => {
    expect(upgradePathFor(1, 'unclaimed')).toBeNull()
  })

  it('returns null when status is claimed (already at the target)', () => {
    expect(upgradePathFor(1, 'claimed', 'clm_x')).toBeNull()
  })

  it('returns null for L2 — L2→L3 lives in downstream products, not the library', () => {
    expect(upgradePathFor(2, 'unclaimed', 'clm_x')).toBeNull()
  })

  it('returns null for L3', () => {
    expect(upgradePathFor(3, 'claimed')).toBeNull()
  })
})

describe('upgradeUrl', () => {
  it('appends pathTemplate to the caller-supplied origin', () => {
    const path = upgradePathFor(0, 'unclaimed')!
    expect(upgradeUrl(path, 'https://id.org.ai')).toBe('https://id.org.ai/api/provision')
  })

  it('honours custom origins (auth.org.ai, dev hosts)', () => {
    const path = upgradePathFor(1, 'unclaimed', 'clm_xyz')!
    expect(upgradeUrl(path, 'https://auth.org.ai')).toBe('https://auth.org.ai/claim/clm_xyz')
    expect(upgradeUrl(path, 'http://localhost:8787')).toBe('http://localhost:8787/claim/clm_xyz')
  })
})

describe('isClaimedBranch', () => {
  it('matches the explicit default branch when provided', () => {
    expect(isClaimedBranch('main', 'main')).toBe(true)
    expect(isClaimedBranch('feature/x', 'main')).toBe(false)
    expect(isClaimedBranch('trunk', 'trunk')).toBe(true)
  })

  it('falls back to main/master when no default is provided', () => {
    expect(isClaimedBranch('main')).toBe(true)
    expect(isClaimedBranch('master')).toBe(true)
    expect(isClaimedBranch('feature/x')).toBe(false)
    expect(isClaimedBranch('trunk')).toBe(false)
  })

  it('returns false for missing/empty branch', () => {
    expect(isClaimedBranch(undefined)).toBe(false)
    expect(isClaimedBranch('')).toBe(false)
  })

  it('honours an explicit non-main default — the heuristic does not leak', () => {
    expect(isClaimedBranch('main', 'develop')).toBe(false)
  })
})

describe('parseGitHubOIDC', () => {
  const oidcPayload = {
    actor_id: '12345',
    actor: 'alice',
    repository: 'alice/myrepo',
    repository_id: '777',
    repository_owner: 'alice',
    repository_owner_id: '12345',
    ref: 'refs/heads/main',
    repository_default_branch: 'main',
  }

  it('extracts canonical fields from the OIDC payload', () => {
    expect(parseGitHubOIDC(oidcPayload)).toEqual({
      githubUserId: '12345',
      githubUsername: 'alice',
      repo: 'alice/myrepo',
      repositoryId: '777',
      repositoryOwnerId: '12345',
      branch: 'main',
      defaultBranch: 'main',
    })
  })

  // H1: the request body must never override a verified OIDC claim. The
  // claim token is public in the committed workflow, so a body override
  // would let anyone with any OIDC token claim as anyone, on any branch.
  it('takes identity only from the verified claims: request body fields are reported, never applied', () => {
    const body = { githubUserId: '666', githubUsername: 'mallory', repo: 'victim/repo', branch: 'main' }
    const result = parseGitHubOIDC({ ...oidcPayload, ref: 'refs/heads/feature/x' })
    expect(result.githubUserId).toBe('12345')
    expect(result.githubUsername).toBe('alice')
    expect(result.repo).toBe('alice/myrepo')
    expect(result.branch).toBe('feature/x')
    expect(bodyClaimMismatches(result, body).sort()).toEqual(['branch', 'githubUserId', 'githubUsername', 'repo'])
  })

  it('reports no mismatch when the body repeats the verified claims (the dot-org-ai/id action does)', () => {
    const result = parseGitHubOIDC(oidcPayload)
    expect(bodyClaimMismatches(result, { githubUserId: '12345', githubUsername: 'alice', repo: 'alice/myrepo', branch: 'main' })).toEqual([])
    expect(bodyClaimMismatches(result, {})).toEqual([])
  })

  it('stringifies numeric ids', () => {
    const result = parseGitHubOIDC({ ...oidcPayload, actor_id: 12345, repository_id: 777, repository_owner_id: 42 })
    expect(result.githubUserId).toBe('12345')
    expect(result.repositoryId).toBe('777')
    expect(result.repositoryOwnerId).toBe('42')
  })

  it('strips refs/heads/ from the ref', () => {
    const result = parseGitHubOIDC({ ...oidcPayload, ref: 'refs/heads/feature/abc' })
    expect(result.branch).toBe('feature/abc')
  })

  it('derives no branch from a tag or pull-request ref', () => {
    expect(parseGitHubOIDC({ ...oidcPayload, ref: 'refs/tags/main' }).branch).toBe('')
    expect(parseGitHubOIDC({ ...oidcPayload, ref: 'refs/pull/1/merge' }).branch).toBe('')
  })

  it('returns undefined defaultBranch when OIDC omits it', () => {
    const { repository_default_branch: _omit, ...without } = oidcPayload
    expect(parseGitHubOIDC(without).defaultBranch).toBeUndefined()
  })

  it('lists the required claims a token lacks', () => {
    expect(missingGitHubOIDCClaims(parseGitHubOIDC(oidcPayload))).toEqual([])
    const { repository_id: _r, actor_id: _a, ...without } = oidcPayload
    expect(missingGitHubOIDCClaims(parseGitHubOIDC(without)).sort()).toEqual(['actor_id', 'repository_id'])
  })
})

describe('matchClaimBinding', () => {
  const bound = { repo: 'alice/app', repositoryId: '1001', repositoryOwnerId: '501', boundAt: 1 }

  it('refuses a claim that names no repository', () => {
    expect(matchClaimBinding(null, {})).toBe('missing')
  })

  it('binds when nothing is bound yet', () => {
    expect(matchClaimBinding(null, { repo: 'alice/app', repositoryId: '1001', repositoryOwnerId: '501' })).toBe('bind')
  })

  it('matches on repository id and owner id, not on name', () => {
    expect(matchClaimBinding(bound, { repo: 'alice/renamed', repositoryId: '1001', repositoryOwnerId: '501' })).toBe('match')
    expect(matchClaimBinding(bound, { repo: 'alice/app', repositoryId: '1002', repositoryOwnerId: '501' })).toBe('mismatch')
    expect(matchClaimBinding(bound, { repo: 'alice/app', repositoryId: '1001', repositoryOwnerId: '666' })).toBe('mismatch')
    expect(matchClaimBinding(bound, { repo: 'alice/app' })).toBe('mismatch')
  })

  it('matches a name-only legacy binding by case-insensitive name', () => {
    const legacy = { repo: 'Alice/App', boundAt: 1 }
    expect(matchClaimBinding(legacy, { repo: 'alice/app', repositoryId: '1001' })).toBe('match')
    expect(matchClaimBinding(legacy, { repo: 'mallory/fork', repositoryId: '9999' })).toBe('mismatch')
  })
})
