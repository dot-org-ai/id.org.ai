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
  isClaimEvent,
  githubRepoFromRemote,
  isGitHubRepoName,
  isGitBranchName,
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
    event_name: 'push',
  }

  it('extracts canonical fields from the OIDC payload', () => {
    expect(parseGitHubOIDC(oidcPayload)).toEqual({
      githubUserId: '12345',
      githubUsername: 'alice',
      repo: 'alice/myrepo',
      repositoryId: '777',
      repositoryOwnerId: '12345',
      branch: 'main',
      eventName: 'push',
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

  it('reads no default branch: GitHub Actions OIDC tokens carry none', () => {
    const parsed = parseGitHubOIDC({ ...oidcPayload, repository_default_branch: 'develop' }) as unknown as Record<string, unknown>
    expect(parsed.defaultBranch).toBeUndefined()
  })

  it('lists the required claims a token lacks', () => {
    expect(missingGitHubOIDCClaims(parseGitHubOIDC(oidcPayload))).toEqual([])
    const { repository_id: _r, actor_id: _a, ...without } = oidcPayload
    expect(missingGitHubOIDCClaims(parseGitHubOIDC(without)).sort()).toEqual(['actor_id', 'repository_id'])
    const { event_name: _e, ...noEvent } = oidcPayload
    expect(missingGitHubOIDCClaims(parseGitHubOIDC(noEvent))).toEqual(['event_name'])
  })
})

describe('isClaimEvent', () => {
  it('accepts push and workflow_dispatch runs', () => {
    expect(isClaimEvent('push')).toBe(true)
    expect(isClaimEvent('workflow_dispatch')).toBe(true)
  })

  // These run in the bound repository but carry an outside contributor as
  // the actor; a claim from one could link a stranger's GitHub account.
  it('refuses events an outsider can trigger, and a missing event', () => {
    for (const event of ['pull_request_target', 'pull_request', 'workflow_run', 'issue_comment', 'issues', 'schedule', '', undefined]) {
      expect(isClaimEvent(event), String(event)).toBe(false)
    }
  })
})

describe('githubRepoFromRemote', () => {
  it('reads owner/name from the github.com remote forms git uses', () => {
    expect(githubRepoFromRemote('https://github.com/alice/app.git')).toBe('alice/app')
    expect(githubRepoFromRemote('https://github.com/alice/app')).toBe('alice/app')
    expect(githubRepoFromRemote('https://x-access-token:secret@github.com/alice/app.git')).toBe('alice/app')
    expect(githubRepoFromRemote('git@github.com:alice/app.git')).toBe('alice/app')
    expect(githubRepoFromRemote('ssh://git@github.com/alice/my.app.git')).toBe('alice/my.app')
    expect(githubRepoFromRemote('ssh://git@github.com:22/alice/app.git\n')).toBe('alice/app')
  })

  it('refuses other hosts and malformed paths', () => {
    expect(githubRepoFromRemote('https://gitlab.com/alice/app.git')).toBeNull()
    expect(githubRepoFromRemote('https://github.com.evil.example/alice/app.git')).toBeNull()
    expect(githubRepoFromRemote('git@gitlab.com:alice/app.git')).toBeNull()
    expect(githubRepoFromRemote('https://github.com/alice')).toBeNull()
    expect(githubRepoFromRemote('https://github.com/alice/app/tree/main')).toBeNull()
    expect(githubRepoFromRemote('/srv/git/app.git')).toBeNull()
    expect(githubRepoFromRemote('file:///github.com/alice/app')).toBeNull()
  })
})

describe('isGitHubRepoName', () => {
  it('accepts owner/name and refuses anything else', () => {
    expect(isGitHubRepoName('alice/app')).toBe(true)
    expect(isGitHubRepoName('a-1/x_y.z')).toBe(true)
    for (const bad of ['alice', 'alice/', '/app', 'alice/app/x', '-alice/app', 'alice/..', 'al ice/app', 'alice/app\n', 42, undefined]) {
      expect(isGitHubRepoName(bad), String(bad)).toBe(false)
    }
  })
})

describe('isGitBranchName', () => {
  it('accepts ordinary branch names and refuses malformed ones', () => {
    for (const ok of ['main', 'trunk', 'release/1.2', 'feature/x-y_z']) expect(isGitBranchName(ok), ok).toBe(true)
    for (const bad of ['', 'a b', 'a..b', 'a~1', 'a:b', '-x', '/x', 'x/', 'x.', 'x.lock', 'a@{1}', 'a//b', 'x\n', 'a'.repeat(256), 1]) {
      expect(isGitBranchName(bad), String(bad)).toBe(false)
    }
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
