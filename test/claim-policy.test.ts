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
    ref: 'refs/heads/main',
    repository_default_branch: 'main',
  }

  it('extracts canonical fields from the OIDC payload', () => {
    expect(parseGitHubOIDC(oidcPayload)).toEqual({
      githubUserId: '12345',
      githubUsername: 'alice',
      repo: 'alice/myrepo',
      branch: 'main',
      defaultBranch: 'main',
    })
  })

  it('lets request body fields override OIDC fields', () => {
    const result = parseGitHubOIDC(oidcPayload, { githubUsername: 'bob', branch: 'feature/x' })
    expect(result.githubUsername).toBe('bob')
    expect(result.branch).toBe('feature/x')
    expect(result.repo).toBe('alice/myrepo')
  })

  it('strips refs/heads/ from the ref', () => {
    const result = parseGitHubOIDC({ ...oidcPayload, ref: 'refs/heads/feature/abc' })
    expect(result.branch).toBe('feature/abc')
  })

  it('returns undefined defaultBranch when OIDC omits it', () => {
    const { repository_default_branch: _omit, ...without } = oidcPayload
    expect(parseGitHubOIDC(without).defaultBranch).toBeUndefined()
  })
})
