/**
 * POST /api/claim — claim-by-commit over GitHub Actions OIDC (H1).
 *
 * The claim token travels in the committed workflow file, so it is public in
 * any public repo. These tests pin that:
 *   - identity comes only from the verified OIDC claims; request body fields
 *     never override them;
 *   - the claim is bound to the repository (and owner) that first used it, so
 *     an OIDC token from another repo cannot claim with a copied token.
 *
 * GitHub's JWKS is faked with fetchMock; tokens are signed with a local key.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { SELF, fetchMock, env } from 'cloudflare:test'
import * as jose from 'jose'
import { getStubForIdentity, resolveIdentityFromClaim } from '../worker/middleware/tenant'
import type { Env } from '../worker/types'

const BASE = 'https://id.org.ai'
const GITHUB_OIDC = 'https://token.actions.githubusercontent.com'

let privateKey: CryptoKey

beforeAll(async () => {
  const pair = await jose.generateKeyPair('RS256', { extractable: true })
  privateKey = pair.privateKey as CryptoKey
  const jwk = { ...(await jose.exportJWK(pair.publicKey)), kid: 'test-kid', alg: 'RS256', use: 'sig' }
  fetchMock.activate()
  fetchMock.disableNetConnect()
  fetchMock
    .get(GITHUB_OIDC)
    .intercept({ method: 'GET', path: '/.well-known/jwks' })
    .reply(200, JSON.stringify({ keys: [jwk] }), { headers: { 'content-type': 'application/json' } })
    .persist()
})

afterAll(() => fetchMock.deactivate())

interface Repo {
  repository: string
  repository_id: string
  repository_owner: string
  repository_owner_id: string
}

const OWNER_REPO: Repo = { repository: 'alice/app', repository_id: '1001', repository_owner: 'alice', repository_owner_id: '501' }
const ATTACKER_REPO: Repo = { repository: 'mallory/fork', repository_id: '9999', repository_owner: 'mallory', repository_owner_id: '666' }

async function oidcToken(repo: Repo, actor: { actor: string; actor_id: string }, ref: string, extra: Record<string, unknown> = {}): Promise<string> {
  return new jose.SignJWT({ ...repo, ...actor, ref, ref_type: 'branch', event_name: 'push', ...extra })
    .setProtectedHeader({ alg: 'RS256', kid: 'test-kid' })
    .setIssuer(GITHUB_OIDC)
    .setAudience('id.org.ai')
    .setSubject(`repo:${repo.repository}:ref:${ref}`)
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(privateKey)
}

async function provision(): Promise<{ claimToken: string; identityId: string; sessionToken: string }> {
  const res = await SELF.fetch(`${BASE}/api/provision`, { method: 'POST' })
  expect(res.status).toBe(201)
  const body = (await res.json()) as { claimToken: string; identityId: string; sessionToken: string }
  return body
}

async function bind(sessionToken: string | null, body: Record<string, unknown>): Promise<Response> {
  return SELF.fetch(`${BASE}/api/claim/bind`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...(sessionToken ? { authorization: `Bearer ${sessionToken}` } : {}) },
    body: JSON.stringify(body),
  })
}

async function postClaim(token: string, body: Record<string, unknown>): Promise<Response> {
  return SELF.fetch(`${BASE}/api/claim`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
    body: JSON.stringify(body),
  })
}

async function stored(claimToken: string): Promise<Record<string, unknown>> {
  const identityId = await resolveIdentityFromClaim(claimToken, env as unknown as Env)
  const stub = getStubForIdentity(env as unknown as Env, identityId!)
  const { value } = await stub.oauthStorageOp({ op: 'get', key: `identity:${identityId}` })
  return value as Record<string, unknown>
}

const ALICE = { actor: 'alice', actor_id: '501' }
const MALLORY = { actor: 'mallory', actor_id: '666' }

describe('POST /api/claim (GitHub OIDC)', () => {
  it('claims from the default branch of the repository the OIDC token names', async () => {
    const { claimToken } = await provision()
    const token = await oidcToken(OWNER_REPO, ALICE, 'refs/heads/main')
    const res = await postClaim(token, { claimToken, githubUserId: '501', githubUsername: 'alice', repo: 'alice/app', branch: 'main' })
    expect(res.status).toBe(200)
    const record = await stored(claimToken)
    expect(record.claimStatus).toBe('claimed')
    expect(record.level).toBe(2)
    expect(record.githubUserId).toBe('501')
  })

  it('ignores body fields that contradict the verified claims (branch, user id, repo)', async () => {
    const { claimToken } = await provision()
    // A push to a feature branch: OIDC says feature/x. The body claims main,
    // another user and another repo — none of it may count.
    const token = await oidcToken(OWNER_REPO, ALICE, 'refs/heads/feature/x')
    const res = await postClaim(token, { claimToken, githubUserId: '666', githubUsername: 'mallory', repo: 'mallory/fork', branch: 'main' })
    expect(res.status).toBe(200)
    const record = await stored(claimToken)
    expect(record.claimStatus).toBe('pending')
    expect(record.level).toBe(1)
    expect(record.githubUserId).toBe('501')
    expect(record.githubUsername).toBe('alice')
  })

  it('refuses an OIDC token from another repository once the claim is bound (copied-token attack)', async () => {
    const { claimToken } = await provision()
    // The rightful owner's first push binds the claim to alice/app.
    const first = await postClaim(await oidcToken(OWNER_REPO, ALICE, 'refs/heads/feature/x'), { claimToken })
    expect(first.status).toBe(200)

    // Mallory copies clm_… from the public commit and runs a workflow in her
    // own repo, with a body that names the victim.
    const attack = await postClaim(await oidcToken(ATTACKER_REPO, MALLORY, 'refs/heads/main'), {
      claimToken,
      githubUserId: '501',
      githubUsername: 'alice',
      repo: 'alice/app',
      branch: 'main',
    })
    expect(attack.status).toBe(400)
    const err = (await attack.json()) as { error: string }
    expect(err.error).toContain('bound to another repository')

    const record = await stored(claimToken)
    expect(record.claimStatus).toBe('pending')
    expect(record.githubUserId).toBe('501')

    // The owner can still finalise from the bound repo.
    const owner = await postClaim(await oidcToken(OWNER_REPO, ALICE, 'refs/heads/main'), { claimToken })
    expect(owner.status).toBe(200)
    expect((await stored(claimToken)).claimStatus).toBe('claimed')
  })

  it('refuses an OIDC token that lacks the repository and actor ids', async () => {
    const { claimToken } = await provision()
    const token = await new jose.SignJWT({ repository: 'alice/app', actor: 'alice', ref: 'refs/heads/main' })
      .setProtectedHeader({ alg: 'RS256', kid: 'test-kid' })
      .setIssuer(GITHUB_OIDC)
      .setAudience('id.org.ai')
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey)
    // The body cannot fill in what the token lacks.
    const res = await postClaim(token, { claimToken, githubUserId: '501', repo: 'alice/app', branch: 'main' })
    expect(res.status).toBe(401)
    expect((await stored(claimToken)).claimStatus).toBe('unclaimed')
  })

  it('refuses a run started by an event an outsider can trigger (event_name)', async () => {
    const { claimToken } = await provision()
    for (const event_name of ['pull_request_target', 'workflow_run', 'issue_comment']) {
      const res = await postClaim(await oidcToken(OWNER_REPO, MALLORY, 'refs/heads/main', { event_name }), { claimToken })
      expect(res.status, event_name).toBe(403)
    }
    expect((await stored(claimToken)).claimStatus).toBe('unclaimed')
  })
})

describe('POST /api/claim/bind (bind before publishing)', () => {
  // The remaining H1 window: the token is public before the owner's first
  // claim runs (a feature-branch push, --no-push, Actions disabled, a race).
  // An attacker who claims FIRST from their own repo must lose.
  it('refuses an attacker who claims first once the owner bound the repository', async () => {
    const { claimToken, sessionToken } = await provision()
    const bound = await bind(sessionToken, { repo: 'alice/app' })
    expect(bound.status).toBe(200)
    expect(await bound.json()).toMatchObject({ success: true, repo: 'alice/app' })

    const attack = await postClaim(await oidcToken(ATTACKER_REPO, MALLORY, 'refs/heads/main'), { claimToken, repo: 'alice/app' })
    expect(attack.status).toBe(400)
    expect(((await attack.json()) as { error: string }).error).toContain('bound to another repository')
    expect((await stored(claimToken)).claimStatus).toBe('unclaimed')

    const owner = await postClaim(await oidcToken(OWNER_REPO, ALICE, 'refs/heads/main'), { claimToken })
    expect(owner.status).toBe(200)
    const record = await stored(claimToken)
    expect(record.claimStatus).toBe('claimed')
    expect(record.githubUserId).toBe('501')
  })

  it('finalises on the default branch named at bind time (OIDC carries none)', async () => {
    const { claimToken, sessionToken } = await provision()
    expect((await bind(sessionToken, { repo: 'alice/app', defaultBranch: 'trunk' })).status).toBe(200)
    await postClaim(await oidcToken(OWNER_REPO, ALICE, 'refs/heads/main'), { claimToken })
    expect((await stored(claimToken)).claimStatus).toBe('pending')
    await postClaim(await oidcToken(OWNER_REPO, ALICE, 'refs/heads/trunk'), { claimToken })
    expect((await stored(claimToken)).claimStatus).toBe('claimed')
  })

  it('requires the tenant\'s own valid session token', async () => {
    const { claimToken } = await provision()
    expect((await bind(null, { repo: 'alice/app' })).status).toBe(401)
    expect((await bind('ses_not_a_real_session', { repo: 'alice/app' })).status).toBe(401)
    // The claim token is public; it is not a credential for binding.
    expect((await bind(claimToken, { repo: 'mallory/fork' })).status).toBe(401)
  })

  it('refuses a malformed repo, and a different repo once a claim has used the token', async () => {
    const { claimToken, sessionToken } = await provision()
    expect((await bind(sessionToken, {})).status).toBe(400)
    expect((await bind(sessionToken, { repo: 'https://github.com/alice/app' })).status).toBe(400)
    await postClaim(await oidcToken(OWNER_REPO, ALICE, 'refs/heads/feature/x'), { claimToken })
    expect((await bind(sessionToken, { repo: 'alice/other' })).status).toBe(409)
    expect((await bind(sessionToken, { repo: 'alice/app' })).status).toBe(200)
  })

  // Legacy path, pinned so it is a visible decision rather than an accident:
  // a token nobody bound is bound by whoever claims first. `id.org.ai claim`
  // always binds first; the /claim/:token page and older clients do not.
  it('legacy: without a binding, the first claim wins, even an attacker\'s', async () => {
    const { claimToken } = await provision()
    const attack = await postClaim(await oidcToken(ATTACKER_REPO, MALLORY, 'refs/heads/main'), { claimToken })
    expect(attack.status).toBe(200)
    expect((await stored(claimToken)).githubUserId).toBe('666')
  })
})
