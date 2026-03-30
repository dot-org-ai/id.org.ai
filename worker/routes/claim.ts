/**
 * Claim route module — provision, claim status, claim OIDC, freeze
 * Extracted from worker/index.ts (Phase 8).
 */
import { Hono } from 'hono'
import * as jose from 'jose'
import type { Env, Variables } from '../types'
import { errorResponse, ErrorCode } from '../../src/errors'
import { getStubForIdentity, resolveIdentityFromClaim } from '../middleware/tenant'
import { ClaimService } from '../../src/claim/provision'
import { verifyClaim } from '../../src/claim/verify'
import { buildClaimWorkflow } from '../../src/claim/workflow'
import { AUDIT_EVENTS } from '../../src/audit'
import { logAuditEvent } from '../utils/audit'

const app = new Hono<{ Bindings: Env; Variables: Variables }>()

// ── Provision Endpoint ────────────────────────────────────────────────────
// Auto-provisions an anonymous tenant. No auth required.
// Creates a NEW identity with its own Durable Object instance (shard).
// Writes token → identityId mappings to KV for future request routing.

app.post('/api/provision', async (c) => {
  // Generate a new identity ID to use as the shard key.
  // We pass this to the DO so the identity ID matches the shard key.
  const shardKey = crypto.randomUUID()
  const stub = getStubForIdentity(c.env, shardKey)

  try {
    const data = await stub.provisionAnonymous(shardKey)

    // Build the provision result
    const result = {
      tenantId: data.identity.name,
      identityId: data.identity.id,
      sessionToken: data.sessionToken,
      claimToken: data.claimToken,
      level: 1 as const,
      limits: {
        maxEntities: 1000,
        ttlHours: 24,
        maxRequestsPerMinute: 100,
      },
      upgrade: {
        nextLevel: 2 as const,
        action: 'claim' as const,
        description: 'Commit a GitHub Action workflow to claim this tenant',
        url: `https://id.org.ai/claim/${data.claimToken}`,
      },
    }

    // Write KV mappings so future requests can route to this shard.
    // Session token → identityId (24h TTL matches session TTL)
    await c.env.SESSIONS.put(`session:${data.sessionToken}`, data.identity.id, { expirationTtl: 86400 })
    // Claim token → identityId (30 days — claim window)
    await c.env.SESSIONS.put(`claim:${data.claimToken}`, data.identity.id, { expirationTtl: 2592000 })

    // Audit: identity provisioned
    await logAuditEvent(stub, {
      event: AUDIT_EVENTS.IDENTITY_CREATED,
      actor: 'anonymous',
      target: data.identity.id,
      ip: c.req.raw.headers.get('cf-connecting-ip') ?? undefined,
      userAgent: c.req.raw.headers.get('user-agent') ?? undefined,
      metadata: { tenantName: data.identity.name, level: 1 },
    })

    return c.json(result, 201)
  } catch (err: any) {
    return errorResponse(c, 500, ErrorCode.ProvisionFailed, err.message)
  }
})

// ── Claim Status Endpoint ─────────────────────────────────────────────────

app.get('/api/claim/:token', async (c) => {
  const token = c.req.param('token')

  // Resolve shard from claim token via KV
  const identityId = await resolveIdentityFromClaim(token, c.env)
  if (!identityId) {
    return errorResponse(c, 404, ErrorCode.InvalidClaimToken, 'Unknown or expired claim token')
  }
  const stub = getStubForIdentity(c.env, identityId)

  try {
    const status = await verifyClaim(token, stub)
    return c.json(status, status.valid ? 200 : 404)
  } catch (err: any) {
    return errorResponse(c, 500, ErrorCode.VerificationFailed, err.message)
  }
})

// ── Claim Status Polling Endpoint ─────────────────────────────────────────
// Lightweight endpoint for CLI polling. Returns only status + level.

app.get('/api/claim/:token/status', async (c) => {
  const token = c.req.param('token')

  if (!token || !token.startsWith('clm_')) {
    return c.json({ status: 'unclaimed' }, 404)
  }

  // Resolve identity ID from claim token KV
  const identityId = await resolveIdentityFromClaim(token, c.env)
  if (!identityId) {
    return c.json({ status: 'expired' })
  }

  // Get the identity DO stub and verify claim status
  const stub = getStubForIdentity(c.env, identityId)

  try {
    const result = await verifyClaim(token, stub)

    if (!result.valid) {
      return c.json({ status: 'unclaimed' })
    }

    return c.json({
      status: result.status || 'unclaimed',
      level: result.level,
    })
  } catch (err: any) {
    return errorResponse(c, 500, ErrorCode.VerificationFailed, err.message)
  }
})

// ── Claim Endpoint (GitHub Action OIDC) ──────────────────────────────────
// Called by the dot-org-ai/id@v1 GitHub Action to complete a claim-by-commit.
// Authenticates via GitHub Actions OIDC token (Bearer), verifies the token
// against GitHub's JWKS, then executes the claim on the IdentityDO.

const GITHUB_OIDC_ISSUER = 'https://token.actions.githubusercontent.com'
let _githubJwks: jose.JWTVerifyGetKey | null = null
let _githubJwksFetchedAt = 0

async function getGitHubOIDCKeys(): Promise<jose.JWTVerifyGetKey> {
  if (_githubJwks && Date.now() - _githubJwksFetchedAt < 10 * 60 * 1000) return _githubJwks
  const jwksUrl = `${GITHUB_OIDC_ISSUER}/.well-known/jwks`
  const keys = await fetch(jwksUrl).then((r) => r.json() as Promise<{ keys: jose.JWK[] }>)
  _githubJwks = jose.createLocalJWKSet(keys as jose.JSONWebKeySet)
  _githubJwksFetchedAt = Date.now()
  return _githubJwks
}

app.post('/api/claim', async (c) => {
  // Verify GitHub Actions OIDC token
  const authHeader = c.req.header('authorization')
  if (!authHeader?.startsWith('Bearer ')) {
    return errorResponse(c, 401, ErrorCode.Unauthorized, 'Missing OIDC bearer token')
  }

  const oidcToken = authHeader.slice(7)
  let oidcPayload: jose.JWTPayload

  try {
    const jwks = await getGitHubOIDCKeys()
    const { payload } = await jose.jwtVerify(oidcToken, jwks, {
      issuer: GITHUB_OIDC_ISSUER,
      audience: 'id.org.ai',
    })
    oidcPayload = payload
  } catch (err: any) {
    return errorResponse(c, 401, ErrorCode.Unauthorized, `OIDC token verification failed: ${err.message}`)
  }

  // Parse request body
  const body = (await c.req.json().catch(() => ({}))) as {
    claimToken?: string
    githubUserId?: string
    githubUsername?: string
    repo?: string
    branch?: string
  }

  const claimToken = body.claimToken
  if (!claimToken?.startsWith('clm_')) {
    return errorResponse(c, 400, ErrorCode.InvalidRequest, 'Missing or invalid claimToken')
  }

  // Resolve identity from claim token
  const identityId = await resolveIdentityFromClaim(claimToken, c.env)
  if (!identityId) {
    return errorResponse(c, 404, ErrorCode.InvalidClaimToken, 'Unknown or expired claim token')
  }

  const stub = getStubForIdentity(c.env, identityId)

  // Extract GitHub identity from OIDC token claims or request body
  const githubUserId = body.githubUserId || (oidcPayload.actor_id as string) || ''
  const githubUsername = body.githubUsername || (oidcPayload.actor as string) || ''
  const repo = body.repo || (oidcPayload.repository as string) || ''
  const branch = body.branch || (oidcPayload.ref as string)?.replace('refs/heads/', '') || ''

  try {
    const result = await stub.claim({
      claimToken,
      githubUserId,
      githubUsername,
      repo,
      branch,
    })

    if (!result.success) {
      await logAuditEvent(stub, {
        event: AUDIT_EVENTS.CLAIM_FAILED,
        actor: githubUsername,
        target: identityId,
        metadata: { claimToken, repo, branch, error: result.error },
      })
      return c.json({ success: false, error: result.error ?? 'claim_failed' }, 400)
    }

    await logAuditEvent(stub, {
      event: AUDIT_EVENTS.CLAIM_COMPLETED,
      actor: githubUsername,
      target: result.identity?.id ?? identityId,
      metadata: { claimToken, repo, branch, githubUserId, level: result.identity?.level },
    })

    return c.json({
      success: true,
      identity: result.identity,
    })
  } catch (err: any) {
    return errorResponse(c, 500, ErrorCode.ServerError, err.message)
  }
})

// ── Freeze Endpoint ───────────────────────────────────────────────────────
// Requires L1+ auth. Freezes the caller's own tenant.

app.post('/api/freeze', async (c) => {
  const auth = c.get('auth')
  if (!auth.authenticated || !auth.identityId) {
    return errorResponse(c, 401, ErrorCode.Unauthorized, 'Session token required to freeze a tenant')
  }

  // Stub is already set by middleware for authenticated requests
  const stub = c.get('identityStub')
  if (!stub) {
    return errorResponse(c, 500, ErrorCode.ServerError, 'Identity stub not resolved')
  }
  const claimService = new ClaimService(stub)

  try {
    const result = await claimService.freeze(auth.identityId)

    // Audit: identity frozen
    await logAuditEvent(stub, {
      event: AUDIT_EVENTS.IDENTITY_FROZEN,
      actor: auth.identityId,
      target: auth.identityId,
      ip: c.req.raw.headers.get('cf-connecting-ip') ?? undefined,
      userAgent: c.req.raw.headers.get('user-agent') ?? undefined,
      metadata: { stats: result.stats },
    })

    return c.json(result)
  } catch (err: any) {
    return errorResponse(c, 500, ErrorCode.FreezeFailed, err.message)
  }
})

// ── Claim page (human-facing) ─────────────────────────────────────────────

app.get('/claim/:token', async (c) => {
  const token = c.req.param('token')

  // Resolve shard from claim token via KV
  const identityId = await resolveIdentityFromClaim(token, c.env)
  if (!identityId) {
    return errorResponse(c, 404, ErrorCode.InvalidClaimToken, 'This claim token is invalid or has expired.')
  }
  const stub = getStubForIdentity(c.env, identityId)
  const status = await verifyClaim(token, stub)

  if (!status.valid) {
    return errorResponse(c, 404, ErrorCode.InvalidClaimToken, 'This claim token is invalid or has expired.')
  }

  // Return claim info for the human-facing claim page
  return c.json({
    claimToken: token,
    status: status.status,
    stats: status.stats,
    instructions: {
      step1: 'Add this GitHub Action workflow to your repository:',
      file: '.github/workflows/headlessly.yml',
      content: buildClaimWorkflow(token),
      step2: 'Push to your main branch',
      step3: 'The push event will link your GitHub identity to this tenant',
    },
  })
})

export { app as claimRoutes }
