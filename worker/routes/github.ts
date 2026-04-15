/**
 * GitHub webhook route module — handles GitHub App push events (claim-by-commit).
 * Extracted from worker/index.ts (Phase 10).
 */
import { Hono } from 'hono'
import type { Env, Variables } from '../types'
import { errorResponse, ErrorCode } from '../../src/sdk/errors'
import { GitHubApp } from '../../src/sdk/github/app'
import type { PushEvent } from '../../src/sdk/github/app'
import { getStubForIdentity, resolveIdentityFromClaim } from '../middleware/tenant'
import { updateWorkOSUser } from '../../src/sdk/workos/upstream'
import { AUDIT_EVENTS } from '../../src/sdk/audit'
import { logAuditEvent } from '../utils/audit'

const app = new Hono<{ Bindings: Env; Variables: Variables }>()

// ── GitHub webhook endpoint ───────────────────────────────────────────────

app.post('/webhook/github', async (c) => {
  const signature = c.req.header('x-hub-signature-256')
  const event = c.req.header('x-github-event')
  const deliveryId = c.req.header('x-github-delivery')
  const body = await c.req.text()

  // Validate required environment variables
  if (!c.env.GITHUB_WEBHOOK_SECRET || !c.env.GITHUB_APP_ID || !c.env.GITHUB_APP_PRIVATE_KEY) {
    return errorResponse(c, 503, ErrorCode.ServiceUnavailable, 'GitHub App is not configured')
  }

  const githubApp = new GitHubApp({
    webhookSecret: c.env.GITHUB_WEBHOOK_SECRET,
    appId: c.env.GITHUB_APP_ID,
    privateKey: c.env.GITHUB_APP_PRIVATE_KEY,
  })

  // Verify webhook signature
  if (!(await githubApp.verifySignature(body, signature ?? ''))) {
    return errorResponse(c, 401, ErrorCode.InvalidSignature, 'Webhook signature verification failed')
  }

  // Handle push events — the core claim-by-commit flow
  if (event === 'push') {
    const push = JSON.parse(body) as PushEvent

    // The GitHubApp.handlePush needs to fetch the workflow file from GitHub,
    // parse the claim token, then route to the correct DO shard.
    // We use a sharded stub resolver that wraps handlePush.
    const result = await handlePushWithSharding(githubApp, push, c.env)

    return c.json({
      event: 'push',
      delivery: deliveryId,
      ...result,
    })
  }

  // Handle installation events for logging/telemetry
  if (event === 'installation') {
    const payload = JSON.parse(body) as { action: string; installation: { id: number; account: { login: string } } }
    return c.json({
      received: true,
      event: 'installation',
      action: payload.action,
      account: payload.installation?.account?.login,
      delivery: deliveryId,
    })
  }

  // Handle installation_repositories events
  if (event === 'installation_repositories') {
    return c.json({
      received: true,
      event: 'installation_repositories',
      delivery: deliveryId,
    })
  }

  // Acknowledge all other events
  return c.json({
    received: true,
    event,
    delivery: deliveryId,
  })
})

// ============================================================================
// GitHub Push Sharding
// ============================================================================

/**
 * Handle a GitHub push webhook with identity sharding.
 *
 * The GitHubApp.handlePush method needs a DO stub, but the webhook doesn't
 * carry auth credentials — it carries a claim token embedded in the workflow
 * YAML. We resolve the claim token to an identity via KV, then pass the
 * correct shard's stub to handlePush.
 *
 * Flow:
 *   1. Check if any commit touches the headlessly workflow file
 *   2. If not, return early (no claim)
 *   3. Fetch the workflow file from GitHub
 *   4. Parse the claim token from the YAML
 *   5. Resolve identity ID from claim token via KV
 *   6. Get the correct DO stub for that identity
 *   7. Call the claim method on that specific DO via RPC
 */
async function handlePushWithSharding(
  githubApp: GitHubApp,
  push: PushEvent,
  env: Env,
): Promise<{
  claimed: boolean
  claimToken?: string
  tenantId?: string
  level?: number
  branch?: string
  error?: string
}> {
  // Check if any commit touches the headlessly workflow
  const WORKFLOW_PATH = '.github/workflows/headlessly.yml'
  const touchedWorkflow = push.commits.some((c) => c.added.includes(WORKFLOW_PATH) || c.modified.includes(WORKFLOW_PATH))

  if (!touchedWorkflow) {
    return { claimed: false }
  }

  const branch = push.ref.replace('refs/heads/', '')

  if (!push.installation?.id) {
    return { claimed: false, branch, error: 'missing_installation_id' }
  }

  // Fetch the workflow file to extract the claim token
  let yamlContent: string | null = null
  try {
    yamlContent = await githubApp.fetchWorkflowContent(push.repository.full_name, push.ref, push.installation.id)
  } catch (err: any) {
    return { claimed: false, branch, error: `fetch_workflow_failed: ${err.message}` }
  }

  if (!yamlContent) {
    return { claimed: false, branch, error: 'workflow_file_not_found' }
  }

  const claimToken = githubApp.parseClaimToken(yamlContent)
  if (!claimToken) {
    return { claimed: false, branch, error: 'no_claim_token_in_workflow' }
  }

  // Resolve the identity shard from the claim token
  const identityId = await resolveIdentityFromClaim(claimToken, env)
  if (!identityId) {
    return { claimed: false, claimToken, branch, error: 'unknown_claim_token' }
  }

  // Get the DO stub for this specific identity and execute the claim via RPC
  const stub = getStubForIdentity(env, identityId)

  try {
    const result = await stub.claim({
      claimToken,
      githubUserId: String(push.sender.id),
      githubUsername: push.sender.login,
      githubEmail: push.sender.email,
      repo: push.repository.full_name,
      branch,
    })

    if (!result.success) {
      // Audit: claim failed
      await logAuditEvent(stub, {
        event: AUDIT_EVENTS.CLAIM_FAILED,
        actor: push.sender.login,
        target: identityId,
        metadata: { claimToken, repo: push.repository.full_name, branch, error: result.error },
      })

      return { claimed: false, claimToken, branch, error: result.error ?? 'claim_failed' }
    }

    // Audit: claim completed
    await logAuditEvent(stub, {
      event: AUDIT_EVENTS.CLAIM_COMPLETED,
      actor: push.sender.login,
      target: result.identity?.id ?? identityId,
      metadata: {
        claimToken,
        repo: push.repository.full_name,
        branch,
        githubUserId: String(push.sender.id),
        level: result.identity?.level,
      },
    })

    // Persist GitHub ID to WorkOS as external_id (if identity has a WorkOS user ID)
    if (env.WORKOS_API_KEY && result.identity) {
      const stored = await stub.oauthStorageOp({ op: 'get', key: `identity:${identityId}` })
      const workosUserId = (stored.value as any)?.workosUserId
      if (workosUserId) {
        updateWorkOSUser(env.WORKOS_API_KEY, workosUserId, {
          external_id: String(push.sender.id),
          metadata: { github_id: String(push.sender.id), github_username: push.sender.login },
        }).catch(() => {}) // Best-effort, don't fail the claim
      }
    }

    return {
      claimed: true,
      claimToken,
      tenantId: result.identity?.id,
      level: result.identity?.level,
      branch,
    }
  } catch (err: any) {
    return { claimed: false, claimToken, branch, error: `claim_request_failed: ${err.message}` }
  }
}

export { app as githubRoutes }
