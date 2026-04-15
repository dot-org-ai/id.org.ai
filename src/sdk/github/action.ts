/**
 * GitHub Action Claim Verification
 *
 * When the dot-org-ai/id@v1 action runs in a user's CI:
 *   1. Requests a GitHub Actions OIDC token for authentication
 *   2. Calls id.org.ai/api/claim to confirm the claim
 *   3. Writes tenant config to .headless.ly/tenant.json
 *   4. Optionally syncs agent public keys from .headless.ly/agents/*.pub
 */

const CLAIM_API = 'https://id.org.ai/api/claim'
const OIDC_AUDIENCE = 'id.org.ai'
const MAX_RETRIES = 3
const RETRY_DELAY_MS = 1000

export interface ActionInput {
  tenant: string // Claim token (clm_*)
  oidcToken: string // GitHub Actions OIDC token
  repo: string // owner/repo
  branch: string // Current branch
  actor: string // GitHub username who triggered the action
  actorId: string // GitHub user ID
}

export interface ActionOutput {
  success: boolean
  tenantId?: string
  level?: number
  claimed?: boolean
  error?: string
}

/**
 * Request an OIDC token from GitHub's OIDC provider.
 *
 * GitHub Actions provides OIDC tokens when the workflow has
 * `permissions: { id-token: write }`. The token is requested
 * via the ACTIONS_ID_TOKEN_REQUEST_URL endpoint with the
 * ACTIONS_ID_TOKEN_REQUEST_TOKEN as Bearer auth.
 *
 * @param audience - The audience claim for the OIDC token (default: id.org.ai)
 */
export async function requestOIDCToken(audience: string = OIDC_AUDIENCE): Promise<string> {
  const tokenUrl = process.env.ACTIONS_ID_TOKEN_REQUEST_URL
  const requestToken = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN

  if (!tokenUrl || !requestToken) {
    throw new Error(
      'OIDC token not available. Ensure your workflow has `permissions: { id-token: write }` ' +
      'and this action is running in a GitHub Actions environment.',
    )
  }

  // GitHub OIDC endpoint expects audience as a query parameter
  const url = new URL(tokenUrl)
  url.searchParams.set('audience', audience)

  const res = await fetch(url.toString(), {
    headers: {
      Authorization: `Bearer ${requestToken}`,
      Accept: 'application/json',
    },
  })

  if (!res.ok) {
    const body = await res.text()
    throw new Error(`OIDC token request failed (${res.status}): ${body}`)
  }

  const data = await res.json() as { value: string }
  if (!data.value) {
    throw new Error('OIDC token response missing value field')
  }

  return data.value
}

/**
 * Verify a claim from a GitHub Action with retry logic.
 *
 * Makes a POST to id.org.ai/api/claim with the OIDC token for
 * authentication and the claim token + GitHub identity info.
 * Retries transient failures up to MAX_RETRIES times.
 */
export async function verifyClaimFromAction(input: ActionInput): Promise<ActionOutput> {
  let lastError: string | undefined

  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      const response = await fetch(CLAIM_API, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${input.oidcToken}`,
        },
        body: JSON.stringify({
          claimToken: input.tenant,
          githubUserId: input.actorId,
          githubUsername: input.actor,
          repo: input.repo,
          branch: input.branch,
        }),
      })

      // Non-retryable errors: client errors (4xx except 429)
      if (response.status >= 400 && response.status < 500 && response.status !== 429) {
        const error = await response.json() as { error: string }
        return { success: false, error: error.error }
      }

      // Retryable: 429 or 5xx
      if (!response.ok) {
        lastError = `HTTP ${response.status}`
        if (attempt < MAX_RETRIES) {
          await sleep(RETRY_DELAY_MS * attempt)
          continue
        }
        return { success: false, error: `claim_failed_after_retries: ${lastError}` }
      }

      const result = await response.json() as {
        success: boolean
        identity?: { id: string; level: number }
        error?: string
      }

      if (!result.success) {
        return { success: false, error: result.error }
      }

      return {
        success: true,
        tenantId: result.identity?.id,
        level: result.identity?.level,
        claimed: true,
      }
    } catch (err: any) {
      lastError = err.message
      if (attempt < MAX_RETRIES) {
        await sleep(RETRY_DELAY_MS * attempt)
        continue
      }
    }
  }

  return { success: false, error: `claim_failed_after_retries: ${lastError}` }
}

/**
 * Format an output value for GitHub Actions.
 *
 * Writes to $GITHUB_OUTPUT file using the `key=value` format.
 * Falls back to deprecated `::set-output` if $GITHUB_OUTPUT is not set.
 */
export function setOutput(name: string, value: string): void {
  const outputFile = process.env.GITHUB_OUTPUT
  if (outputFile) {
    // Modern approach: write to $GITHUB_OUTPUT file
    const fs = require('fs') as typeof import('fs')
    fs.appendFileSync(outputFile, `${name}=${value}\n`)
  } else {
    // Fallback for older runners
    console.log(`::set-output name=${name}::${value}`)
  }
}

/**
 * Emit a GitHub Actions error annotation.
 */
export function setError(message: string): void {
  console.log(`::error::${message}`)
}

/**
 * Emit a GitHub Actions warning annotation.
 */
export function setWarning(message: string): void {
  console.log(`::warning::${message}`)
}

/**
 * Emit a GitHub Actions notice annotation.
 */
export function setNotice(message: string): void {
  console.log(`::notice::${message}`)
}

/**
 * Write the tenant configuration file to .headless.ly/tenant.json.
 *
 * This file is used by downstream steps and local tooling to
 * know which tenant this repository is linked to.
 */
export async function writeTenantConfig(output: ActionOutput): Promise<void> {
  const fs = require('fs') as typeof import('fs')
  const path = require('path') as typeof import('path')

  const workspace = process.env.GITHUB_WORKSPACE ?? process.cwd()
  const configDir = path.join(workspace, '.headless.ly')
  const configFile = path.join(configDir, 'tenant.json')

  // Ensure directory exists
  if (!fs.existsSync(configDir)) {
    fs.mkdirSync(configDir, { recursive: true })
  }

  const config = {
    tenantId: output.tenantId,
    level: output.level,
    claimed: output.claimed,
    claimedAt: new Date().toISOString(),
    repo: process.env.GITHUB_REPOSITORY,
    actor: process.env.GITHUB_ACTOR,
  }

  fs.writeFileSync(configFile, JSON.stringify(config, null, 2) + '\n')
}

// ============================================================================
// Utilities
// ============================================================================

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}
