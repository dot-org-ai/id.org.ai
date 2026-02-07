/**
 * GitHub Action Claim Verification
 *
 * When the dot-org-ai/id@v1 action runs in a user's CI:
 *   1. Uses the GitHub Actions OIDC token for authentication
 *   2. Calls id.org.ai/api/claim to confirm the claim
 *   3. Writes tenant config to .headless.ly/tenant.json
 *   4. Optionally syncs agent public keys from .headless.ly/agents/*.pub
 */

export interface ActionInput {
  tenant: string  // Claim token (clm_*)
  oidcToken: string  // GitHub Actions OIDC token
  repo: string  // owner/repo
  branch: string  // Current branch
  actor: string  // GitHub username who triggered the action
  actorId: string  // GitHub user ID
}

export async function verifyClaimFromAction(input: ActionInput): Promise<{
  success: boolean
  tenantId?: string
  level?: number
  error?: string
}> {
  const response = await fetch('https://id.org.ai/api/claim', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${input.oidcToken}`,
    },
    body: JSON.stringify({
      claimToken: input.tenant,
      githubUserId: input.actorId,
      githubUsername: input.actor,
      repo: input.repo,
      branch: input.branch,
    }),
  })

  if (!response.ok) {
    const error = await response.json() as { error: string }
    return { success: false, error: error.error }
  }

  const result = await response.json() as { success: boolean; identity?: { id: string; level: number } }
  return {
    success: true,
    tenantId: result.identity?.id,
    level: result.identity?.level,
  }
}
