/**
 * GitHub App Webhook Handler
 *
 * Listens for push events and scans for:
 *   .github/workflows/headlessly.yml
 *
 * When found, extracts the claim token from `with.tenant` and
 * calls IdentityDO.claim() to link the GitHub user to the anonymous tenant.
 *
 * The commit IS the identity — GitHub authenticates who pushed.
 */

export interface PushEvent {
  ref: string
  repository: {
    full_name: string
    default_branch: string
  }
  sender: {
    id: number
    login: string
    email?: string
  }
  commits: Array<{
    id: string
    added: string[]
    modified: string[]
    message: string
  }>
}

export class GitHubApp {
  constructor(
    private webhookSecret: string,
  ) {}

  /**
   * Handle a GitHub push webhook
   */
  async handlePush(event: PushEvent): Promise<{
    claimed: boolean
    claimToken?: string
    branch?: string
    error?: string
  }> {
    // Check if any commit added/modified the headlessly workflow
    const workflowFile = '.github/workflows/headlessly.yml'
    const touchedWorkflow = event.commits.some(
      (c) => c.added.includes(workflowFile) || c.modified.includes(workflowFile),
    )

    if (!touchedWorkflow) {
      return { claimed: false }
    }

    // Extract branch name from ref
    const branch = event.ref.replace('refs/heads/', '')

    // TODO: Fetch the workflow file content from GitHub API
    // Extract the claim token from `with.tenant` field
    // Call IdentityDO.claim() with the GitHub user identity

    return {
      claimed: true,
      branch,
    }
  }

  /**
   * Verify GitHub webhook signature (HMAC-SHA256)
   */
  async verifySignature(payload: string, signature: string): Promise<boolean> {
    const encoder = new TextEncoder()
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(this.webhookSecret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign'],
    )
    const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(payload))
    const expected = `sha256=${Array.from(new Uint8Array(sig), (b) => b.toString(16).padStart(2, '0')).join('')}`
    return signature === expected
  }
}
