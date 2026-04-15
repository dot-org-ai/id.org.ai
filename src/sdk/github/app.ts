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
  installation?: {
    id: number
  }
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

export interface ClaimResult {
  claimed: boolean
  claimToken?: string
  tenantId?: string
  level?: number
  branch?: string
  error?: string
}

interface GitHubAppConfig {
  webhookSecret: string
  appId: string
  privateKey: string
}

const GITHUB_API = 'https://api.github.com'
const WORKFLOW_PATH = '.github/workflows/headlessly.yml'

export class GitHubApp {
  constructor(private config: GitHubAppConfig) {}

  /**
   * Verify GitHub webhook signature (HMAC-SHA256)
   *
   * GitHub sends the signature as `sha256=<hex>` in the
   * `x-hub-signature-256` header. We compute our own HMAC
   * over the raw body and compare in constant-time fashion
   * using byte-by-byte hex comparison.
   */
  async verifySignature(payload: string, signature: string): Promise<boolean> {
    if (!signature || !signature.startsWith('sha256=')) {
      return false
    }

    const encoder = new TextEncoder()
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(this.config.webhookSecret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign'],
    )
    const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(payload))
    const expected = `sha256=${Array.from(new Uint8Array(sig), (b) => b.toString(16).padStart(2, '0')).join('')}`

    // Constant-time comparison via matching length + every char
    if (expected.length !== signature.length) return false
    let mismatch = 0
    for (let i = 0; i < expected.length; i++) {
      mismatch |= expected.charCodeAt(i) ^ signature.charCodeAt(i)
    }
    return mismatch === 0
  }

  /**
   * Handle a GitHub push webhook.
   *
   * 1. Check if any commit added/modified .github/workflows/headlessly.yml
   * 2. Fetch the workflow file content via GitHub API (using app installation token)
   * 3. Parse YAML to extract `with.tenant: clm_xxx`
   * 4. Call IdentityDO's /api/claim endpoint with GitHub user info
   * 5. Return claim result
   */
  async handlePush(
    event: PushEvent,
    identityStub: { fetch(input: string | Request): Promise<Response> },
  ): Promise<ClaimResult> {
    // Check if any commit added/modified the headlessly workflow
    const touchedWorkflow = event.commits.some(
      (c) => c.added.includes(WORKFLOW_PATH) || c.modified.includes(WORKFLOW_PATH),
    )

    if (!touchedWorkflow) {
      return { claimed: false }
    }

    // Extract branch name from ref
    const branch = event.ref.replace('refs/heads/', '')

    // We need an installation ID to authenticate with the GitHub API
    if (!event.installation?.id) {
      return {
        claimed: false,
        branch,
        error: 'missing_installation_id',
      }
    }

    // Fetch the workflow file content from the repo
    const repo = event.repository.full_name
    const ref = event.ref
    let yamlContent: string | null = null

    try {
      yamlContent = await this.fetchWorkflowContent(repo, ref, event.installation.id)
    } catch (err: any) {
      return {
        claimed: false,
        branch,
        error: `fetch_workflow_failed: ${err.message}`,
      }
    }

    if (!yamlContent) {
      return {
        claimed: false,
        branch,
        error: 'workflow_file_not_found',
      }
    }

    // Parse the claim token from the workflow YAML
    const claimToken = this.parseClaimToken(yamlContent)
    if (!claimToken) {
      return {
        claimed: false,
        branch,
        error: 'no_claim_token_in_workflow',
      }
    }

    // Call IdentityDO's claim endpoint
    try {
      const res = await identityStub.fetch(
        new Request('https://id.org.ai/api/claim', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            claimToken,
            githubUserId: String(event.sender.id),
            githubUsername: event.sender.login,
            githubEmail: event.sender.email,
            repo,
            branch,
          }),
        }),
      )

      const result = await res.json() as {
        success: boolean
        identity?: { id: string; level: number }
        error?: string
      }

      if (!result.success) {
        return {
          claimed: false,
          claimToken,
          branch,
          error: result.error ?? 'claim_failed',
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
      return {
        claimed: false,
        claimToken,
        branch,
        error: `claim_request_failed: ${err.message}`,
      }
    }
  }

  /**
   * Fetch workflow file content from GitHub API using app installation token.
   *
   * Uses the Contents API: GET /repos/{owner}/{repo}/contents/{path}?ref={ref}
   * The response includes `content` as base64-encoded file contents.
   */
  async fetchWorkflowContent(repo: string, ref: string, installationId: number): Promise<string | null> {
    const token = await this.getInstallationToken(installationId)

    const url = `${GITHUB_API}/repos/${repo}/contents/${WORKFLOW_PATH}?ref=${ref}`
    const res = await fetch(url, {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/vnd.github.v3+json',
        'User-Agent': 'id.org.ai-github-app',
      },
    })

    if (!res.ok) {
      if (res.status === 404) return null
      const body = await res.text()
      throw new Error(`GitHub API error ${res.status}: ${body}`)
    }

    const data = await res.json() as {
      content?: string
      encoding?: string
    }

    if (!data.content) return null

    // GitHub returns base64-encoded content with newlines
    const cleaned = data.content.replace(/\n/g, '')
    return atob(cleaned)
  }

  /**
   * Generate a GitHub App JWT for API authentication (RS256).
   *
   * The JWT is used to authenticate as the GitHub App itself,
   * which can then request installation-specific access tokens.
   *
   * Claims:
   *   iss: GitHub App ID
   *   iat: current time - 60 (clock drift buffer)
   *   exp: current time + 600 (10 minutes max)
   */
  async generateAppJWT(): Promise<string> {
    const now = Math.floor(Date.now() / 1000)
    const payload = {
      iss: this.config.appId,
      iat: now - 60,
      exp: now + 600,
    }

    // Encode header
    const header = { alg: 'RS256', typ: 'JWT' }
    const encodedHeader = base64url(JSON.stringify(header))
    const encodedPayload = base64url(JSON.stringify(payload))
    const signingInput = `${encodedHeader}.${encodedPayload}`

    // Import the RSA private key
    const key = await importPKCS8Key(this.config.privateKey)

    // Sign
    const encoder = new TextEncoder()
    const signature = await crypto.subtle.sign(
      { name: 'RSASSA-PKCS1-v1_5' },
      key,
      encoder.encode(signingInput),
    )

    const encodedSignature = base64urlFromBuffer(signature)
    return `${signingInput}.${encodedSignature}`
  }

  /**
   * Get an installation access token for a specific GitHub App installation.
   *
   * POST /app/installations/{installation_id}/access_tokens
   * Authenticated with the App JWT.
   */
  async getInstallationToken(installationId: number): Promise<string> {
    const jwt = await this.generateAppJWT()

    const res = await fetch(`${GITHUB_API}/app/installations/${installationId}/access_tokens`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${jwt}`,
        Accept: 'application/vnd.github.v3+json',
        'User-Agent': 'id.org.ai-github-app',
      },
    })

    if (!res.ok) {
      const body = await res.text()
      throw new Error(`Failed to get installation token (${res.status}): ${body}`)
    }

    const data = await res.json() as { token: string }
    return data.token
  }

  /**
   * Parse the workflow YAML to extract the claim token from `with.tenant`.
   *
   * Expected workflow structure:
   *   steps:
   *     - uses: dot-org-ai/id@v1
   *       with:
   *         tenant: clm_abc123
   *
   * We use simple string matching rather than a full YAML parser
   * since the workflow file has a known structure. Looks for patterns:
   *   tenant: clm_...
   *   tenant: 'clm_...'
   *   tenant: "clm_..."
   *   claim-token: clm_... (legacy format from buildClaimWorkflow)
   */
  parseClaimToken(yamlContent: string): string | null {
    // Match `tenant:` or `claim-token:` followed by the clm_ token value
    // Handles optional quoting (none, single, double)
    const patterns = [
      /tenant:\s*['"]?(clm_[a-zA-Z0-9]+)['"]?/,
      /claim-token:\s*['"]?(clm_[a-zA-Z0-9]+)['"]?/,
    ]

    for (const pattern of patterns) {
      const match = yamlContent.match(pattern)
      if (match?.[1]) {
        return match[1]
      }
    }

    return null
  }
}

// ============================================================================
// Crypto Utilities
// ============================================================================

/**
 * Base64url encode a UTF-8 string (no padding).
 */
function base64url(str: string): string {
  const encoded = btoa(str)
  return encoded.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/**
 * Base64url encode an ArrayBuffer (no padding).
 */
function base64urlFromBuffer(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer)
  let binary = ''
  for (const byte of bytes) {
    binary += String.fromCharCode(byte)
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/**
 * Import a PEM-encoded PKCS#8 RSA private key for use with Web Crypto.
 *
 * Strips PEM headers/footers and decodes the base64 DER content.
 * The key is imported for RSASSA-PKCS1-v1_5 with SHA-256 (RS256).
 */
async function importPKCS8Key(pem: string): Promise<CryptoKey> {
  // Strip PEM headers and whitespace
  const pemBody = pem
    .replace(/-----BEGIN PRIVATE KEY-----/, '')
    .replace(/-----END PRIVATE KEY-----/, '')
    .replace(/-----BEGIN RSA PRIVATE KEY-----/, '')
    .replace(/-----END RSA PRIVATE KEY-----/, '')
    .replace(/\s/g, '')

  // Decode base64 to binary
  const binaryStr = atob(pemBody)
  const bytes = new Uint8Array(binaryStr.length)
  for (let i = 0; i < binaryStr.length; i++) {
    bytes[i] = binaryStr.charCodeAt(i)
  }

  return crypto.subtle.importKey(
    'pkcs8',
    bytes.buffer,
    {
      name: 'RSASSA-PKCS1-v1_5',
      hash: 'SHA-256',
    },
    false,
    ['sign'],
  )
}
