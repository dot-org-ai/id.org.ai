const DEFAULT_BASE_URL = 'https://id.org.ai'

export interface ProvisionResult {
  tenantId: string
  identityId: string
  sessionToken: string
  claimToken: string
  level: number
  limits: {
    maxEntities: number
    ttlHours: number
    maxRequestsPerMinute: number
  }
  upgrade: {
    nextLevel: number
    action: string
    description?: string
    url?: string
  }
}

export interface ClaimStatusResult {
  status: 'unclaimed' | 'pending' | 'claimed' | 'expired'
  level?: number
}

export async function provision(baseUrl = DEFAULT_BASE_URL): Promise<ProvisionResult> {
  const response = await fetch(`${baseUrl}/api/provision`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
  })

  if (!response.ok) {
    throw new Error(`Provision failed: ${response.status} ${response.statusText}`)
  }

  return response.json() as Promise<ProvisionResult>
}

export async function getClaimStatus(
  claimToken: string,
  baseUrl = DEFAULT_BASE_URL,
): Promise<ClaimStatusResult> {
  const response = await fetch(`${baseUrl}/api/claim/${claimToken}/status`)

  if (!response.ok) {
    return { status: 'unclaimed' }
  }

  return response.json() as Promise<ClaimStatusResult>
}

export interface BindClaimResult {
  /** HTTP status; 0 when the request itself failed (network). */
  status: number
  success: boolean
  repo?: string
  defaultBranch?: string | null
  error?: string
}

/**
 * Bind the tenant's claim token to the GitHub repository it will be claimed
 * from, before the token is committed (H1). Authenticated by the tenant's
 * session token, which is never committed, so only the owner can bind.
 * Never throws: the caller decides what each status means.
 */
export async function bindClaimRepository(
  sessionToken: string,
  repo: string,
  opts: { defaultBranch?: string; baseUrl?: string } = {},
): Promise<BindClaimResult> {
  try {
    const response = await fetch(`${opts.baseUrl ?? DEFAULT_BASE_URL}/api/claim/bind`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${sessionToken}` },
      body: JSON.stringify(opts.defaultBranch ? { repo, defaultBranch: opts.defaultBranch } : { repo }),
    })
    const body = (await response.json().catch(() => ({}))) as {
      success?: boolean
      repo?: string
      defaultBranch?: string | null
      error?: string
      error_description?: string
    }
    const error = body.error_description ?? body.error
    return { status: response.status, success: response.ok && body.success !== false, repo: body.repo, defaultBranch: body.defaultBranch, error }
  } catch (err) {
    return { status: 0, success: false, error: err instanceof Error ? err.message : String(err) }
  }
}
