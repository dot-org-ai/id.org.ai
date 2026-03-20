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
