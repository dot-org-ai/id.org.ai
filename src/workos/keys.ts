/**
 * WorkOS API Key Management
 *
 * CRUD operations for WorkOS-managed API keys.
 * WorkOS handles key generation, validation, and rotation.
 *
 * These functions are standalone helpers (not tied to a class) so they
 * can be called from the Hono routes in worker/index.ts without needing
 * to instantiate a WorkerEntrypoint.
 */

// ============================================================================
// Types
// ============================================================================

export interface CreateKeyOptions {
  name: string
  organizationId?: string
  permissions?: string[]
  expiresAt?: string
}

export interface WorkOSApiKey {
  id: string
  key?: string // Only returned on creation
  name: string
  organization_id?: string
  permissions?: string[]
  created_at: string
  last_used_at?: string
}

// ============================================================================
// Create
// ============================================================================

/**
 * Create a new API key via WorkOS.
 *
 * @param workosApiKey - The platform's WorkOS API key (Bearer token)
 * @param options - Key creation options (name, org, permissions, expiry)
 * @returns The created key (including the raw key string, only available at creation time)
 */
export async function createWorkOSApiKey(workosApiKey: string, options: CreateKeyOptions): Promise<WorkOSApiKey> {
  const body: Record<string, unknown> = { name: options.name }
  if (options.organizationId) body.organization_id = options.organizationId
  if (options.permissions) body.permissions = options.permissions
  if (options.expiresAt) body.expires_at = options.expiresAt

  const resp = await fetch('https://api.workos.com/api_keys', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${workosApiKey}`,
    },
    body: JSON.stringify(body),
  })

  if (!resp.ok) {
    const text = await resp.text()
    throw new Error(`WorkOS create API key failed: ${resp.status} ${text}`)
  }

  return resp.json() as Promise<WorkOSApiKey>
}

// ============================================================================
// List
// ============================================================================

/**
 * List API keys via WorkOS, optionally filtered by organization.
 *
 * @param workosApiKey - The platform's WorkOS API key (Bearer token)
 * @param organizationId - Optional organization filter
 * @returns Array of API key metadata (does not include raw key strings)
 */
export async function listWorkOSApiKeys(workosApiKey: string, organizationId?: string): Promise<WorkOSApiKey[]> {
  const url = new URL('https://api.workos.com/api_keys')
  if (organizationId) url.searchParams.set('organization_id', organizationId)
  url.searchParams.set('limit', '100')

  const resp = await fetch(url.toString(), {
    headers: { Authorization: `Bearer ${workosApiKey}` },
  })

  if (!resp.ok) {
    throw new Error(`WorkOS list API keys failed: ${resp.status}`)
  }

  const data = (await resp.json()) as { data: WorkOSApiKey[] }
  return data.data
}

// ============================================================================
// Revoke
// ============================================================================

/**
 * Revoke (delete) an API key via WorkOS.
 *
 * @param workosApiKey - The platform's WorkOS API key (Bearer token)
 * @param keyId - The WorkOS key ID to revoke
 * @returns true if the key was revoked (or already didn't exist)
 */
export async function revokeWorkOSApiKey(workosApiKey: string, keyId: string): Promise<boolean> {
  const resp = await fetch(`https://api.workos.com/api_keys/${keyId}`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${workosApiKey}` },
  })

  return resp.ok || resp.status === 404
}
