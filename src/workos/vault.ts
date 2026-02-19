/**
 * WorkOS Vault — Encrypted Secret Storage
 *
 * CRUD operations for WorkOS Vault secrets + runtime secret resolution.
 * Secrets are scoped per WorkOS environment (production/staging/development).
 *
 * Use cases:
 * - Code Functions: `$.vault.get('SECRET_NAME')`
 * - Workflows: `{{vault:SECRET_NAME}}` in step configs
 * - Integration configs: connection credentials
 * - API proxy headers: upstream auth tokens
 *
 * These functions are standalone helpers (not tied to a class) so they
 * can be called from the Hono routes in worker/index.ts without needing
 * to instantiate a WorkerEntrypoint.
 */

const VAULT_BASE = 'https://api.workos.com/vault/v1'

// ============================================================================
// Types
// ============================================================================

export interface VaultSecret {
  id: string
  name: string
  description?: string
  environment: 'production' | 'staging' | 'development'
  created_at: string
  updated_at: string
}

export interface VaultSecretWithValue extends VaultSecret {
  value: string
}

export interface CreateSecretOptions {
  name: string
  value: string
  description?: string
  environment?: 'production' | 'staging' | 'development'
}

export interface UpdateSecretOptions {
  value?: string
  description?: string
}

// ============================================================================
// CRUD Operations
// ============================================================================

/**
 * Create a secret in WorkOS Vault.
 * Secrets are scoped to the WorkOS environment (production/staging).
 *
 * @param apiKey - The platform's WorkOS API key (Bearer token)
 * @param options - Secret creation options (name, value, description, environment)
 * @returns The created secret metadata (value is NOT returned)
 */
export async function createVaultSecret(apiKey: string, options: CreateSecretOptions): Promise<VaultSecret> {
  const resp = await fetch(`${VAULT_BASE}/secrets`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      name: options.name,
      value: options.value,
      description: options.description,
      environment: options.environment || 'production',
    }),
  })
  if (!resp.ok) {
    const body = await resp.text()
    throw new Error(`Vault createSecret failed: ${resp.status} ${body}`)
  }
  return resp.json() as Promise<VaultSecret>
}

/**
 * Get a secret's metadata (without value) by ID.
 *
 * @param apiKey - The platform's WorkOS API key (Bearer token)
 * @param secretId - The WorkOS secret ID
 * @returns Secret metadata (no decrypted value)
 */
export async function getVaultSecret(apiKey: string, secretId: string): Promise<VaultSecret> {
  const resp = await fetch(`${VAULT_BASE}/secrets/${secretId}`, {
    headers: { Authorization: `Bearer ${apiKey}` },
  })
  if (!resp.ok) {
    const body = await resp.text()
    throw new Error(`Vault getSecret failed: ${resp.status} ${body}`)
  }
  return resp.json() as Promise<VaultSecret>
}

/**
 * Read a secret's decrypted value. Use sparingly — audit-logged by WorkOS.
 *
 * @param apiKey - The platform's WorkOS API key (Bearer token)
 * @param secretId - The WorkOS secret ID
 * @returns Secret metadata with decrypted value
 */
export async function readVaultSecretValue(apiKey: string, secretId: string): Promise<VaultSecretWithValue> {
  const resp = await fetch(`${VAULT_BASE}/secrets/${secretId}/reveal`, {
    headers: { Authorization: `Bearer ${apiKey}` },
  })
  if (!resp.ok) {
    const body = await resp.text()
    throw new Error(`Vault readSecretValue failed: ${resp.status} ${body}`)
  }
  return resp.json() as Promise<VaultSecretWithValue>
}

/**
 * List all secrets (metadata only, no values).
 *
 * @param apiKey - The platform's WorkOS API key (Bearer token)
 * @param options - Optional filters (environment, pagination)
 * @returns Paginated list of secret metadata
 */
export async function listVaultSecrets(
  apiKey: string,
  options?: { environment?: string; limit?: number; after?: string },
): Promise<{ data: VaultSecret[]; list_metadata: { after?: string } }> {
  const params = new URLSearchParams()
  if (options?.environment) params.set('environment', options.environment)
  if (options?.limit) params.set('limit', String(options.limit))
  if (options?.after) params.set('after', options.after)

  const url = `${VAULT_BASE}/secrets${params.toString() ? '?' + params.toString() : ''}`
  const resp = await fetch(url, {
    headers: { Authorization: `Bearer ${apiKey}` },
  })
  if (!resp.ok) {
    const body = await resp.text()
    throw new Error(`Vault listSecrets failed: ${resp.status} ${body}`)
  }
  return resp.json() as Promise<{ data: VaultSecret[]; list_metadata: { after?: string } }>
}

/**
 * Update a secret's value and/or description.
 *
 * @param apiKey - The platform's WorkOS API key (Bearer token)
 * @param secretId - The WorkOS secret ID
 * @param updates - Fields to update (value, description)
 * @returns Updated secret metadata
 */
export async function updateVaultSecret(apiKey: string, secretId: string, updates: UpdateSecretOptions): Promise<VaultSecret> {
  const resp = await fetch(`${VAULT_BASE}/secrets/${secretId}`, {
    method: 'PUT',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(updates),
  })
  if (!resp.ok) {
    const body = await resp.text()
    throw new Error(`Vault updateSecret failed: ${resp.status} ${body}`)
  }
  return resp.json() as Promise<VaultSecret>
}

/**
 * Delete a secret permanently.
 *
 * @param apiKey - The platform's WorkOS API key (Bearer token)
 * @param secretId - The WorkOS secret ID to delete
 */
export async function deleteVaultSecret(apiKey: string, secretId: string): Promise<void> {
  const resp = await fetch(`${VAULT_BASE}/secrets/${secretId}`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${apiKey}` },
  })
  if (!resp.ok && resp.status !== 404) {
    const body = await resp.text()
    throw new Error(`Vault deleteSecret failed: ${resp.status} ${body}`)
  }
}

// ============================================================================
// Secret Resolution
// ============================================================================

/**
 * Resolve a secret by name. This is the main runtime API used by:
 * - Code Functions (`$.vault.get('SECRET_NAME')`)
 * - Workflows (`{{vault:SECRET_NAME}}` in step configs)
 * - Integration configs (connection credentials)
 * - API proxy headers (upstream auth tokens)
 *
 * Looks up the secret by name, returns the decrypted value.
 * Throws if the secret doesn't exist.
 *
 * @param apiKey - The platform's WorkOS API key (Bearer token)
 * @param secretName - The human-readable secret name to resolve
 * @returns The decrypted secret value
 */
export async function resolveSecret(apiKey: string, secretName: string): Promise<string> {
  const list = await listVaultSecrets(apiKey, { limit: 100 })
  const secret = list.data.find((s) => s.name === secretName)
  if (!secret) {
    throw new Error(`Vault secret not found: ${secretName}`)
  }
  const revealed = await readVaultSecretValue(apiKey, secret.id)
  return revealed.value
}

/**
 * Resolve multiple secrets at once (for batch injection into runtime contexts).
 * Returns a map of name -> value.
 * Missing secrets are skipped (not thrown) — caller checks for required ones.
 *
 * @param apiKey - The platform's WorkOS API key (Bearer token)
 * @param secretNames - Array of secret names to resolve
 * @returns Map of name -> decrypted value (missing secrets omitted)
 */
export async function resolveSecrets(apiKey: string, secretNames: string[]): Promise<Record<string, string>> {
  if (secretNames.length === 0) return {}

  const list = await listVaultSecrets(apiKey, { limit: 100 })
  const nameToId = new Map<string, string>()
  for (const s of list.data) {
    if (secretNames.includes(s.name)) {
      nameToId.set(s.name, s.id)
    }
  }

  const result: Record<string, string> = {}
  for (const [name, id] of nameToId) {
    try {
      const revealed = await readVaultSecretValue(apiKey, id)
      result[name] = revealed.value
    } catch {
      // Skip secrets that can't be revealed
    }
  }
  return result
}

/**
 * Replace `{{vault:SECRET_NAME}}` placeholders in a string with resolved values.
 * Used by workflow engines and config parsers.
 *
 * Placeholders that reference missing secrets are left unchanged.
 *
 * @param apiKey - The platform's WorkOS API key (Bearer token)
 * @param template - String containing `{{vault:NAME}}` placeholders
 * @returns The template with placeholders replaced by decrypted values
 */
export async function interpolateSecrets(apiKey: string, template: string): Promise<string> {
  const pattern = /\{\{vault:([A-Za-z0-9_-]+)\}\}/g
  const matches = [...template.matchAll(pattern)]
  if (matches.length === 0) return template

  const names = [...new Set(matches.map((m) => m[1]))]
  const resolved = await resolveSecrets(apiKey, names)

  let result = template
  for (const match of matches) {
    const name = match[1]
    const value = resolved[name]
    if (value !== undefined) {
      result = result.replace(match[0], value)
    }
  }
  return result
}
