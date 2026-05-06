/**
 * Tenant-scoped WorkOS Vault wrapper (id-z7d).
 *
 * id.org.ai exposes a Vault-like surface where every secret is bound to a
 * Tenant. Sibling agents under one tenant share their tenant's secrets;
 * cross-tenant access is impossible by construction.
 *
 * Naming convention: `tenant_{tenantId}__{name}`.
 *   - `tenantId` is the id.org.ai tenant identifier (e.g. `tenant_abc...`)
 *   - `name` is the caller-facing secret name (e.g. `STRIPE_KEY`)
 *
 * The double underscore is the separator. Caller-facing name MUST NOT
 * contain `__` to keep the encoding unambiguous; this is enforced.
 *
 * Backed by the existing src/sdk/workos/vault primitives, which use raw
 * fetch against api.workos.com/vault/v1/secrets.
 *
 * Future (id-9s0/id-9s0+): when AAP wires up DPoP, agent-issued requests
 * for downstream credentials should also pass an `agentId` audit field
 * via the secret's description. Out of scope for id-z7d.
 */

import {
  createVaultSecret,
  updateVaultSecret,
  listVaultSecrets,
  deleteVaultSecret,
  readVaultSecretValue,
  type VaultSecret,
} from './vault'

// ============================================================================
// Naming
// ============================================================================

const SEP = '__'

/** Compose the WorkOS Vault `name` from a tenant ID and caller-facing secret name. */
export function encodeTenantVaultName(tenantId: string, name: string): string {
  if (!tenantId || tenantId.includes(SEP)) {
    throw new Error(`Invalid tenantId: must be non-empty and contain no '${SEP}' separator`)
  }
  if (!name || name.includes(SEP)) {
    throw new Error(`Invalid secret name: must be non-empty and contain no '${SEP}' separator`)
  }
  return `tenant_${tenantId}${SEP}${name}`
}

/**
 * Decode a WorkOS Vault `name` into `{ tenantId, name }` if it matches the
 * tenant convention. Returns null otherwise (foreign secret — not ours).
 */
export function decodeTenantVaultName(fullName: string): { tenantId: string; name: string } | null {
  if (!fullName.startsWith('tenant_')) return null
  const idx = fullName.indexOf(SEP)
  if (idx === -1) return null
  const tenantPart = fullName.slice(0, idx) // 'tenant_xxx'
  const name = fullName.slice(idx + SEP.length)
  const tenantId = tenantPart.slice('tenant_'.length)
  if (!tenantId || !name) return null
  return { tenantId, name }
}

// ============================================================================
// Public API
// ============================================================================

export interface TenantSecretInfo {
  /** The id.org.ai-facing secret name (without tenant prefix). */
  name: string
  /** WorkOS-side secret id (`secret_*`). */
  id: string
  /** Tenant the secret is scoped to. */
  tenantId: string
  /** ISO timestamp. */
  createdAt: string
  /** ISO timestamp. */
  updatedAt: string
  /** Optional caller-supplied description. */
  description?: string
}

/**
 * Put a tenant-scoped secret. Creates if absent, updates if present.
 * Returns the WorkOS secret metadata (no value).
 */
export async function putTenantSecret(
  apiKey: string,
  tenantId: string,
  name: string,
  value: string,
  options?: { description?: string },
): Promise<TenantSecretInfo> {
  const fullName = encodeTenantVaultName(tenantId, name)

  // Look up existing — listVaultSecrets paginates, but with limit=100 this
  // is enough for the current scale (id.org.ai is greenfield).
  const list = await listVaultSecrets(apiKey, { limit: 100 })
  const existing = list.data.find((s) => s.name === fullName)

  let secret: VaultSecret
  if (existing) {
    secret = await updateVaultSecret(apiKey, existing.id, {
      value,
      description: options?.description,
    })
  } else {
    secret = await createVaultSecret(apiKey, {
      name: fullName,
      value,
      description: options?.description,
    })
  }

  return toInfo(secret, tenantId, name)
}

/**
 * Read the decrypted value of a tenant-scoped secret. Throws if absent.
 * Each call is audit-logged by WorkOS — use sparingly.
 */
export async function getTenantSecretValue(apiKey: string, tenantId: string, name: string): Promise<string> {
  const fullName = encodeTenantVaultName(tenantId, name)
  const list = await listVaultSecrets(apiKey, { limit: 100 })
  const secret = list.data.find((s) => s.name === fullName)
  if (!secret) {
    throw new Error(`Tenant secret not found: ${tenantId}/${name}`)
  }
  const revealed = await readVaultSecretValue(apiKey, secret.id)
  return revealed.value
}

/** List all secrets for a tenant (metadata only). */
export async function listTenantSecrets(apiKey: string, tenantId: string): Promise<TenantSecretInfo[]> {
  const list = await listVaultSecrets(apiKey, { limit: 100 })
  const result: TenantSecretInfo[] = []
  for (const secret of list.data) {
    const decoded = decodeTenantVaultName(secret.name)
    if (decoded && decoded.tenantId === tenantId) {
      result.push(toInfo(secret, decoded.tenantId, decoded.name))
    }
  }
  return result
}

/** Delete a tenant-scoped secret by name. Idempotent — no error if absent. */
export async function deleteTenantSecret(apiKey: string, tenantId: string, name: string): Promise<void> {
  const fullName = encodeTenantVaultName(tenantId, name)
  const list = await listVaultSecrets(apiKey, { limit: 100 })
  const secret = list.data.find((s) => s.name === fullName)
  if (!secret) return
  await deleteVaultSecret(apiKey, secret.id)
}

// ============================================================================
// Internal
// ============================================================================

function toInfo(secret: VaultSecret, tenantId: string, name: string): TenantSecretInfo {
  return {
    name,
    id: secret.id,
    tenantId,
    createdAt: secret.created_at,
    updatedAt: secret.updated_at,
    description: secret.description,
  }
}
