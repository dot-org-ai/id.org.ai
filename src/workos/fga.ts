/**
 * WorkOS Fine-Grained Authorization (FGA)
 *
 * Zanzibar-style entity-level authorization for all 35 headless.ly entities.
 * Moves from implicit DO-isolation to explicit FGA checks.
 *
 * Resource types map 1:1 with headless.ly entities.
 * Relations: owner > editor > viewer (inherited), parent (tenant hierarchy).
 * Warrants are the actual permission grants.
 * Checks ask "can user X do action Y on resource Z?"
 */

// ── Resource Type Definitions ───────────────────────────────────────────────

/** All 35 headless.ly entity types as FGA resource types */
export const FGA_RESOURCE_TYPES = [
  // Identity
  'user',
  'api-key',
  // CRM
  'organization',
  'contact',
  'lead',
  'deal',
  'activity',
  'pipeline',
  // Billing
  'customer',
  'product',
  'plan',
  'price',
  'subscription',
  'invoice',
  'payment',
  // Projects
  'project',
  'issue',
  'comment',
  // Content
  'content',
  'asset',
  'site',
  // Support
  'ticket',
  // Analytics
  'event',
  'metric',
  'funnel',
  'goal',
  // Marketing
  'campaign',
  'segment',
  'form',
  // Experimentation
  'experiment',
  'feature-flag',
  // Platform
  'workflow',
  'integration',
  'agent',
  // Communication
  'message',
  // Meta
  'tenant',
] as const

export type FGAResourceType = (typeof FGA_RESOURCE_TYPES)[number]

/** Standard relations for entity access */
export type FGARelation = 'owner' | 'editor' | 'viewer' | 'parent'

/** A warrant (permission grant) */
export interface FGAWarrant {
  resourceType: FGAResourceType
  resourceId: string
  relation: FGARelation
  subject: {
    resourceType: 'user' | 'tenant'
    resourceId: string
  }
}

/** FGA check request */
export interface FGACheckRequest {
  resourceType: FGAResourceType
  resourceId: string
  relation: FGARelation
  subject: {
    resourceType: 'user' | 'tenant'
    resourceId: string
  }
}

// ── WorkOS FGA API Helpers ──────────────────────────────────────────────────

const FGA_BASE = 'https://api.workos.com/fga/v1'

/**
 * Create a warrant (permission grant).
 * Called when entities are created to establish ownership.
 */
export async function createWarrant(apiKey: string, warrant: FGAWarrant): Promise<{ warrantToken: string }> {
  const resp = await fetch(`${FGA_BASE}/warrants`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      resource_type: warrant.resourceType,
      resource_id: warrant.resourceId,
      relation: warrant.relation,
      subject: {
        resource_type: warrant.subject.resourceType,
        resource_id: warrant.subject.resourceId,
      },
    }),
  })
  if (!resp.ok) {
    const body = await resp.text()
    throw new Error(`FGA createWarrant failed: ${resp.status} ${body}`)
  }
  return resp.json() as Promise<{ warrantToken: string }>
}

/**
 * Delete a warrant (revoke permission).
 */
export async function deleteWarrant(apiKey: string, warrant: FGAWarrant): Promise<void> {
  const resp = await fetch(`${FGA_BASE}/warrants`, {
    method: 'DELETE',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      resource_type: warrant.resourceType,
      resource_id: warrant.resourceId,
      relation: warrant.relation,
      subject: {
        resource_type: warrant.subject.resourceType,
        resource_id: warrant.subject.resourceId,
      },
    }),
  })
  if (!resp.ok && resp.status !== 404) {
    const body = await resp.text()
    throw new Error(`FGA deleteWarrant failed: ${resp.status} ${body}`)
  }
}

/**
 * Check if a subject has a relation on a resource.
 * This is the core authorization check — called on every API request.
 */
export async function checkPermission(apiKey: string, check: FGACheckRequest): Promise<boolean> {
  const resp = await fetch(`${FGA_BASE}/check`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      checks: [
        {
          resource_type: check.resourceType,
          resource_id: check.resourceId,
          relation: check.relation,
          subject: {
            resource_type: check.subject.resourceType,
            resource_id: check.subject.resourceId,
          },
        },
      ],
    }),
  })
  if (!resp.ok) {
    const body = await resp.text()
    throw new Error(`FGA check failed: ${resp.status} ${body}`)
  }
  const result = (await resp.json()) as { result: string }
  return result.result === 'authorized'
}

/**
 * Batch check multiple permissions at once.
 */
export async function batchCheck(apiKey: string, checks: FGACheckRequest[]): Promise<boolean[]> {
  const resp = await fetch(`${FGA_BASE}/check`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      checks: checks.map((c) => ({
        resource_type: c.resourceType,
        resource_id: c.resourceId,
        relation: c.relation,
        subject: {
          resource_type: c.subject.resourceType,
          resource_id: c.subject.resourceId,
        },
      })),
    }),
  })
  if (!resp.ok) {
    const body = await resp.text()
    throw new Error(`FGA batchCheck failed: ${resp.status} ${body}`)
  }
  const result = (await resp.json()) as Array<{ result: string }>
  return result.map((r) => r.result === 'authorized')
}

/**
 * Register a resource with tenant as parent.
 * Called on entity creation to establish the tenant->entity hierarchy.
 */
export async function registerResource(
  apiKey: string,
  resourceType: FGAResourceType,
  resourceId: string,
  tenantId: string,
  createdBy?: string,
): Promise<void> {
  // Create tenant->entity parent warrant
  await createWarrant(apiKey, {
    resourceType,
    resourceId,
    relation: 'parent',
    subject: { resourceType: 'tenant', resourceId: tenantId },
  })

  // If createdBy is provided, make them the owner
  if (createdBy) {
    await createWarrant(apiKey, {
      resourceType,
      resourceId,
      relation: 'owner',
      subject: { resourceType: 'user', resourceId: createdBy },
    })
  }
}

/**
 * Share a resource with another tenant (cross-tenant sharing).
 * Grants viewer access to the target tenant.
 */
export async function shareResource(
  apiKey: string,
  resourceType: FGAResourceType,
  resourceId: string,
  targetTenantId: string,
  relation: FGARelation = 'viewer',
): Promise<void> {
  await createWarrant(apiKey, {
    resourceType,
    resourceId,
    relation,
    subject: { resourceType: 'tenant', resourceId: targetTenantId },
  })
}

/**
 * Revoke cross-tenant sharing.
 */
export async function unshareResource(
  apiKey: string,
  resourceType: FGAResourceType,
  resourceId: string,
  targetTenantId: string,
  relation: FGARelation = 'viewer',
): Promise<void> {
  await deleteWarrant(apiKey, {
    resourceType,
    resourceId,
    relation,
    subject: { resourceType: 'tenant', resourceId: targetTenantId },
  })
}

/**
 * List all resources a user can access (query warrants).
 */
export async function listAccessible(
  apiKey: string,
  resourceType: FGAResourceType,
  userId: string,
  relation: FGARelation = 'viewer',
): Promise<Array<{ resourceType: string; resourceId: string }>> {
  const resp = await fetch(
    `${FGA_BASE}/warrants?resource_type=${resourceType}&relation=${relation}&subject_type=user&subject_id=${userId}&limit=100`,
    {
      headers: { Authorization: `Bearer ${apiKey}` },
    },
  )
  if (!resp.ok) {
    const body = await resp.text()
    throw new Error(`FGA listAccessible failed: ${resp.status} ${body}`)
  }
  const result = (await resp.json()) as { data: Array<{ resource_type: string; resource_id: string }> }
  return result.data.map((w) => ({ resourceType: w.resource_type, resourceId: w.resource_id }))
}

/**
 * Define resource types in WorkOS FGA.
 * Run once during setup to register all 35 entity types with their relations.
 */
export async function defineResourceTypes(apiKey: string): Promise<void> {
  for (const resourceType of FGA_RESOURCE_TYPES) {
    await fetch(`${FGA_BASE}/resource-types`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        type: resourceType,
        relations: {
          owner: {},
          editor: { inherit_if: 'owner' },
          viewer: { inherit_if: 'editor' },
          parent: {},
        },
      }),
    })
    // Ignore 409 (already exists)
  }
}

/**
 * Map entity type slug (e.g., 'contacts') to FGA resource type (e.g., 'contact').
 */
export function entityTypeToFGA(entityType: string): FGAResourceType | undefined {
  // Normalize to lowercase
  const lower = entityType.toLowerCase()
  // Strip trailing 's' for plural -> singular
  const singular = lower.endsWith('s') ? lower.slice(0, -1) : lower
  // Handle special cases
  const map: Record<string, FGAResourceType> = {
    'api-key': 'api-key',
    apikey: 'api-key',
    featureflag: 'feature-flag',
    'feature-flag': 'feature-flag',
  }
  return map[singular] || (FGA_RESOURCE_TYPES.includes(singular as FGAResourceType) ? (singular as FGAResourceType) : undefined)
}
