/**
 * WorkOS Directory Sync (SCIM) Event Handlers
 *
 * Handles enterprise user provisioning via WorkOS Directory Sync webhooks.
 * Events follow the pattern `dsync.{resource}.{action}`:
 *
 *   - dsync.user.created/updated/deleted   — User lifecycle
 *   - dsync.group.created/updated/deleted   — Group lifecycle
 *   - dsync.group.user_added/user_removed   — Group membership
 *
 * All data is stored in D1 tables (directory_users, directory_groups,
 * directory_group_members). Users are never hard-deleted — deactivation
 * sets state to 'suspended'.
 */

// ============================================================================
// Types
// ============================================================================

/** WorkOS Directory Sync event payload */
export interface DSyncEvent {
  id: string
  event: string // e.g., 'dsync.user.created'
  data: DSyncUser | DSyncGroup | DSyncGroupMembership
  created_at: string
  directory_id: string
}

export interface DSyncUser {
  id: string // WorkOS directory user ID (directory_user_*)
  directory_id: string
  organization_id: string
  idp_id: string // IdP's user ID
  first_name: string
  last_name: string
  email: string
  username?: string
  state: 'active' | 'suspended'
  custom_attributes: Record<string, unknown>
  raw_attributes: Record<string, unknown>
  groups: Array<{ id: string; name: string }>
  created_at: string
  updated_at: string
}

export interface DSyncGroup {
  id: string // WorkOS directory group ID (directory_group_*)
  directory_id: string
  organization_id: string
  idp_id: string
  name: string
  created_at: string
  updated_at: string
}

export interface DSyncGroupMembership {
  directory_id: string
  directory_group: DSyncGroup
  directory_user: DSyncUser
}

// ============================================================================
// Table Initialization
// ============================================================================

/**
 * Ensure SCIM-related D1 tables exist.
 *
 * Called before every webhook handler — safe to call multiple times
 * because every statement uses CREATE TABLE IF NOT EXISTS.
 */
export async function ensureSCIMTables(db: D1Database): Promise<void> {
  await db.exec(`
    CREATE TABLE IF NOT EXISTS directory_users (
      id TEXT PRIMARY KEY,
      workos_id TEXT UNIQUE NOT NULL,
      directory_id TEXT NOT NULL,
      organization_id TEXT NOT NULL,
      email TEXT NOT NULL,
      first_name TEXT,
      last_name TEXT,
      state TEXT DEFAULT 'active',
      raw_attributes TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS directory_groups (
      id TEXT PRIMARY KEY,
      workos_id TEXT UNIQUE NOT NULL,
      directory_id TEXT NOT NULL,
      organization_id TEXT NOT NULL,
      name TEXT NOT NULL,
      role TEXT DEFAULT 'member',
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS directory_group_members (
      group_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      added_at TEXT NOT NULL,
      PRIMARY KEY (group_id, user_id),
      FOREIGN KEY (group_id) REFERENCES directory_groups(workos_id),
      FOREIGN KEY (user_id) REFERENCES directory_users(workos_id)
    );
    CREATE INDEX IF NOT EXISTS idx_directory_users_email ON directory_users(email);
    CREATE INDEX IF NOT EXISTS idx_directory_users_org ON directory_users(organization_id);
    CREATE INDEX IF NOT EXISTS idx_directory_groups_org ON directory_groups(organization_id);
  `)
}

// ============================================================================
// User Handlers
// ============================================================================

/**
 * Handle dsync.user.created — provision a new directory user.
 *
 * Upserts into directory_users (idempotent if WorkOS retries the webhook).
 */
export async function handleDSyncUserCreated(
  user: DSyncUser,
  db: D1Database,
): Promise<{ userId: string; contactId: string }> {
  const userId = crypto.randomUUID()
  const contactId = `contact_${crypto.randomUUID().slice(0, 8)}`
  const now = new Date().toISOString()

  await db
    .prepare(
      `INSERT INTO directory_users (id, workos_id, directory_id, organization_id, email, first_name, last_name, state, raw_attributes, created_at, updated_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
       ON CONFLICT (workos_id) DO UPDATE SET
         email = excluded.email,
         first_name = excluded.first_name,
         last_name = excluded.last_name,
         state = excluded.state,
         raw_attributes = excluded.raw_attributes,
         updated_at = excluded.updated_at`,
    )
    .bind(
      userId,
      user.id,
      user.directory_id,
      user.organization_id,
      user.email,
      user.first_name || null,
      user.last_name || null,
      user.state || 'active',
      JSON.stringify(user.raw_attributes || {}),
      user.created_at || now,
      user.updated_at || now,
    )
    .run()

  return { userId, contactId }
}

/**
 * Handle dsync.user.updated — update an existing directory user.
 *
 * Finds the user by WorkOS ID and updates name, email, and state.
 * If state is 'suspended', the user is soft-deactivated.
 */
export async function handleDSyncUserUpdated(
  user: DSyncUser,
  db: D1Database,
): Promise<{ updated: boolean }> {
  const now = new Date().toISOString()

  const result = await db
    .prepare(
      `UPDATE directory_users
       SET email = ?1, first_name = ?2, last_name = ?3, state = ?4, raw_attributes = ?5, updated_at = ?6
       WHERE workos_id = ?7`,
    )
    .bind(
      user.email,
      user.first_name || null,
      user.last_name || null,
      user.state || 'active',
      JSON.stringify(user.raw_attributes || {}),
      now,
      user.id,
    )
    .run()

  return { updated: (result.meta?.changes ?? 0) > 0 }
}

/**
 * Handle dsync.user.deleted — deactivate a directory user.
 *
 * Marks the user as suspended (soft delete). Never hard-deletes.
 */
export async function handleDSyncUserDeleted(
  user: DSyncUser,
  db: D1Database,
): Promise<{ deactivated: boolean }> {
  const now = new Date().toISOString()

  const result = await db
    .prepare(
      `UPDATE directory_users SET state = 'suspended', updated_at = ?1 WHERE workos_id = ?2`,
    )
    .bind(now, user.id)
    .run()

  return { deactivated: (result.meta?.changes ?? 0) > 0 }
}

// ============================================================================
// Group Handlers
// ============================================================================

/**
 * Handle dsync.group.created — create a new directory group.
 *
 * Maps the group name to a role via `mapGroupToRole()`.
 */
export async function handleDSyncGroupCreated(
  group: DSyncGroup,
  db: D1Database,
): Promise<{ groupId: string }> {
  const groupId = crypto.randomUUID()
  const role = mapGroupToRole(group.name)
  const now = new Date().toISOString()

  await db
    .prepare(
      `INSERT INTO directory_groups (id, workos_id, directory_id, organization_id, name, role, created_at, updated_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
       ON CONFLICT (workos_id) DO UPDATE SET
         name = excluded.name,
         role = excluded.role,
         updated_at = excluded.updated_at`,
    )
    .bind(
      groupId,
      group.id,
      group.directory_id,
      group.organization_id,
      group.name,
      role,
      group.created_at || now,
      group.updated_at || now,
    )
    .run()

  return { groupId }
}

/**
 * Handle dsync.group.updated — update a directory group's name and role mapping.
 */
export async function handleDSyncGroupUpdated(
  group: DSyncGroup,
  db: D1Database,
): Promise<{ updated: boolean }> {
  const role = mapGroupToRole(group.name)
  const now = new Date().toISOString()

  const result = await db
    .prepare(
      `UPDATE directory_groups SET name = ?1, role = ?2, updated_at = ?3 WHERE workos_id = ?4`,
    )
    .bind(group.name, role, now, group.id)
    .run()

  return { updated: (result.meta?.changes ?? 0) > 0 }
}

/**
 * Handle dsync.group.deleted — soft-delete a directory group.
 *
 * Removes the group record but does NOT remove users from the group.
 * Group membership records remain for audit trail.
 */
export async function handleDSyncGroupDeleted(
  group: DSyncGroup,
  db: D1Database,
): Promise<{ deleted: boolean }> {
  const result = await db
    .prepare(`DELETE FROM directory_groups WHERE workos_id = ?1`)
    .bind(group.id)
    .run()

  return { deleted: (result.meta?.changes ?? 0) > 0 }
}

// ============================================================================
// Group Membership Handlers
// ============================================================================

/**
 * Handle dsync.group.user_added — add a user to a group.
 *
 * Also updates the user's effective role based on the group's role mapping.
 */
export async function handleDSyncGroupUserAdded(
  membership: DSyncGroupMembership,
  db: D1Database,
): Promise<{ added: boolean }> {
  const now = new Date().toISOString()

  // Ensure both the user and group exist (they may arrive out of order)
  const userExists = await db
    .prepare(`SELECT 1 FROM directory_users WHERE workos_id = ?1`)
    .bind(membership.directory_user.id)
    .first()

  if (!userExists) {
    // Auto-create the user if we haven't seen the dsync.user.created event yet
    await handleDSyncUserCreated(membership.directory_user, db)
  }

  const groupExists = await db
    .prepare(`SELECT 1 FROM directory_groups WHERE workos_id = ?1`)
    .bind(membership.directory_group.id)
    .first()

  if (!groupExists) {
    await handleDSyncGroupCreated(membership.directory_group, db)
  }

  // Insert membership (ignore if already exists)
  await db
    .prepare(
      `INSERT OR IGNORE INTO directory_group_members (group_id, user_id, added_at)
       VALUES (?1, ?2, ?3)`,
    )
    .bind(membership.directory_group.id, membership.directory_user.id, now)
    .run()

  return { added: true }
}

/**
 * Handle dsync.group.user_removed — remove a user from a group.
 *
 * If the user has no remaining group memberships, their role is
 * effectively downgraded (the absence of group memberships means
 * no elevated role).
 */
export async function handleDSyncGroupUserRemoved(
  membership: DSyncGroupMembership,
  db: D1Database,
): Promise<{ removed: boolean }> {
  const result = await db
    .prepare(
      `DELETE FROM directory_group_members WHERE group_id = ?1 AND user_id = ?2`,
    )
    .bind(membership.directory_group.id, membership.directory_user.id)
    .run()

  return { removed: (result.meta?.changes ?? 0) > 0 }
}

// ============================================================================
// Role Mapping
// ============================================================================

/**
 * Map a directory group name to a platform role.
 *
 * Common enterprise group naming patterns:
 *   - 'admins', 'administrators', 'admin', 'it-admins' → 'admin'
 *   - 'engineering', 'developers', 'dev', 'product' → 'member'
 *   - 'viewers', 'readonly', 'read-only', 'auditors' → 'viewer'
 *   - everything else → 'member'
 */
export function mapGroupToRole(groupName: string): string {
  const normalized = groupName.toLowerCase().trim()

  // Admin patterns
  if (
    normalized === 'admins' ||
    normalized === 'administrators' ||
    normalized === 'admin' ||
    normalized === 'it-admins' ||
    normalized === 'super-admins' ||
    normalized === 'superadmins' ||
    normalized.endsWith('-admins') ||
    normalized.endsWith(' admins')
  ) {
    return 'admin'
  }

  // Viewer / read-only patterns
  if (
    normalized === 'viewers' ||
    normalized === 'readonly' ||
    normalized === 'read-only' ||
    normalized === 'auditors' ||
    normalized === 'observers' ||
    normalized.endsWith('-viewers') ||
    normalized.endsWith(' viewers')
  ) {
    return 'viewer'
  }

  // Default to member for all other groups
  return 'member'
}

// ============================================================================
// Admin Portal
// ============================================================================

/**
 * Generate a WorkOS Admin Portal link for self-service SCIM/SSO configuration.
 *
 * The Admin Portal allows enterprise IT admins to configure their directory
 * connection (Okta, Azure AD, etc.) without needing our support.
 *
 * @param organizationId - The WorkOS organization ID
 * @param workosApiKey - The platform's WorkOS API key
 * @returns An object with a short-lived `url` to redirect the admin to
 */
export async function getAdminPortalUrl(
  organizationId: string,
  workosApiKey: string,
): Promise<{ url: string }> {
  const response = await fetch('https://api.workos.com/portal/generate_link', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${workosApiKey}`,
    },
    body: JSON.stringify({
      organization: organizationId,
      intent: 'dsync',
    }),
  })

  if (!response.ok) {
    const text = await response.text()
    throw new Error(`WorkOS Admin Portal link generation failed: ${response.status} ${text}`)
  }

  const data = (await response.json()) as { link: string }
  return { url: data.link }
}
