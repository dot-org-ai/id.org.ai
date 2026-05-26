/**
 * Role-slug ↔ Account-role mapping.
 *
 * SaaS.Studio's Account tier (ADR 0021) uses a fixed four-role set —
 * `owner | admin | editor | viewer` — for human members. WorkOS stores a
 * role *slug* per organization membership. This module is the single place
 * that translates between the two vocabularies, on both read and write, so
 * the rest of the org-membership surface speaks one language.
 *
 * ## Mapping
 *
 *   Account role   →  WorkOS slug   (write: invite / role-change)
 *   ------------      -----------
 *   owner          →  owner
 *   admin          →  admin
 *   editor         →  editor
 *   viewer         →  viewer
 *
 * WorkOS's default org role slug is `member`. Several existing id.org.ai code
 * paths create memberships with the `member` slug. On the read path we fold
 * unknown / legacy slugs to the nearest Account role:
 *
 *   WorkOS slug    →  Account role  (read: member list)
 *   -----------       ------------
 *   owner          →  owner
 *   admin          →  admin
 *   editor         →  editor
 *   viewer         →  viewer
 *   member         →  editor   (legacy default — closest collaborative role)
 *   <anything else>→  viewer   (fail safe: least privilege)
 *
 * The slugs we *write* (`owner|admin|editor|viewer`) must exist as roles in
 * the WorkOS organization. They are the ADR-0021 canonical set; configure them
 * in the WorkOS dashboard for org `org_01K05B2AERNQ8N0QVSRFBSCNMS`.
 */

/** The fixed Account roles (mirrors saas.studio `roles.ts`). */
export const ACCOUNT_ROLES = ['owner', 'admin', 'editor', 'viewer'] as const
export type AccountRole = (typeof ACCOUNT_ROLES)[number]

/** Whether a string is a known Account role. */
export function isAccountRole(value: string): value is AccountRole {
  return (ACCOUNT_ROLES as readonly string[]).includes(value)
}

/**
 * Map a WorkOS role slug to an Account role (read path).
 * Unknown slugs fold to `viewer` (least privilege); legacy `member` → `editor`.
 */
export function workosSlugToAccountRole(slug: string | undefined | null): AccountRole {
  if (!slug) return 'viewer'
  if (isAccountRole(slug)) return slug
  if (slug === 'member') return 'editor'
  return 'viewer'
}

/**
 * Map an Account role to the WorkOS role slug to write (invite / role-change).
 * Unknown values fall back to `viewer`.
 */
export function accountRoleToWorkosSlug(role: string | undefined | null): string {
  if (role && isAccountRole(role)) return role
  return 'viewer'
}
