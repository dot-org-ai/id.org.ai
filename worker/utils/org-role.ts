/**
 * A Person's role in one organization, for estate Workers bound to AuthService.
 *
 * Relying parties (emails.do, …) authenticate a person by the OIDC `sub` in
 * the id_token or access token id.org.ai issued them, which is the identity
 * id, not the WorkOS user id. Those tokens carry no roles, so a relying party
 * that needs "is this person an admin of org X" asks here instead of keeping
 * its own admin list.
 *
 * The role is read from WorkOS at call time (no claim to go stale), from the
 * person's **active** membership only, and folded to the Account role set
 * (owner | admin | editor | viewer) by workosSlugToAccountRole. `orgId`
 * defaults to PLATFORM_ORG_ID. Fails closed: no WorkOS key, no org, no WorkOS
 * user on the identity, no active membership, or a WorkOS error all answer
 * null. Callers cache the answer briefly; this does not.
 */
import type { Env } from '../types'
import { listUserOrgMemberships } from '../../src/sdk/workos/upstream'
import { workosSlugToAccountRole, type AccountRole } from '../../src/sdk/workos/roles'
import { workosUserIdOf } from './org-membership'

export async function orgRoleOf(env: Env, identityId: string, orgId?: string): Promise<AccountRole | null> {
  const org = orgId || env.PLATFORM_ORG_ID
  if (!env.WORKOS_API_KEY || !org || typeof identityId !== 'string' || !identityId) return null
  const workosUserId = await workosUserIdOf(env, identityId)
  if (!workosUserId) return null
  const memberships = await listUserOrgMemberships(env.WORKOS_API_KEY, workosUserId)
  const m = memberships.find((x) => x.organization_id === org && x.status === 'active')
  return m ? workosSlugToAccountRole(m.role?.slug) : null
}
