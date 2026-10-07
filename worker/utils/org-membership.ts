/**
 * Is an organization one of a Person's workspaces? The OAuth provider asks this
 * of the `org_id` a consent POST names (docs/product-update/spec/backend.md#b2,
 * #b6) before it is stored on the authorization code and emitted in tokens.
 *
 * True only when the Person behind `identityId` has an **active** WorkOS
 * membership in `orgId`. Fails closed: no WorkOS key, no WorkOS user on the
 * identity, or a WorkOS error all answer false.
 */
import type { Env } from '../types'
import { getStubForIdentity } from '../middleware/tenant'
import { listUserOrgMemberships } from '../../src/sdk/workos/upstream'
import type { OrgMembershipValidator } from '../../src/sdk/oauth/provider'

/** The WorkOS user id stored on the identity record (`identity:{id}` → `{ workosUserId }`). */
export async function workosUserIdOf(env: Env, identityId: string): Promise<string | null> {
  const stub = getStubForIdentity(env, identityId)
  const stored = await stub.oauthStorageOp({ op: 'get', key: `identity:${identityId}` }).catch(() => null)
  const id = (stored?.value as { workosUserId?: unknown } | null | undefined)?.workosUserId
  return typeof id === 'string' && id ? id : null
}

export function validateOrgMembershipFor(env: Env): OrgMembershipValidator {
  return async (identityId: string, orgId: string): Promise<boolean> => {
    if (!env.WORKOS_API_KEY || !identityId || !orgId) return false
    const workosUserId = await workosUserIdOf(env, identityId)
    if (!workosUserId) return false
    const memberships = await listUserOrgMemberships(env.WORKOS_API_KEY, workosUserId)
    return memberships.some((m) => m.organization_id === orgId && m.status === 'active')
  }
}
