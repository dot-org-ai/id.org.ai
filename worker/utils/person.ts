/**
 * The signed-in person as the auth pages show them: their name, email and
 * avatar, and their active WorkOS workspaces (consent, device confirm).
 */
import type { Env } from '../types'
import { fetchOrgInfo, listUserOrgMemberships } from '../../src/sdk/workos/upstream'
import { getStubForIdentity } from '../middleware/tenant'

export interface PersonAccount {
  name: string
  email: string
  avatar?: string
}

export interface Workspace {
  id: string
  name: string
}

/** The person: name, email and avatar from their identity record. */
export async function personAccount(env: Env, identityId: string): Promise<PersonAccount> {
  const identity = (await getStubForIdentity(env, identityId)
    .getIdentity(identityId)
    .catch(() => null)) as { name?: string; email?: string; image?: string } | null
  const email = identity?.email ?? ''
  return { name: identity?.name || email || 'You', email, ...(identity?.image && { avatar: identity.image }) }
}

/** Their active WorkOS workspaces, named. Empty when WorkOS isn't configured or the identity isn't linked. */
export async function personWorkspaces(env: Env, identityId: string): Promise<Workspace[]> {
  if (!env.WORKOS_API_KEY) return []
  const stored = await getStubForIdentity(env, identityId)
    .oauthStorageOp({ op: 'get', key: `identity:${identityId}` })
    .catch(() => null)
  const workosUserId = (stored?.value as { workosUserId?: string } | null)?.workosUserId
  if (!workosUserId) return []
  const memberships = (await listUserOrgMemberships(env.WORKOS_API_KEY, workosUserId)).filter((m) => m.status === 'active')
  return Promise.all(
    memberships.map(async (m) => ({ id: m.organization_id, name: (await fetchOrgInfo(env.WORKOS_API_KEY!, m.organization_id))?.name ?? m.organization_id })),
  )
}
