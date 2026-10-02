/**
 * Who may act on an organization (docs/product-update/spec/backend.md#b13, #b6).
 *
 * Callers come in three kinds:
 *   - platform: a validated WorkOS `sk_` key that is unscoped or scoped to
 *     PLATFORM_ORG_ID (the platform's own server tokens), or a person who is an
 *     owner/admin of PLATFORM_ORG_ID;
 *   - service: a validated WorkOS `sk_` key scoped to one organization. It acts
 *     as an admin of that organization and of nothing else;
 *   - user: a person, resolved to their WorkOS user id. They must be a member
 *     of the organization to read it, and an owner or admin to change it.
 *
 * A key caller is recognised by the identity authenticateRequest built, never
 * by the request's headers: only AuthBroker's WorkOS-key path marks an identity
 * `credential: 'workos-key'`, after WorkOS validated the key. (Reading the
 * Authorization header instead let a person's own key in X-API-Key, plus an
 * unvalidated `Bearer sk_…`, pass as the platform.)
 */
import type { Context } from 'hono'
import type { Env, Variables } from '../types'
import type { IdentityStub } from '../../src/server/do/Identity'
import { listUserOrgMemberships } from '../../src/sdk/workos/upstream'
import { workosSlugToAccountRole, type AccountRole } from '../../src/sdk/workos/roles'
import { extractWorkOSUserFromJWT } from '../middleware/tenant'
import { errorResponse, ErrorCode } from '../../src/sdk/errors'

type C = Context<{ Bindings: Env; Variables: Variables }>

export type Caller =
  | { kind: 'platform' }
  | { kind: 'service'; orgId: string }
  | { kind: 'user'; workosUserId: string; roles: Map<string, AccountRole> }

const WRITE_ROLES: ReadonlySet<AccountRole> = new Set(['owner', 'admin'])

async function workosUserIdOf(c: C): Promise<string | null> {
  const auth = c.get('auth')
  if (auth?.authenticated && auth.identityId) {
    const stub = c.get('identityStub') as IdentityStub | undefined
    if (stub) {
      const stored = await stub.oauthStorageOp({ op: 'get', key: `identity:${auth.identityId}` }).catch(() => null)
      const id = (stored?.value as { workosUserId?: string } | null)?.workosUserId
      if (id) return id
    }
  }
  const jwt = await extractWorkOSUserFromJWT(c.req.raw, c.env).catch(() => null)
  return jwt?.sub ?? null
}

/** Resolve the caller, or null when the request isn't authenticated as anyone usable. */
export async function resolveCaller(c: C): Promise<Caller | null> {
  const identity = c.get('identity')
  if (identity?.credential === 'workos-key') {
    const scope = identity.tenantId
    if (!scope || scope === c.env.PLATFORM_ORG_ID) return { kind: 'platform' }
    return { kind: 'service', orgId: scope }
  }
  const workosUserId = await workosUserIdOf(c)
  if (!workosUserId || !c.env.WORKOS_API_KEY) return null
  const memberships = await listUserOrgMemberships(c.env.WORKOS_API_KEY, workosUserId)
  const roles = new Map<string, AccountRole>()
  for (const m of memberships) roles.set(m.organization_id, workosSlugToAccountRole(m.role?.slug))
  const platformRole = c.env.PLATFORM_ORG_ID ? roles.get(c.env.PLATFORM_ORG_ID) : undefined
  if (platformRole && WRITE_ROLES.has(platformRole)) return { kind: 'platform' }
  return { kind: 'user', workosUserId, roles }
}

/** The legacy escape hatch: LEGACY_OPEN_WORKOS_ROUTES=1 restores the old unauthenticated routes. */
export function legacyOpenRoutes(env: Env): boolean {
  return env.LEGACY_OPEN_WORKOS_ROUTES === '1'
}

/**
 * Allow the request to read (`member`) or change (`admin`) organization `orgId`,
 * or return the 401/403 Response to send instead.
 */
export async function requireOrgAccess(c: C, orgId: string, need: 'member' | 'admin'): Promise<Response | null> {
  const caller = await resolveCaller(c)
  if (!caller) return errorResponse(c, 401, ErrorCode.Unauthorized, 'Authentication required')
  if (caller.kind === 'platform') return null
  if (caller.kind === 'service') {
    return caller.orgId === orgId ? null : errorResponse(c, 403, ErrorCode.Forbidden, 'This key is scoped to another organization')
  }
  const role = caller.roles.get(orgId)
  if (!role) return errorResponse(c, 403, ErrorCode.Forbidden, 'Not a member of this organization')
  if (need === 'admin' && !WRITE_ROLES.has(role)) return errorResponse(c, 403, ErrorCode.Forbidden, 'Requires an owner or admin of this organization')
  return null
}

/** Allow platform callers only (FGA administration). */
export async function requirePlatform(c: C): Promise<Response | null> {
  const caller = await resolveCaller(c)
  if (!caller) return errorResponse(c, 401, ErrorCode.Unauthorized, 'Authentication required')
  return caller.kind === 'platform' ? null : errorResponse(c, 403, ErrorCode.Forbidden, 'Requires a platform credential')
}

/**
 * Allow a platform caller, or the person `workosUserId` themself (optionally
 * only as a member of `orgId`). Used by the Pipes routes, which act for one user.
 */
export async function requireSelfOrPlatform(c: C, workosUserId: string, orgId?: string): Promise<Response | null> {
  const caller = await resolveCaller(c)
  if (!caller) return errorResponse(c, 401, ErrorCode.Unauthorized, 'Authentication required')
  if (caller.kind === 'platform') return null
  if (caller.kind === 'user' && caller.workosUserId === workosUserId && (!orgId || caller.roles.has(orgId))) return null
  return errorResponse(c, 403, ErrorCode.Forbidden, 'Not allowed for this user')
}
