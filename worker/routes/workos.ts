/**
 * WorkOS route module — org management, admin portal, FGA, vault, pipes, actions, directory sync webhooks.
 * Extracted from worker/index.ts (Phase 10).
 */
import { Hono } from 'hono'
import type { Env, Variables } from '../types'
import type { IdentityStub } from '../../src/server/do/Identity'
import { errorResponse, ErrorCode, errorMessage } from '../../src/sdk/errors'
import { extractWorkOSUserFromJWT } from '../middleware/tenant'
import {
  createWorkOSOrganization,
  createWorkOSMembership,
  listUserOrgMemberships,
  listOrgMembers,
  sendOrgInvitation,
  fetchOrgInfo,
  fetchWorkOSUser,
  extractGitHubId,
  fetchGitHubUsername,
  updateWorkOSUser,
  updateOrgMembership,
  deleteOrgMembership,
  fetchWorkOSUserProfile,
  listOrgInvitations,
  getInvitation,
  revokeInvitation,
  findOwnedOrg,
} from '../../src/sdk/workos/upstream'
import type { WorkOSOrganizationMembership, WorkOSInvitation } from '../../src/sdk/workos/upstream'
import { workosSlugToAccountRole, accountRoleToWorkosSlug } from '../../src/sdk/workos/roles'
import {
  ensureSCIMTables,
  handleDSyncUserCreated,
  handleDSyncUserUpdated,
  handleDSyncUserDeleted,
  handleDSyncGroupCreated,
  handleDSyncGroupUpdated,
  handleDSyncGroupDeleted,
  handleDSyncGroupUserAdded,
  handleDSyncGroupUserRemoved,
  getAdminPortalUrl,
} from '../../src/sdk/workos/scim'
import type { DSyncEvent, DSyncUser, DSyncGroup, DSyncGroupMembership } from '../../src/sdk/workos/scim'
import { FGA_RESOURCE_TYPES, defineResourceTypes, checkPermission, shareResource, unshareResource, listAccessible, entityTypeToFGA } from '../../src/sdk/workos/fga'
import type { FGACheckRequest, FGARelation } from '../../src/sdk/workos/fga'
import {
  createVaultSecret,
  getVaultSecret,
  readVaultSecretValue,
  listVaultSecrets,
  updateVaultSecret,
  deleteVaultSecret,
  resolveSecret,
  resolveSecrets,
  interpolateSecrets,
} from '../../src/sdk/workos/vault'
import type { CreateSecretOptions, UpdateSecretOptions } from '../../src/sdk/workos/vault'
import { PIPES_PROVIDERS, getAccessToken, listConnections, getConnection, disconnectConnection, getConnectionStatus } from '../../src/sdk/workos/pipes'
import type { PipesProvider } from '../../src/sdk/workos/pipes'

const app = new Hono<{ Bindings: Env; Variables: Variables }>()

// ── Helper ──────────────────────────────────────────────────────────────────

/**
 * Resolve the WorkOS user ID from the authenticated identity.
 */
async function resolveWorkOSUserId(stub: IdentityStub, identityId: string): Promise<string | null> {
  const stored = await stub.oauthStorageOp({ op: 'get', key: `identity:${identityId}` })
  const record = stored.value as { workosUserId?: string } | null
  return record?.workosUserId ?? null
}

// ── Server-to-server org-token auth ───────────────────────────────────────
// Credential validation for `/api/orgs/*` is owned by the upstream
// `authenticateRequest` middleware (worker/middleware/auth.ts) which delegates
// to AuthBroker. The broker resolves three credential shapes for these routes:
//   1. WorkOS `sk_*` service token (SaaS.Studio dashboard's IDORGAI_ORG_TOKEN)
//      → AuthBroker.identify → DO `validateApiKey` miss → falls back to
//      `validateWorkOSKey` (wired in middleware) → service Identity.
//   2. id.org.ai-issued `oai_*` / `hly_sk_*` / `ses_*` → standard DO path.
//   3. Forwarded WorkOS JWT cookie → tenant resolver populates resolvedIdentityId.
// The WorkOS secret stays server-side (ADR 0015) — never returned to/from the
// dashboard.
//
// This handler still resolves the caller's WorkOS user id when callable —
// `POST /api/orgs` + `GET /api/orgs` need it to attribute the new/listed orgs.
// For a service-token caller (no WorkOS user id), endpoints either accept an
// explicit `owner_sub` (POST /api/orgs) or are not user-scoped (members CRUD).

interface OrgAuthResult {
  ok: boolean
  /** WorkOS user id when resolvable (JWT/identity paths); absent for the sk_ service token. */
  workosUserId?: string
}

/**
 * Surface the auth state populated by `authenticateRequest`, plus a final
 * forwarded-JWT fallback for direct browser calls that bypass the cookie
 * path. The middleware has already rejected (401) any presented-but-invalid
 * credential before we get here.
 */
async function authenticateOrgRequest(c: any): Promise<OrgAuthResult> {
  // Authenticated by upstream middleware (sk_* via WorkOS, oai_*/hly_sk_*/ses_*
  // via DO, or cookie via tenant resolver).
  const auth = c.get('auth')
  if (auth?.authenticated && auth.identityId) {
    const stub = c.get('identityStub') as IdentityStub | undefined
    const workosUserId = stub ? (await resolveWorkOSUserId(stub, auth.identityId)) ?? undefined : undefined
    return { ok: true, workosUserId }
  }

  // Forwarded browser WorkOS JWT — kept for legacy direct user calls. The
  // standard middleware path doesn't see WorkOS-signed JWTs unless tenant
  // resolution already mapped them; this is the last-ditch resolver.
  const jwt = await extractWorkOSUserFromJWT(c.req.raw, c.env)
  if (jwt?.sub) return { ok: true, workosUserId: jwt.sub }

  return { ok: false }
}

// ── Member DTO ────────────────────────────────────────────────────────────
// Field names align with saas.studio `membership.ts#dtoToMember`, which reads:
//   id | sub, name | display_name | email | sub, email, role, status, joined_at
// A member row is built from a WorkOS membership (active) hydrated with the
// user's email/name; a pending row is built from a WorkOS invitation.

interface MemberDto {
  id: string
  sub: string
  name: string
  display_name: string
  email: string
  role: string
  status: 'active' | 'pending'
  joined_at: string
}

/** Build an active-member DTO from a membership + (optional) hydrated profile. */
function activeMemberDto(
  m: WorkOSOrganizationMembership,
  profile: { email?: string; first_name?: string; last_name?: string } | null,
): MemberDto {
  const email = profile?.email ?? ''
  const fullName = [profile?.first_name, profile?.last_name].filter(Boolean).join(' ').trim()
  const display = fullName || email || m.user_id
  return {
    // The dashboard keys members by their id.org.ai sub once accepted. We use
    // the WorkOS membership id as the stable handle for role-change / remove
    // (it's what PATCH/DELETE target), and expose the user id as `sub`.
    id: m.id,
    sub: m.user_id,
    name: display,
    display_name: display,
    email,
    role: workosSlugToAccountRole(m.role?.slug),
    status: 'active',
    joined_at: m.created_at,
  }
}

/** Build a pending-member DTO from a WorkOS invitation. */
function pendingMemberDto(inv: WorkOSInvitation): MemberDto {
  const local = inv.email.split('@')[0] ?? inv.email
  return {
    // Pending rows are addressed by the invitation id for rescind (DELETE).
    id: inv.id,
    sub: '',
    name: local,
    display_name: local,
    email: inv.email,
    role: workosSlugToAccountRole(inv.role?.slug),
    status: 'pending',
    joined_at: inv.created_at,
  }
}

// ── Organization Management Endpoints ────────────────────────────────────
// CRUD for organizations. Uses WorkOS Organization + Membership APIs.
// Requires L1+ auth. The authenticated user's WorkOS user ID is resolved
// from the identity record stored in the DO.

// POST /api/orgs — Create (or resolve) an organization.
//
// Two callers:
//   - SaaS.Studio account auto-create: `{ name, owner_sub }` with the server
//     token. Idempotent — if `owner_sub` already owns an org, return it (200);
//     otherwise create it and add `owner_sub` as owner (201). Matches
//     `_data/account.ts#idorgaiEnsureAccount`.
//   - A signed-in user creating their own org: `{ name }`, owner resolved from
//     the caller's identity/JWT (legacy path, returns 201).
app.post('/api/orgs', async (c) => {
  if (!c.env.WORKOS_API_KEY) {
    return errorResponse(c, 503, ErrorCode.ServerError, 'WorkOS not configured')
  }

  const orgAuth = await authenticateOrgRequest(c)
  if (!orgAuth.ok) {
    return errorResponse(c, 401, ErrorCode.Unauthorized, 'Authentication required')
  }

  const body = (await c.req.json().catch(() => ({}))) as { name?: string; owner_sub?: string }
  if (!body.name || body.name.trim().length === 0) {
    return errorResponse(c, 400, ErrorCode.InvalidRequest, 'name is required')
  }

  // Owner: explicit `owner_sub` (server-token path) wins, else the caller.
  const ownerUserId = body.owner_sub || orgAuth.workosUserId
  if (!ownerUserId) {
    return errorResponse(c, 400, ErrorCode.InvalidRequest, 'owner_sub is required when not acting as a user')
  }

  // Idempotency: if the owner already has an org, return it (200, created=false).
  const existing = await findOwnedOrg(c.env.WORKOS_API_KEY, ownerUserId)
  if (existing) {
    const info = await fetchOrgInfo(c.env.WORKOS_API_KEY, existing.orgId)
    return c.json(
      {
        id: existing.orgId,
        name: info?.name ?? body.name.trim(),
        owner_sub: ownerUserId,
        workosOrgId: existing.orgId,
        created: false,
      },
      200,
    )
  }

  // 1. Create the organization in WorkOS.
  const org = await createWorkOSOrganization(c.env.WORKOS_API_KEY, body.name.trim())
  if (!org) {
    return errorResponse(c, 500, ErrorCode.ServerError, 'Failed to create organization in WorkOS')
  }

  // 2. Add the owner as the `owner`-role member (ADR 0021 top role).
  const membershipCreated = await createWorkOSMembership(c.env.WORKOS_API_KEY, ownerUserId, org.id, 'owner')
  if (!membershipCreated) {
    return errorResponse(c, 500, ErrorCode.ServerError, 'Organization created but failed to add membership')
  }

  return c.json(
    {
      id: org.id,
      name: org.name,
      owner_sub: ownerUserId,
      workosOrgId: org.id,
      created: true,
    },
    201,
  )
})

// GET /api/orgs — List the authenticated user's organizations
app.get('/api/orgs', async (c) => {
  if (!c.env.WORKOS_API_KEY) {
    return errorResponse(c, 503, ErrorCode.ServerError, 'WorkOS not configured')
  }

  // Resolve WorkOS user ID: standard auth (ses_*/API key) or JWT fallback
  let workosUserId: string | null = null
  const auth = c.get('auth')
  if (auth.authenticated && auth.identityId) {
    const stub = c.get('identityStub')
    if (stub) {
      workosUserId = await resolveWorkOSUserId(stub, auth.identityId)
    }
  }
  if (!workosUserId) {
    const jwt = await extractWorkOSUserFromJWT(c.req.raw, c.env)
    if (jwt?.sub) workosUserId = jwt.sub
  }
  if (!workosUserId) {
    return errorResponse(c, 401, ErrorCode.Unauthorized, 'Authentication required')
  }

  const memberships = await listUserOrgMemberships(c.env.WORKOS_API_KEY, workosUserId)

  // Fetch org details for each membership
  const orgs = await Promise.all(
    memberships.map(async (m) => {
      const orgInfo = await fetchOrgInfo(c.env.WORKOS_API_KEY!, m.organization_id)
      return {
        id: m.organization_id,
        name: orgInfo?.name ?? m.organization_id,
        role: m.role?.slug ?? 'member',
        domains: orgInfo?.domains ?? [],
      }
    }),
  )

  return c.json({ organizations: orgs })
})

// GET /api/orgs/:id/members — List members of an organization.
//
// Returns active memberships (hydrated with email + name from WorkOS) plus
// pending invitations as `status:'pending'` rows. Field names align with
// saas.studio `membership.ts#dtoToMember`.
app.get('/api/orgs/:id/members', async (c) => {
  if (!c.env.WORKOS_API_KEY) {
    return errorResponse(c, 503, ErrorCode.ServerError, 'WorkOS not configured')
  }

  const orgAuth = await authenticateOrgRequest(c)
  if (!orgAuth.ok) {
    return errorResponse(c, 401, ErrorCode.Unauthorized, 'Authentication required')
  }

  const orgId = c.req.param('id')
  const apiKey = c.env.WORKOS_API_KEY

  // Active memberships + pending invitations, fetched in parallel.
  const [memberships, invitations] = await Promise.all([
    listOrgMembers(apiKey, orgId),
    listOrgInvitations(apiKey, orgId),
  ])

  // Hydrate each membership with the user's email/name. De-duplicate the user
  // lookups so two memberships for the same user only fetch once.
  const uniqueUserIds = [...new Set(memberships.map((m) => m.user_id))]
  const profiles = new Map(
    await Promise.all(
      uniqueUserIds.map(async (uid) => [uid, await fetchWorkOSUserProfile(apiKey, uid)] as const),
    ),
  )

  const activeRows = memberships.map((m) => activeMemberDto(m, profiles.get(m.user_id) ?? null))
  const pendingRows = invitations.map(pendingMemberDto)

  return c.json({ members: [...activeRows, ...pendingRows] })
})

// PATCH /api/orgs/:id/members/:membershipId — Change a member's role.
// Wraps WorkOS PUT /user_management/organization_memberships/:id { role_slug }.
app.patch('/api/orgs/:id/members/:membershipId', async (c) => {
  if (!c.env.WORKOS_API_KEY) {
    return errorResponse(c, 503, ErrorCode.ServerError, 'WorkOS not configured')
  }

  const orgAuth = await authenticateOrgRequest(c)
  if (!orgAuth.ok) {
    return errorResponse(c, 401, ErrorCode.Unauthorized, 'Authentication required')
  }

  const membershipId = c.req.param('membershipId')
  const body = (await c.req.json().catch(() => ({}))) as { role?: string }
  if (!body.role) {
    return errorResponse(c, 400, ErrorCode.InvalidRequest, 'role is required')
  }

  const roleSlug = accountRoleToWorkosSlug(body.role)
  const updated = await updateOrgMembership(c.env.WORKOS_API_KEY, membershipId, roleSlug)
  if (!updated) {
    return errorResponse(c, 502, ErrorCode.ServerError, 'Failed to update membership role')
  }

  return c.json(activeMemberDto(updated, null))
})

// DELETE /api/orgs/:id/members/:membershipId — Remove a member or rescind a
// pending invite. WorkOS membership ids (`om_*`) and invitation ids
// (`invitation_*`) are disjoint, so the path is the same; we detect which by
// prefix and route to DELETE membership vs revoke invitation.
app.delete('/api/orgs/:id/members/:membershipId', async (c) => {
  if (!c.env.WORKOS_API_KEY) {
    return errorResponse(c, 503, ErrorCode.ServerError, 'WorkOS not configured')
  }

  const orgAuth = await authenticateOrgRequest(c)
  if (!orgAuth.ok) {
    return errorResponse(c, 401, ErrorCode.Unauthorized, 'Authentication required')
  }

  const id = c.req.param('membershipId')
  const apiKey = c.env.WORKOS_API_KEY

  // Invitation id → rescind. Membership id → delete. We branch on the WorkOS
  // id prefix; for ambiguous ids we look the invitation up first.
  const looksLikeInvitation = id.startsWith('invitation_')
  let ok: boolean
  if (looksLikeInvitation) {
    ok = await revokeInvitation(apiKey, id)
  } else if (id.startsWith('om_') || id.startsWith('member_')) {
    ok = await deleteOrgMembership(apiKey, id)
  } else {
    // Unknown prefix: probe the invitation API, else treat as a membership.
    const inv = await getInvitation(apiKey, id)
    ok = inv ? await revokeInvitation(apiKey, id) : await deleteOrgMembership(apiKey, id)
  }

  if (!ok) {
    return errorResponse(c, 502, ErrorCode.ServerError, 'Failed to remove member')
  }

  return c.json({ ok: true })
})

// POST /api/orgs/:id/invites (+ /invitations alias) — Invite a Person.
//
// The SaaS.Studio dashboard posts `{ email, role }` to `/invites` and parses
// the response as a member DTO (`membership.ts#idorgaiInviteMember` →
// `dtoToMember`). We map the Account role → WorkOS slug, send the invitation,
// then return a pending member row. `/invitations` is kept as a back-compat
// alias for the legacy `{ ok }` shape callers.
async function handleInvite(c: any): Promise<Response> {
  if (!c.env.WORKOS_API_KEY) {
    return errorResponse(c, 503, ErrorCode.ServerError, 'WorkOS not configured')
  }

  const orgAuth = await authenticateOrgRequest(c)
  if (!orgAuth.ok) {
    return errorResponse(c, 401, ErrorCode.Unauthorized, 'Authentication required')
  }

  const orgId = c.req.param('id')
  const body = (await c.req.json().catch(() => ({}))) as { email?: string; role?: string }
  if (!body.email) {
    return errorResponse(c, 400, ErrorCode.InvalidRequest, 'email is required')
  }

  const email = body.email.trim().toLowerCase()
  const roleSlug = accountRoleToWorkosSlug(body.role)
  const sent = await sendOrgInvitation(c.env.WORKOS_API_KEY, email, orgId, roleSlug)
  if (!sent) {
    return errorResponse(c, 502, ErrorCode.ServerError, 'Failed to send invitation')
  }

  // Reflect the new pending invite back as a member DTO. We don't have the
  // WorkOS invitation id from `sendOrgInvitation` (it returns a boolean), so
  // look it up from the org's pending invitations by email.
  const invitations = await listOrgInvitations(c.env.WORKOS_API_KEY, orgId)
  const created = invitations.find((inv) => inv.email.toLowerCase() === email)
  if (created) {
    return c.json(pendingMemberDto(created), 201)
  }
  // Fallback: synthesise a pending row (id keyed by email) if the lookup
  // raced or returned nothing — the next list call reconciles the real id.
  const local = email.split('@')[0] ?? email
  return c.json(
    {
      id: `invite:${email}`,
      sub: '',
      name: local,
      display_name: local,
      email,
      role: workosSlugToAccountRole(roleSlug),
      status: 'pending',
      joined_at: new Date().toISOString(),
    },
    201,
  )
}

app.post('/api/orgs/:id/invites', handleInvite)
app.post('/api/orgs/:id/invitations', handleInvite)


// ── WorkOS Directory Sync Webhooks ────────────────────────────────────────
// POST /webhooks/workos — receive WorkOS Directory Sync (SCIM) events.
// No auth middleware — WorkOS authenticates via webhook signature.

app.post('/webhooks/workos', async (c) => {
  if (!c.env.DB) return c.json({ error: 'SCIM not configured' }, 503)

  const rawBody = await c.req.text()
  let body: DSyncEvent

  try {
    body = JSON.parse(rawBody) as DSyncEvent
  } catch {
    return c.json({ error: 'Invalid JSON payload' }, 400)
  }

  if (!body.event || !body.data) {
    return c.json({ error: 'Invalid webhook payload' }, 400)
  }

  // Verify webhook signature when WORKOS_WEBHOOK_SECRET is configured.
  // WorkOS signs webhooks with HMAC-SHA256 using the webhook signing secret.
  if (c.env.WORKOS_WEBHOOK_SECRET) {
    const signature = c.req.header('workos-signature')
    if (!signature) {
      return c.json({ error: 'Missing webhook signature' }, 401)
    }

    const isValid = await verifyWorkOSWebhookSignature(rawBody, signature, c.env.WORKOS_WEBHOOK_SECRET)
    if (!isValid) {
      return c.json({ error: 'Invalid webhook signature' }, 401)
    }
  }

  try {
    await ensureSCIMTables(c.env.DB)

    switch (body.event) {
      case 'dsync.user.created': {
        const result = await handleDSyncUserCreated(body.data as DSyncUser, c.env.DB)
        return c.json({ ok: true, ...result })
      }
      case 'dsync.user.updated': {
        const result = await handleDSyncUserUpdated(body.data as DSyncUser, c.env.DB)
        return c.json({ ok: true, ...result })
      }
      case 'dsync.user.deleted': {
        const result = await handleDSyncUserDeleted(body.data as DSyncUser, c.env.DB)
        return c.json({ ok: true, ...result })
      }
      case 'dsync.group.created': {
        const result = await handleDSyncGroupCreated(body.data as DSyncGroup, c.env.DB)
        return c.json({ ok: true, ...result })
      }
      case 'dsync.group.updated': {
        const result = await handleDSyncGroupUpdated(body.data as DSyncGroup, c.env.DB)
        return c.json({ ok: true, ...result })
      }
      case 'dsync.group.deleted': {
        const result = await handleDSyncGroupDeleted(body.data as DSyncGroup, c.env.DB)
        return c.json({ ok: true, ...result })
      }
      case 'dsync.group.user_added': {
        const result = await handleDSyncGroupUserAdded(body.data as DSyncGroupMembership, c.env.DB)
        return c.json({ ok: true, ...result })
      }
      case 'dsync.group.user_removed': {
        const result = await handleDSyncGroupUserRemoved(body.data as DSyncGroupMembership, c.env.DB)
        return c.json({ ok: true, ...result })
      }
      default:
        return c.json({ ok: true, skipped: true, event: body.event })
    }
  } catch (err: unknown) {
    console.error(`[webhooks/workos] Error handling ${body.event}:`, err)
    return c.json({ error: 'Internal error processing webhook' }, 500)
  }
})

// ── WorkOS Admin Portal ──────────────────────────────────────────────────
// GET /admin-portal — Generate a WorkOS Admin Portal link for SCIM/SSO setup.
// Enterprise IT admins use this to self-service their directory connection.

app.get('/admin-portal', async (c) => {
  const orgId = c.req.query('organization_id')
  if (!orgId) {
    return c.json({ error: 'organization_id query param required' }, 400)
  }

  if (!c.env.WORKOS_API_KEY) {
    return errorResponse(c, 503, ErrorCode.ServiceUnavailable, 'WorkOS is not configured')
  }

  try {
    const result = await getAdminPortalUrl(orgId, c.env.WORKOS_API_KEY)
    return c.json(result)
  } catch (err: unknown) {
    return errorResponse(c, 500, ErrorCode.ServerError, errorMessage(err))
  }
})

// ── FGA (Fine-Grained Authorization) Endpoints ──────────────────────────────
// Entity-level authorization using WorkOS FGA (Zanzibar-style).
// Manages resource types, permission checks, and cross-tenant sharing.

// POST /fga/setup — Initialize FGA resource types (admin only, run once)
app.post('/fga/setup', async (c) => {
  if (!c.env.WORKOS_API_KEY) return c.json({ error: 'WorkOS not configured' }, 503)
  await defineResourceTypes(c.env.WORKOS_API_KEY)
  return c.json({ ok: true, resourceTypes: FGA_RESOURCE_TYPES.length })
})

// POST /fga/check — Check a permission
app.post('/fga/check', async (c) => {
  if (!c.env.WORKOS_API_KEY) return c.json({ error: 'WorkOS not configured' }, 503)
  const body = (await c.req.json()) as FGACheckRequest
  const authorized = await checkPermission(c.env.WORKOS_API_KEY, body)
  return c.json({ authorized })
})

// POST /fga/share — Share a resource cross-tenant
app.post('/fga/share', async (c) => {
  if (!c.env.WORKOS_API_KEY) return c.json({ error: 'WorkOS not configured' }, 503)
  const body = (await c.req.json()) as { resourceType: string; resourceId: string; targetTenant: string; relation?: string }
  const fgaType = entityTypeToFGA(body.resourceType)
  if (!fgaType) return c.json({ error: `Unknown resource type: ${body.resourceType}` }, 400)
  await shareResource(c.env.WORKOS_API_KEY, fgaType, body.resourceId, body.targetTenant, (body.relation as FGARelation) || 'viewer')
  return c.json({ ok: true })
})

// DELETE /fga/share — Revoke cross-tenant sharing
app.delete('/fga/share', async (c) => {
  if (!c.env.WORKOS_API_KEY) return c.json({ error: 'WorkOS not configured' }, 503)
  const body = (await c.req.json()) as { resourceType: string; resourceId: string; targetTenant: string; relation?: string }
  const fgaType = entityTypeToFGA(body.resourceType)
  if (!fgaType) return c.json({ error: `Unknown resource type: ${body.resourceType}` }, 400)
  await unshareResource(c.env.WORKOS_API_KEY, fgaType, body.resourceId, body.targetTenant, (body.relation as FGARelation) || 'viewer')
  return c.json({ ok: true })
})

// GET /fga/accessible — List resources accessible by a user
app.get('/fga/accessible', async (c) => {
  if (!c.env.WORKOS_API_KEY) return c.json({ error: 'WorkOS not configured' }, 503)
  const resourceType = c.req.query('type')
  const userId = c.req.query('user')
  if (!resourceType || !userId) return c.json({ error: 'type and user query params required' }, 400)
  const fgaType = entityTypeToFGA(resourceType)
  if (!fgaType) return c.json({ error: `Unknown resource type: ${resourceType}` }, 400)
  const resources = await listAccessible(c.env.WORKOS_API_KEY, fgaType, userId)
  return c.json({ resources })
})

// ── WorkOS Vault — Secret Management ────────────────────────────────────────
// CRUD for encrypted secrets stored in WorkOS Vault.
// Secrets are used by code functions, workflows, integrations, and API proxies.
// The /vault/resolve endpoint does NOT expose actual secret values in the API
// response — values are only injected by runtime (code execution, workflows).

// POST /vault/secrets — Create a new secret
app.post('/vault/secrets', async (c) => {
  if (!c.env.WORKOS_API_KEY) return c.json({ error: 'WorkOS not configured' }, 503)
  const body = await c.req.json<CreateSecretOptions>()
  if (!body.name || !body.value) {
    return c.json({ error: 'name and value are required' }, 400)
  }
  const secret = await createVaultSecret(c.env.WORKOS_API_KEY, body)
  return c.json(secret, 201)
})

// GET /vault/secrets — List all secrets (metadata only)
app.get('/vault/secrets', async (c) => {
  if (!c.env.WORKOS_API_KEY) return c.json({ error: 'WorkOS not configured' }, 503)
  const env = c.req.query('environment')
  const limit = c.req.query('limit')
  const after = c.req.query('after')
  const result = await listVaultSecrets(c.env.WORKOS_API_KEY, {
    environment: env,
    limit: limit ? parseInt(limit) : undefined,
    after,
  })
  return c.json(result)
})

// GET /vault/secrets/:id — Get secret metadata (no value)
app.get('/vault/secrets/:id', async (c) => {
  if (!c.env.WORKOS_API_KEY) return c.json({ error: 'WorkOS not configured' }, 503)
  const id = c.req.param('id')
  try {
    const secret = await getVaultSecret(c.env.WORKOS_API_KEY, id)
    return c.json(secret)
  } catch {
    return c.json({ error: 'Secret not found' }, 404)
  }
})

// GET /vault/secrets/:id/reveal — Get secret with decrypted value
app.get('/vault/secrets/:id/reveal', async (c) => {
  if (!c.env.WORKOS_API_KEY) return c.json({ error: 'WorkOS not configured' }, 503)
  const id = c.req.param('id')
  try {
    const secret = await readVaultSecretValue(c.env.WORKOS_API_KEY, id)
    return c.json(secret)
  } catch {
    return c.json({ error: 'Secret not found or cannot be revealed' }, 404)
  }
})

// PUT /vault/secrets/:id — Update a secret
app.put('/vault/secrets/:id', async (c) => {
  if (!c.env.WORKOS_API_KEY) return c.json({ error: 'WorkOS not configured' }, 503)
  const id = c.req.param('id')
  const body = await c.req.json<UpdateSecretOptions>()
  const secret = await updateVaultSecret(c.env.WORKOS_API_KEY, id, body)
  return c.json(secret)
})

// DELETE /vault/secrets/:id — Delete a secret
app.delete('/vault/secrets/:id', async (c) => {
  if (!c.env.WORKOS_API_KEY) return c.json({ error: 'WorkOS not configured' }, 503)
  const id = c.req.param('id')
  await deleteVaultSecret(c.env.WORKOS_API_KEY, id)
  return c.json({ ok: true })
})

// POST /vault/resolve — Resolve a secret by name (runtime API)
// NOTE: This endpoint does NOT expose actual secret values in the response.
// Values are only injected into runtime contexts by the code execution worker
// and workflow engine, which call resolveSecret() directly.
app.post('/vault/resolve', async (c) => {
  if (!c.env.WORKOS_API_KEY) return c.json({ error: 'WorkOS not configured' }, 503)
  const body = await c.req.json<{ name?: string; names?: string[]; template?: string }>()

  // Single secret resolution
  if (body.name) {
    try {
      await resolveSecret(c.env.WORKOS_API_KEY, body.name)
      return c.json({ name: body.name, resolved: true })
      // NOTE: We return resolved:true but NOT the value in the response
      // The value should only be injected into runtime contexts, not exposed via API
    } catch {
      return c.json({ name: body.name, resolved: false, error: 'Secret not found' }, 404)
    }
  }

  // Batch resolution
  if (body.names) {
    const resolved = await resolveSecrets(c.env.WORKOS_API_KEY, body.names)
    return c.json({
      resolved: Object.keys(resolved),
      missing: body.names.filter((n) => !(n in resolved)),
    })
  }

  // Template interpolation
  if (body.template) {
    await interpolateSecrets(c.env.WORKOS_API_KEY, body.template)
    return c.json({ interpolated: true })
    // Again, don't return the actual interpolated string via API
  }

  return c.json({ error: 'Provide name, names, or template' }, 400)
})

// ── WorkOS Pipes — Managed OAuth Connections ─────────────────────────────────
// Replaces manual OAuth token management for third-party providers (Slack, GitHub, etc.).
// WorkOS handles the OAuth flow, token storage, and automatic refresh.

// POST /pipes/token — Get a fresh access token for a provider
app.post('/pipes/token', async (c) => {
  if (!c.env.WORKOS_API_KEY) return c.json({ error: 'WorkOS not configured' }, 503)
  const body = await c.req.json<{ provider: string; userId: string; organizationId?: string }>()
  if (!body.provider || !body.userId) {
    return c.json({ error: 'provider and userId are required' }, 400)
  }
  if (!PIPES_PROVIDERS.includes(body.provider as PipesProvider)) {
    return c.json({ error: `Unsupported provider: ${body.provider}. Supported: ${PIPES_PROVIDERS.join(', ')}` }, 400)
  }
  const token = await getAccessToken(c.env.WORKOS_API_KEY, body.provider as PipesProvider, body.userId, body.organizationId)
  return c.json(token)
})

// GET /pipes/connections — List all connections
app.get('/pipes/connections', async (c) => {
  if (!c.env.WORKOS_API_KEY) return c.json({ error: 'WorkOS not configured' }, 503)
  const userId = c.req.query('user_id')
  const orgId = c.req.query('organization_id')
  const provider = c.req.query('provider')
  const result = await listConnections(c.env.WORKOS_API_KEY, {
    userId: userId || undefined,
    organizationId: orgId || undefined,
    provider: (provider as PipesProvider) || undefined,
  })
  return c.json(result)
})

// GET /pipes/connections/:id — Get a specific connection
app.get('/pipes/connections/:id', async (c) => {
  if (!c.env.WORKOS_API_KEY) return c.json({ error: 'WorkOS not configured' }, 503)
  try {
    const connection = await getConnection(c.env.WORKOS_API_KEY, c.req.param('id'))
    return c.json(connection)
  } catch {
    return c.json({ error: 'Connection not found' }, 404)
  }
})

// DELETE /pipes/connections/:id — Disconnect a provider
app.delete('/pipes/connections/:id', async (c) => {
  if (!c.env.WORKOS_API_KEY) return c.json({ error: 'WorkOS not configured' }, 503)
  await disconnectConnection(c.env.WORKOS_API_KEY, c.req.param('id'))
  return c.json({ ok: true })
})

// GET /pipes/status — Get connection status for all providers
app.get('/pipes/status', async (c) => {
  if (!c.env.WORKOS_API_KEY) return c.json({ error: 'WorkOS not configured' }, 503)
  const userId = c.req.query('user_id')
  const orgId = c.req.query('organization_id')
  if (!userId) return c.json({ error: 'user_id query param required' }, 400)
  const status = await getConnectionStatus(c.env.WORKOS_API_KEY, userId, orgId || undefined)
  return c.json({ providers: status })
})

// ── WorkOS Actions ────────────────────────────────────────────────────────
// Synchronous hooks called by WorkOS during authentication/registration.
// These run BEFORE the user is redirected, so any user updates (external_id,
// metadata) will be reflected in the WorkOS JWT template on this same request.

/**
 * Verify WorkOS action request signature (HMAC-SHA256).
 * Header format: WorkOS-Signature: t=<timestamp_ms>,v1=<hex_signature>
 */
async function verifyActionSignature(rawBody: string, sigHeader: string, secret: string, toleranceMs = 300_000): Promise<boolean> {
  const parts = Object.fromEntries(
    sigHeader
      .split(',')
      .map((p) => p.split('='))
      .map(([k, ...v]) => [k, v.join('=')]),
  )
  const timestamp = parts['t']
  const signature = parts['v1']
  if (!timestamp || !signature) return false

  // Replay protection
  if (Math.abs(Date.now() - Number(timestamp)) > toleranceMs) return false

  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  const mac = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${timestamp}.${rawBody}`))
  const expected = Array.from(new Uint8Array(mac))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')

  return expected === signature
}

/**
 * Sign a WorkOS action response (HMAC-SHA256).
 * Returns the full response envelope with signature.
 */
async function signActionResponse(
  type: 'authentication' | 'user_registration',
  verdict: 'Allow' | 'Deny',
  secret: string,
  errorMessage?: string,
): Promise<object> {
  const timestamp = Date.now()
  const payload = { timestamp, verdict, error_message: errorMessage ?? null }
  const payloadJson = JSON.stringify(payload)

  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  const mac = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${timestamp}.${payloadJson}`))
  const signature = Array.from(new Uint8Array(mac))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')

  return { object: `${type}_action_response`, payload, signature }
}

/**
 * Authentication Action — runs after user authenticates, before redirect.
 * Enriches the WorkOS user with GitHub numeric ID as external_id + metadata
 * so it's available in JWT templates on this same authentication request.
 */
app.post('/actions/authentication', async (c) => {
  const secret = c.env.WORKOS_ACTIONS_SECRET
  const apiKey = c.env.WORKOS_API_KEY

  // WorkOS requires a valid action response format — errorResponse() returns
  // standard JSON which WorkOS can't parse, causing "Endpoint response invalid".
  // Always return a signed Allow response; log errors for debugging.
  if (!secret) {
    console.error('[actions/authentication] WORKOS_ACTIONS_SECRET not configured')
    return c.json({ object: 'authentication_action_response', payload: { timestamp: Date.now(), verdict: 'Allow', error_message: null }, signature: '' })
  }

  const rawBody = await c.req.text()
  const sigHeader = c.req.header('workos-signature') || c.req.header('WorkOS-Signature') || ''

  if (!(await verifyActionSignature(rawBody, sigHeader, secret))) {
    console.error('[actions/authentication] Invalid signature — allowing with fail-open')
    return c.json(await signActionResponse('authentication', 'Allow', secret))
  }

  let action: Record<string, unknown> = {}
  try {
    action = JSON.parse(rawBody)
  } catch {
    console.error('[actions/authentication] Failed to parse body')
    return c.json(await signActionResponse('authentication', 'Allow', secret))
  }
  const userId = (action?.user as Record<string, unknown>)?.id || (action?.userData as Record<string, unknown>)?.id

  // Enrich user with GitHub ID + username if available
  if (apiKey && userId) {
    try {
      const workosUser = await fetchWorkOSUser(apiKey, userId as string)
      if (workosUser) {
        const githubId = extractGitHubId(workosUser)
        if (githubId) {
          const githubUsername = await fetchGitHubUsername(githubId)
          await updateWorkOSUser(apiKey, userId as string, {
            external_id: githubId,
            metadata: {
              github_id: githubId,
              ...(githubUsername ? { github_username: githubUsername } : {}),
            },
          })
        }
      }
    } catch (err) {
      console.error('[actions/authentication] Enrichment failed:', err)
    }
  }

  return c.json(await signActionResponse('authentication', 'Allow', secret))
})

/**
 * User Registration Action — runs after registration, before provisioning.
 * Currently allows all registrations. Can be extended to enforce domain
 * policies, block disposable emails, etc.
 */
app.post('/actions/registration', async (c) => {
  const secret = c.env.WORKOS_ACTIONS_SECRET

  if (!secret) {
    console.error('[actions/registration] WORKOS_ACTIONS_SECRET not configured')
    return c.json({ object: 'user_registration_action_response', payload: { timestamp: Date.now(), verdict: 'Allow', error_message: null }, signature: '' })
  }

  const rawBody = await c.req.text()
  const sigHeader = c.req.header('workos-signature') || c.req.header('WorkOS-Signature') || ''

  if (!(await verifyActionSignature(rawBody, sigHeader, secret))) {
    console.error('[actions/registration] Invalid signature — allowing with fail-open')
    return c.json(await signActionResponse('user_registration', 'Allow', secret))
  }

  return c.json(await signActionResponse('user_registration', 'Allow', secret))
})

// ── WorkOS Webhook Signature Verification ──────────────────────────────────

/**
 * Verify a WorkOS webhook signature.
 *
 * WorkOS sends a `workos-signature` header containing a timestamp and
 * HMAC-SHA256 signature. Format: `t={timestamp}, v1={signature}`
 *
 * Verification:
 *   1. Parse the timestamp and signature from the header
 *   2. Build the signed payload: `{timestamp}.{body}`
 *   3. Compute HMAC-SHA256 with the webhook secret
 *   4. Compare signatures in constant time
 */
async function verifyWorkOSWebhookSignature(body: string, signatureHeader: string, secret: string): Promise<boolean> {
  try {
    // Parse "t={timestamp}, v1={signature}" format
    const parts: Record<string, string> = {}
    for (const part of signatureHeader.split(',')) {
      const [key, ...valueParts] = part.trim().split('=')
      if (key && valueParts.length) {
        parts[key.trim()] = valueParts.join('=').trim()
      }
    }

    const timestamp = parts['t']
    const expectedSig = parts['v1']
    if (!timestamp || !expectedSig) return false

    // Build the signed payload: "{timestamp}.{body}"
    const signedPayload = `${timestamp}.${body}`

    const encoder = new TextEncoder()
    const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
    const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(signedPayload))
    const computedSig = Array.from(new Uint8Array(sig), (b) => b.toString(16).padStart(2, '0')).join('')

    // Constant-time comparison
    if (computedSig.length !== expectedSig.length) return false
    let mismatch = 0
    for (let i = 0; i < computedSig.length; i++) {
      mismatch |= computedSig.charCodeAt(i) ^ expectedSig.charCodeAt(i)
    }
    return mismatch === 0
  } catch {
    return false
  }
}

export { app as workosRoutes }
