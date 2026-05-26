/**
 * WorkOS Organization-Membership management helpers — unit tests.
 *
 * Covers the member-management surface added for the SaaS.Studio Account →
 * Members feature: update/delete membership, list/get/revoke invitations,
 * user-profile hydration, owned-org lookup, and the role-slug ↔ Account-role
 * mapping.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import {
  updateOrgMembership,
  deleteOrgMembership,
  fetchWorkOSUserProfile,
  listOrgInvitations,
  getInvitation,
  revokeInvitation,
  findOwnedOrg,
} from '../src/sdk/workos/upstream'
import {
  workosSlugToAccountRole,
  accountRoleToWorkosSlug,
  isAccountRole,
} from '../src/sdk/workos/roles'

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}
function textResponse(body: string, status = 200): Response {
  return new Response(body, { status })
}

// ============================================================================
// roles mapping
// ============================================================================

describe('role mapping', () => {
  it('isAccountRole recognises the fixed set only', () => {
    expect(isAccountRole('owner')).toBe(true)
    expect(isAccountRole('admin')).toBe(true)
    expect(isAccountRole('editor')).toBe(true)
    expect(isAccountRole('viewer')).toBe(true)
    expect(isAccountRole('member')).toBe(false)
    expect(isAccountRole('superuser')).toBe(false)
  })

  it('maps canonical slugs through unchanged on read', () => {
    expect(workosSlugToAccountRole('owner')).toBe('owner')
    expect(workosSlugToAccountRole('admin')).toBe('admin')
    expect(workosSlugToAccountRole('editor')).toBe('editor')
    expect(workosSlugToAccountRole('viewer')).toBe('viewer')
  })

  it('folds the legacy WorkOS default `member` to editor on read', () => {
    expect(workosSlugToAccountRole('member')).toBe('editor')
  })

  it('folds unknown / nullish slugs to viewer (least privilege)', () => {
    expect(workosSlugToAccountRole('billing-admin')).toBe('viewer')
    expect(workosSlugToAccountRole(undefined)).toBe('viewer')
    expect(workosSlugToAccountRole(null)).toBe('viewer')
    expect(workosSlugToAccountRole('')).toBe('viewer')
  })

  it('maps Account roles to slugs on write, defaulting unknowns to viewer', () => {
    expect(accountRoleToWorkosSlug('owner')).toBe('owner')
    expect(accountRoleToWorkosSlug('admin')).toBe('admin')
    expect(accountRoleToWorkosSlug('editor')).toBe('editor')
    expect(accountRoleToWorkosSlug('viewer')).toBe('viewer')
    expect(accountRoleToWorkosSlug('member')).toBe('viewer')
    expect(accountRoleToWorkosSlug(undefined)).toBe('viewer')
  })
})

// ============================================================================
// updateOrgMembership
// ============================================================================

describe('updateOrgMembership', () => {
  let mockFetch: ReturnType<typeof vi.fn>
  beforeEach(() => {
    mockFetch = vi.fn()
    vi.stubGlobal('fetch', mockFetch)
  })
  afterEach(() => vi.restoreAllMocks())

  it('PUTs to organization_memberships/:id with role_slug', async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ id: 'om_1', user_id: 'user_1', organization_id: 'org_1', role: { slug: 'admin' }, status: 'active', created_at: 't', updated_at: 't' }))

    await updateOrgMembership('sk_test', 'om_1', 'admin')

    const [url, options] = mockFetch.mock.calls[0]
    expect(url).toBe('https://api.workos.com/user_management/organization_memberships/om_1')
    expect(options.method).toBe('PUT')
    expect(options.headers.Authorization).toBe('Bearer sk_test')
    expect(JSON.parse(options.body).role_slug).toBe('admin')
  })

  it('returns the updated membership on success', async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ id: 'om_1', user_id: 'user_1', organization_id: 'org_1', role: { slug: 'editor' }, status: 'active', created_at: 't', updated_at: 't' }))
    const result = await updateOrgMembership('sk_test', 'om_1', 'editor')
    expect(result?.role.slug).toBe('editor')
  })

  it('returns null on non-2xx', async () => {
    mockFetch.mockResolvedValueOnce(textResponse('Not Found', 404))
    expect(await updateOrgMembership('sk_test', 'om_x', 'admin')).toBeNull()
  })

  it('returns null on fetch error', async () => {
    mockFetch.mockRejectedValueOnce(new Error('network'))
    expect(await updateOrgMembership('sk_test', 'om_1', 'admin')).toBeNull()
  })
})

// ============================================================================
// deleteOrgMembership
// ============================================================================

describe('deleteOrgMembership', () => {
  let mockFetch: ReturnType<typeof vi.fn>
  beforeEach(() => {
    mockFetch = vi.fn()
    vi.stubGlobal('fetch', mockFetch)
  })
  afterEach(() => vi.restoreAllMocks())

  it('DELETEs organization_memberships/:id', async () => {
    mockFetch.mockResolvedValueOnce(new Response(null, { status: 204 }))
    const ok = await deleteOrgMembership('sk_test', 'om_1')
    const [url, options] = mockFetch.mock.calls[0]
    expect(url).toBe('https://api.workos.com/user_management/organization_memberships/om_1')
    expect(options.method).toBe('DELETE')
    expect(ok).toBe(true)
  })

  it('treats 404 as success (idempotent)', async () => {
    mockFetch.mockResolvedValueOnce(new Response(null, { status: 404 }))
    expect(await deleteOrgMembership('sk_test', 'om_gone')).toBe(true)
  })

  it('returns false on a real failure', async () => {
    mockFetch.mockResolvedValueOnce(new Response(null, { status: 500 }))
    expect(await deleteOrgMembership('sk_test', 'om_1')).toBe(false)
  })

  it('returns false on fetch error', async () => {
    mockFetch.mockRejectedValueOnce(new Error('network'))
    expect(await deleteOrgMembership('sk_test', 'om_1')).toBe(false)
  })
})

// ============================================================================
// fetchWorkOSUserProfile
// ============================================================================

describe('fetchWorkOSUserProfile', () => {
  let mockFetch: ReturnType<typeof vi.fn>
  beforeEach(() => {
    mockFetch = vi.fn()
    vi.stubGlobal('fetch', mockFetch)
  })
  afterEach(() => vi.restoreAllMocks())

  it('GETs the user and returns email + names', async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ id: 'user_1', email: 'a@b.com', first_name: 'Ada', last_name: 'Lovelace' }))
    const profile = await fetchWorkOSUserProfile('sk_test', 'user_1')
    const [url] = mockFetch.mock.calls[0]
    expect(url).toBe('https://api.workos.com/user_management/users/user_1')
    expect(profile).toMatchObject({ email: 'a@b.com', first_name: 'Ada', last_name: 'Lovelace' })
  })

  it('returns null on non-2xx', async () => {
    mockFetch.mockResolvedValueOnce(textResponse('Not Found', 404))
    expect(await fetchWorkOSUserProfile('sk_test', 'user_x')).toBeNull()
  })

  it('returns null on fetch error', async () => {
    mockFetch.mockRejectedValueOnce(new Error('network'))
    expect(await fetchWorkOSUserProfile('sk_test', 'user_1')).toBeNull()
  })
})

// ============================================================================
// listOrgInvitations
// ============================================================================

describe('listOrgInvitations', () => {
  let mockFetch: ReturnType<typeof vi.fn>
  beforeEach(() => {
    mockFetch = vi.fn()
    vi.stubGlobal('fetch', mockFetch)
  })
  afterEach(() => vi.restoreAllMocks())

  it('GETs invitations scoped to the organization', async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ data: [] }))
    await listOrgInvitations('sk_test', 'org_xyz')
    const [url, options] = mockFetch.mock.calls[0]
    expect(url).toContain('https://api.workos.com/user_management/invitations')
    expect(url).toContain('organization_id=org_xyz')
    expect(options.headers.Authorization).toBe('Bearer sk_test')
  })

  it('returns only pending invitations', async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        data: [
          { id: 'inv_1', email: 'p@x.com', state: 'pending', created_at: 't' },
          { id: 'inv_2', email: 'a@x.com', state: 'accepted', created_at: 't' },
          { id: 'inv_3', email: 'e@x.com', state: 'expired', created_at: 't' },
        ],
      }),
    )
    const invites = await listOrgInvitations('sk_test', 'org_xyz')
    expect(invites).toHaveLength(1)
    expect(invites[0].email).toBe('p@x.com')
  })

  it('returns empty array on non-2xx / error', async () => {
    mockFetch.mockResolvedValueOnce(textResponse('boom', 500))
    expect(await listOrgInvitations('sk_test', 'org_xyz')).toEqual([])
    mockFetch.mockRejectedValueOnce(new Error('network'))
    expect(await listOrgInvitations('sk_test', 'org_xyz')).toEqual([])
  })
})

// ============================================================================
// getInvitation / revokeInvitation
// ============================================================================

describe('getInvitation', () => {
  let mockFetch: ReturnType<typeof vi.fn>
  beforeEach(() => {
    mockFetch = vi.fn()
    vi.stubGlobal('fetch', mockFetch)
  })
  afterEach(() => vi.restoreAllMocks())

  it('GETs a single invitation by id', async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ id: 'invitation_1', email: 'p@x.com', state: 'pending', created_at: 't' }))
    const inv = await getInvitation('sk_test', 'invitation_1')
    const [url] = mockFetch.mock.calls[0]
    expect(url).toBe('https://api.workos.com/user_management/invitations/invitation_1')
    expect(inv?.email).toBe('p@x.com')
  })

  it('returns null when not found', async () => {
    mockFetch.mockResolvedValueOnce(textResponse('Not Found', 404))
    expect(await getInvitation('sk_test', 'invitation_x')).toBeNull()
  })
})

describe('revokeInvitation', () => {
  let mockFetch: ReturnType<typeof vi.fn>
  beforeEach(() => {
    mockFetch = vi.fn()
    vi.stubGlobal('fetch', mockFetch)
  })
  afterEach(() => vi.restoreAllMocks())

  it('POSTs to invitations/:id/revoke', async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ id: 'invitation_1', state: 'revoked' }))
    const ok = await revokeInvitation('sk_test', 'invitation_1')
    const [url, options] = mockFetch.mock.calls[0]
    expect(url).toBe('https://api.workos.com/user_management/invitations/invitation_1/revoke')
    expect(options.method).toBe('POST')
    expect(ok).toBe(true)
  })

  it('treats 404 as success', async () => {
    mockFetch.mockResolvedValueOnce(new Response(null, { status: 404 }))
    expect(await revokeInvitation('sk_test', 'invitation_gone')).toBe(true)
  })

  it('returns false on a real failure', async () => {
    mockFetch.mockResolvedValueOnce(new Response(null, { status: 500 }))
    expect(await revokeInvitation('sk_test', 'invitation_1')).toBe(false)
  })
})

// ============================================================================
// findOwnedOrg
// ============================================================================

describe('findOwnedOrg', () => {
  let mockFetch: ReturnType<typeof vi.fn>
  beforeEach(() => {
    mockFetch = vi.fn()
    vi.stubGlobal('fetch', mockFetch)
  })
  afterEach(() => vi.restoreAllMocks())

  it('returns the owner/admin org when the user owns one', async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        data: [
          { id: 'om_1', user_id: 'user_1', organization_id: 'org_member', role: { slug: 'viewer' }, status: 'active', created_at: 't', updated_at: 't' },
          { id: 'om_2', user_id: 'user_1', organization_id: 'org_owned', role: { slug: 'owner' }, status: 'active', created_at: 't', updated_at: 't' },
        ],
      }),
    )
    const owned = await findOwnedOrg('sk_test', 'user_1')
    expect(owned).toEqual({ orgId: 'org_owned', role: 'owner' })
  })

  it('falls back to the first membership when none is owner/admin', async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        data: [{ id: 'om_1', user_id: 'user_1', organization_id: 'org_only', role: { slug: 'viewer' }, status: 'active', created_at: 't', updated_at: 't' }],
      }),
    )
    const owned = await findOwnedOrg('sk_test', 'user_1')
    expect(owned).toEqual({ orgId: 'org_only', role: 'viewer' })
  })

  it('returns null when the user has no memberships', async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ data: [] }))
    expect(await findOwnedOrg('sk_test', 'user_1')).toBeNull()
  })
})
