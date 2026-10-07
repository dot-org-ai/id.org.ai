/**
 * AuthService.orgRole(sub, orgId?): a person's role in one organization, for
 * bound estate Workers (emails.do) whose id.org.ai tokens carry no roles.
 * Read live from WorkOS active memberships; fails closed to null.
 */
import { describe, it, expect, beforeAll, afterEach } from 'vitest'
import { env, fetchMock, createExecutionContext } from 'cloudflare:test'
import { AuthService } from '../worker/index'
import { orgRoleOf } from '../worker/utils/org-role'
import { getStubForIdentity } from '../worker/middleware/tenant'
import type { Env } from '../worker/types'

const WORKOS = 'https://api.workos.com'
const PLATFORM = (env as unknown as Env).PLATFORM_ORG_ID!

async function linkIdentity(identityId: string, workosUserId: string) {
  await getStubForIdentity(env as never, identityId).oauthStorageOp({ op: 'put', key: `identity:${identityId}`, value: { workosUserId } })
}

function mockMemberships(userId: string, rows: Array<{ org: string; role: string; status?: string }>, status = 200) {
  fetchMock
    .get(WORKOS)
    .intercept({ method: 'GET', path: '/user_management/organization_memberships', query: { user_id: userId, limit: '100' } })
    .reply(
      status,
      JSON.stringify({
        data: rows.map((r, i) => ({ id: `om_${i}`, user_id: userId, organization_id: r.org, role: { slug: r.role }, status: r.status ?? 'active', created_at: 't', updated_at: 't' })),
      }),
      { headers: { 'content-type': 'application/json' } },
    )
}

beforeAll(() => {
  fetchMock.activate()
  fetchMock.disableNetConnect()
})
afterEach(() => fetchMock.assertNoPendingInterceptors())

describe('orgRoleOf', () => {
  it('defaults to the platform org and returns the WorkOS role', async () => {
    expect(PLATFORM).toMatch(/^org_/)
    await linkIdentity('idn_admin', 'user_admin')
    mockMemberships('user_admin', [
      { org: 'org_other', role: 'owner' },
      { org: PLATFORM, role: 'admin' },
    ])
    expect(await orgRoleOf(env as never, 'idn_admin')).toBe('admin')
  })

  it('answers for a named org', async () => {
    await linkIdentity('idn_named', 'user_named')
    mockMemberships('user_named', [{ org: 'org_x', role: 'owner' }])
    expect(await orgRoleOf(env as never, 'idn_named', 'org_x')).toBe('owner')
  })

  it('folds the legacy member slug to editor (not admin)', async () => {
    await linkIdentity('idn_member', 'user_member')
    mockMemberships('user_member', [{ org: PLATFORM, role: 'member' }])
    expect(await orgRoleOf(env as never, 'idn_member')).toBe('editor')
  })

  it('ignores memberships that are not active', async () => {
    await linkIdentity('idn_pending', 'user_pending')
    mockMemberships('user_pending', [{ org: PLATFORM, role: 'admin', status: 'pending' }])
    expect(await orgRoleOf(env as never, 'idn_pending')).toBeNull()
  })

  it('is null when not a member of the org', async () => {
    await linkIdentity('idn_none', 'user_none')
    mockMemberships('user_none', [{ org: 'org_elsewhere', role: 'admin' }])
    expect(await orgRoleOf(env as never, 'idn_none')).toBeNull()
  })

  it('is null for an identity with no WorkOS user (no WorkOS call)', async () => {
    expect(await orgRoleOf(env as never, 'idn_unlinked')).toBeNull()
  })

  it('is null on a WorkOS error', async () => {
    await linkIdentity('idn_err', 'user_err')
    mockMemberships('user_err', [], 500)
    expect(await orgRoleOf(env as never, 'idn_err')).toBeNull()
  })

  it('is null for an empty sub', async () => {
    expect(await orgRoleOf(env as never, '')).toBeNull()
  })
})

describe('AuthService.orgRole', () => {
  it('delegates to orgRoleOf over RPC', async () => {
    await linkIdentity('idn_rpc', 'user_rpc')
    mockMemberships('user_rpc', [{ org: PLATFORM, role: 'owner' }])
    const service = new AuthService(createExecutionContext(), env as never)
    expect(await service.orgRole('idn_rpc')).toBe('owner')
  })
})
