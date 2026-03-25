// @vitest-environment node
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { createIdClient } from './client'
import type { AuthUser } from './types'

const mockUser: AuthUser = {
  id: 'user_1',
  email: 'test@test.com',
  firstName: 'Test',
  lastName: 'User',
  profilePictureUrl: null,
  emailVerified: true,
  organizationId: 'org_1',
  role: 'member',
  permissions: [],
  createdAt: '2026-01-01T00:00:00Z',
  updatedAt: '2026-01-01T00:00:00Z',
}

describe('createIdClient', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })

  it('fetchSession returns user on 200', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ user: mockUser, organizationId: 'org_1' }),
    }))

    const client = createIdClient('https://id.org.ai')
    const result = await client.fetchSession()
    expect(result.user).toEqual(mockUser)
    expect(result.organizationId).toBe('org_1')
    expect(fetch).toHaveBeenCalledWith('https://id.org.ai/api/session', { credentials: 'include' })
  })

  it('fetchSession returns null user on 401', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, status: 401 }))

    const client = createIdClient('https://id.org.ai')
    const result = await client.fetchSession()
    expect(result.user).toBeNull()
  })

  it('fetchSession throws on network error', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('Network error')))

    const client = createIdClient('https://id.org.ai')
    let caught: Error | undefined
    try {
      await client.fetchSession()
    } catch (e) {
      caught = e as Error
    }
    expect(caught).toBeDefined()
    expect(caught?.message).toBe('Network error')
  })

  it('fetchWidgetToken returns token', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ token: 'wos_token_123' }),
    }))

    const client = createIdClient('https://id.org.ai')
    const token = await client.fetchWidgetToken()
    expect(token).toBe('wos_token_123')
  })

  it('exchangeCode sends PKCE verifier and client_id', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ success: true }),
    }))

    const client = createIdClient('https://id.org.ai')
    await client.exchangeCode('auth_code_123', 'verifier_123', 'https://app.com/callback', 'app_test')

    expect(fetch).toHaveBeenCalledWith('https://id.org.ai/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({
        grant_type: 'authorization_code',
        code: 'auth_code_123',
        code_verifier: 'verifier_123',
        redirect_uri: 'https://app.com/callback',
        client_id: 'app_test',
      }),
    })
  })

  it('logout calls POST /api/logout', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true }))

    const client = createIdClient('https://id.org.ai')
    await client.logout()
    expect(fetch).toHaveBeenCalledWith('https://id.org.ai/api/logout', {
      method: 'POST',
      credentials: 'include',
    })
  })

  it('switchOrganization sends orgId', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ user: mockUser, organizationId: 'org_2' }),
    }))

    const client = createIdClient('https://id.org.ai')
    const result = await client.switchOrganization('org_2')
    expect(result.organizationId).toBe('org_2')
  })

  it('fetchOrganizations returns org list', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ organizations: [{ id: 'org_1', name: 'Acme', slug: 'acme' }] }),
    }))

    const client = createIdClient('https://id.org.ai')
    const orgs = await client.fetchOrganizations()
    expect(orgs).toHaveLength(1)
    expect(orgs[0].slug).toBe('acme')
  })
})
