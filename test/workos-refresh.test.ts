// @vitest-environment node
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { refreshWorkOSAccessToken } from '../src/sdk/workos/upstream'

describe('refreshWorkOSAccessToken', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })

  it('exchanges refresh token for access token', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({
        access_token: 'new_access_token',
        refresh_token: 'new_refresh_token',
        user: { id: 'user_1', email: 'test@test.com' },
      }),
    }))

    const result = await refreshWorkOSAccessToken('client_id', 'api_key', 'old_refresh_token')

    expect(result.access_token).toBe('new_access_token')
    expect(result.refresh_token).toBe('new_refresh_token')
    expect(fetch).toHaveBeenCalledWith('https://api.workos.com/user_management/authenticate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: expect.stringContaining('grant_type=refresh_token'),
    })
  })

  it('passes organizationId when provided', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({
        access_token: 'org_scoped_token',
        refresh_token: 'new_refresh',
        user: { id: 'user_1' },
      }),
    }))

    await refreshWorkOSAccessToken('client_id', 'api_key', 'refresh_token', 'org_123')

    const body = (fetch as any).mock.calls[0][1].body as string
    expect(body).toContain('organization_id=org_123')
  })

  it('throws on WorkOS error', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      text: () => Promise.resolve('Invalid refresh token'),
    }))

    let caught: Error | undefined
    try {
      await refreshWorkOSAccessToken('client_id', 'api_key', 'bad_token')
    } catch (e) {
      caught = e as Error
    }
    expect(caught).toBeDefined()
    expect(caught?.message).toContain('WorkOS token refresh failed: 401')
  })
})
