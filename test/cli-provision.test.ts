import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

describe('provisionCommand', () => {
  let mockFetch: ReturnType<typeof vi.fn>
  let mockStorage: { setProvisionData: ReturnType<typeof vi.fn>; getProvisionData: ReturnType<typeof vi.fn>; removeProvisionData: ReturnType<typeof vi.fn> }
  let logs: string[]

  beforeEach(() => {
    mockFetch = vi.fn()
    vi.stubGlobal('fetch', mockFetch)
    mockStorage = { setProvisionData: vi.fn(), getProvisionData: vi.fn(), removeProvisionData: vi.fn() }
    logs = []
    vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
      logs.push(args.join(' '))
    })
    vi.spyOn(console, 'error').mockImplementation(() => {})
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('provisions and prints human-readable output', async () => {
    const { provisionCommand } = await import('../src/sdk/cli/provision')

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 201,
      json: async () => ({
        tenantId: 'tnt_abc',
        identityId: 'id_123',
        sessionToken: 'ses_xyz',
        claimToken: 'clm_def',
        level: 1,
        limits: { maxEntities: 1000, ttlHours: 24, maxRequestsPerMinute: 100 },
        upgrade: { nextLevel: 2, action: 'claim' },
      }),
    })

    await provisionCommand({ baseUrl: 'https://id.org.ai', json: false, storage: mockStorage as any })

    const output = logs.join('\n')
    expect(output).toContain('tnt_abc')
    expect(output).toContain('clm_def')
    expect(output).toContain('id.org.ai claim')
    expect(mockStorage.setProvisionData).toHaveBeenCalled()
  })

  it('outputs JSON with --json flag', async () => {
    const { provisionCommand } = await import('../src/sdk/cli/provision')

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 201,
      json: async () => ({
        tenantId: 'tnt_abc',
        identityId: 'id_123',
        sessionToken: 'ses_xyz',
        claimToken: 'clm_def',
        level: 1,
        limits: { maxEntities: 1000, ttlHours: 24, maxRequestsPerMinute: 100 },
        upgrade: { nextLevel: 2, action: 'claim' },
      }),
    })

    await provisionCommand({ baseUrl: 'https://id.org.ai', json: true, storage: mockStorage as any })

    const output = logs.join('\n')
    const parsed = JSON.parse(output)
    expect(parsed.tenantId).toBe('tnt_abc')
  })
})
