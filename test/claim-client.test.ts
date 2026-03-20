import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

describe('provision', () => {
  let mockFetch: ReturnType<typeof vi.fn>

  beforeEach(() => {
    mockFetch = vi.fn()
    vi.stubGlobal('fetch', mockFetch)
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('calls POST /api/provision and returns result', async () => {
    const { provision } = await import('../src/claim/client')

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

    const result = await provision('https://id.org.ai')

    expect(mockFetch).toHaveBeenCalledWith('https://id.org.ai/api/provision', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    })
    expect(result.tenantId).toBe('tnt_abc')
    expect(result.claimToken).toBe('clm_def')
    expect(result.level).toBe(1)
  })

  it('throws on non-ok response', async () => {
    const { provision } = await import('../src/claim/client')

    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 500,
      statusText: 'Internal Server Error',
    })

    await expect(provision('https://id.org.ai')).rejects.toThrow()
  })
})

describe('getClaimStatus', () => {
  let mockFetch: ReturnType<typeof vi.fn>

  beforeEach(() => {
    mockFetch = vi.fn()
    vi.stubGlobal('fetch', mockFetch)
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('calls GET /api/claim/:token/status', async () => {
    const { getClaimStatus } = await import('../src/claim/client')

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ status: 'claimed', level: 2 }),
    })

    const result = await getClaimStatus('clm_abc', 'https://id.org.ai')

    expect(mockFetch).toHaveBeenCalledWith('https://id.org.ai/api/claim/clm_abc/status')
    expect(result.status).toBe('claimed')
    expect(result.level).toBe(2)
  })

  it('returns unclaimed on 404', async () => {
    const { getClaimStatus } = await import('../src/claim/client')

    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 404,
    })

    const result = await getClaimStatus('clm_unknown', 'https://id.org.ai')

    expect(result.status).toBe('unclaimed')
  })
})
