/**
 * CLI auth tests — refresh under the issuing client, rotation persistence,
 * never returning an expired token, and the failure reason shown by
 * `status` / `whoami`.
 *
 * Background: id.org.ai binds refresh tokens to the client_id that issued
 * them and rotates them on use. The token file is shared between the
 * id.org.ai / oauth.do / auto.dev CLIs, so a token issued to `auto_dev_cli`
 * must be refreshed under `auto_dev_cli` — never under whichever CLI happens
 * to be running.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import {
  refreshTokens,
  refreshAccessToken,
  refreshClientIdOrder,
  resolveAccessToken,
  ensureValidToken,
  describeTokenFailure,
  KNOWN_CLI_CLIENT_IDS,
} from '../src/sdk/cli/auth'
import type { TokenStorage, StoredTokenData } from '../src/sdk/cli/storage'
import { pollForTokens } from '../src/sdk/cli/device'
import { getCliVersion } from '../src/sdk/cli/version'

// ── Helpers ─────────────────────────────────────────────────────────────────

class MemoryStorage implements TokenStorage {
  data: StoredTokenData | null = null
  writes: StoredTokenData[] = []
  constructor(initial: StoredTokenData | null = null) {
    this.data = initial
  }
  async getToken() {
    return this.data?.accessToken ?? null
  }
  async setToken(token: string) {
    await this.setTokenData({ accessToken: token })
  }
  async removeToken() {
    this.data = null
  }
  async getTokenData() {
    return this.data
  }
  async setTokenData(data: StoredTokenData) {
    this.data = data
    this.writes.push({ ...data })
  }
}

function oauthError(error: string, description: string, status = 400) {
  return new Response(JSON.stringify({ error, error_description: description }), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function tokenResponse(suffix: string, expiresIn = 3600) {
  return new Response(
    JSON.stringify({
      access_token: `access_${suffix}`,
      refresh_token: `refresh_${suffix}`,
      token_type: 'Bearer',
      expires_in: expiresIn,
    }),
    { status: 200, headers: { 'Content-Type': 'application/json' } },
  )
}

/** Simulates the server: one refresh token, bound to one client, rotating on use. */
function fakeRefreshServer(issuedTo: string, opts: { revoked?: boolean } = {}) {
  const calls: Array<{ client_id: string; refresh_token: string; grant_type: string }> = []
  let current = 'refresh_0'
  let n = 0
  const fetchMock = vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
    const params = new URLSearchParams(String(init?.body))
    const call = {
      client_id: params.get('client_id') ?? '',
      refresh_token: params.get('refresh_token') ?? '',
      grant_type: params.get('grant_type') ?? '',
    }
    calls.push(call)
    if (call.refresh_token !== current) return oauthError('invalid_grant', 'Invalid refresh token')
    if (call.client_id !== issuedTo) return oauthError('invalid_grant', 'Refresh token was not issued to this client')
    if (opts.revoked) return oauthError('invalid_grant', 'Refresh token has been revoked')
    n += 1
    current = `refresh_${n}`
    return tokenResponse(String(n))
  })
  return { fetchMock, calls, currentRefreshToken: () => current }
}

beforeEach(() => {
  vi.unstubAllGlobals()
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.useRealTimers()
})

// ── Client-id order ─────────────────────────────────────────────────────────

describe('refreshClientIdOrder', () => {
  it('tries the configured CLIENT_ID first, then the other first-party CLI ids, de-duplicated', () => {
    const order = refreshClientIdOrder()
    expect(order[0]).toBe('id_org_ai_cli')
    expect(order).toEqual(['id_org_ai_cli', 'oauth_do_cli', 'auto_dev_cli'])
    expect(new Set(order).size).toBe(order.length)
    for (const id of KNOWN_CLI_CLIENT_IDS) expect(order).toContain(id)
  })

  it('puts the stored clientId first and keeps the rest as fallbacks', () => {
    expect(refreshClientIdOrder({ clientId: 'auto_dev_cli' })).toEqual(['auto_dev_cli', 'id_org_ai_cli', 'oauth_do_cli'])
  })

  it('honours explicit fallbackClientIds', () => {
    expect(refreshClientIdOrder({ clientId: 'x', fallbackClientIds: ['y', 'x'] })).toEqual(['x', 'y'])
  })
})

// ── Refresh under the issuing client ────────────────────────────────────────

describe('refreshTokens', () => {
  it('refreshes under the stored clientId without probing', async () => {
    const server = fakeRefreshServer('auto_dev_cli')
    vi.stubGlobal('fetch', server.fetchMock)

    const outcome = await refreshTokens('refresh_0', { clientId: 'auto_dev_cli' })
    expect(outcome.ok).toBe(true)
    expect(server.calls).toHaveLength(1)
    expect(server.calls[0].client_id).toBe('auto_dev_cli')
    expect(server.calls[0].grant_type).toBe('refresh_token')
  })

  it('falls back through the known CLI ids in order when no clientId is stored (the reported defect)', async () => {
    // Token file written by auto_dev_cli, predating `clientId` in the file.
    const server = fakeRefreshServer('auto_dev_cli')
    vi.stubGlobal('fetch', server.fetchMock)

    const outcome = await refreshTokens('refresh_0')
    expect(outcome.ok).toBe(true)
    expect(server.calls.map((c) => c.client_id)).toEqual(['id_org_ai_cli', 'oauth_do_cli', 'auto_dev_cli'])
    if (outcome.ok) {
      expect(outcome.data.clientId).toBe('auto_dev_cli')
      expect(outcome.data.accessToken).toBe('access_1')
    }
  })

  it('stops at the first success', async () => {
    const server = fakeRefreshServer('oauth_do_cli')
    vi.stubGlobal('fetch', server.fetchMock)

    const outcome = await refreshTokens('refresh_0')
    expect(outcome.ok).toBe(true)
    expect(server.calls.map((c) => c.client_id)).toEqual(['id_org_ai_cli', 'oauth_do_cli'])
  })

  it('does NOT probe other clients when the token is revoked (only wrong-client errors fall through)', async () => {
    const server = fakeRefreshServer('id_org_ai_cli', { revoked: true })
    vi.stubGlobal('fetch', server.fetchMock)

    const outcome = await refreshTokens('refresh_0')
    expect(outcome.ok).toBe(false)
    expect(server.calls).toHaveLength(1)
    if (!outcome.ok) {
      expect(outcome.error.code).toBe('invalid_grant')
      expect(outcome.error.description).toBe('Refresh token has been revoked')
      expect(outcome.error.clientId).toBe('id_org_ai_cli')
      expect(outcome.error.triedClientIds).toEqual(['id_org_ai_cli'])
    }
  })

  it('reports every client tried when none is accepted', async () => {
    const server = fakeRefreshServer('some_other_client')
    vi.stubGlobal('fetch', server.fetchMock)

    const outcome = await refreshTokens('refresh_0')
    expect(outcome.ok).toBe(false)
    if (!outcome.ok) {
      expect(outcome.error.triedClientIds).toEqual(['id_org_ai_cli', 'oauth_do_cli', 'auto_dev_cli'])
      expect(outcome.error.description).toMatch(/not issued to this client/)
    }
  })

  it('reports network errors as network_error without probing further', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new TypeError('fetch failed')
      }),
    )
    const outcome = await refreshTokens('refresh_0')
    expect(outcome.ok).toBe(false)
    if (!outcome.ok) {
      expect(outcome.error.code).toBe('network_error')
      expect(outcome.error.triedClientIds).toHaveLength(1)
    }
  })

  it('persists the rotated refresh token and the accepted clientId in the same operation', async () => {
    const server = fakeRefreshServer('auto_dev_cli')
    vi.stubGlobal('fetch', server.fetchMock)
    const storage = new MemoryStorage({ accessToken: 'old', refreshToken: 'refresh_0' })

    const outcome = await refreshTokens('refresh_0', { storage })
    expect(outcome.ok).toBe(true)
    expect(storage.writes).toHaveLength(1)
    expect(storage.data?.refreshToken).toBe(server.currentRefreshToken())
    expect(storage.data?.refreshToken).toBe('refresh_1')
    expect(storage.data?.clientId).toBe('auto_dev_cli')
    expect(storage.data?.accessToken).toBe('access_1')
    expect(storage.data?.expiresAt).toBeGreaterThan(Date.now())
  })

  it('a second refresh uses the rotated token and the persisted clientId (no re-probing)', async () => {
    const server = fakeRefreshServer('auto_dev_cli')
    vi.stubGlobal('fetch', server.fetchMock)
    const storage = new MemoryStorage({ accessToken: 'old', refreshToken: 'refresh_0' })

    await refreshTokens('refresh_0', { storage })
    server.calls.length = 0

    const second = await refreshTokens(storage.data!.refreshToken!, { clientId: storage.data!.clientId, storage })
    expect(second.ok).toBe(true)
    expect(server.calls).toHaveLength(1)
    expect(server.calls[0]).toMatchObject({ client_id: 'auto_dev_cli', refresh_token: 'refresh_1' })
    expect(storage.data?.refreshToken).toBe('refresh_2')
  })

  it('refreshAccessToken stays a nullable convenience wrapper', async () => {
    const server = fakeRefreshServer('id_org_ai_cli', { revoked: true })
    vi.stubGlobal('fetch', server.fetchMock)
    expect(await refreshAccessToken('refresh_0')).toBeNull()
  })
})

// ── Never return an expired token ───────────────────────────────────────────

describe('resolveAccessToken / ensureValidToken', () => {
  it('returns the stored token untouched while it is valid', async () => {
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
    const storage = new MemoryStorage({ accessToken: 'fresh', refreshToken: 'r', expiresAt: Date.now() + 3_600_000 })

    expect(await resolveAccessToken(storage)).toEqual({ token: 'fresh' })
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('returns a token without expiresAt as-is (legacy plain-text files)', async () => {
    const storage = new MemoryStorage({ accessToken: 'legacy' })
    expect(await ensureValidToken(storage)).toBe('legacy')
  })

  it('refreshes an expired token under the stored clientId and persists the rotation', async () => {
    const server = fakeRefreshServer('auto_dev_cli')
    vi.stubGlobal('fetch', server.fetchMock)
    const storage = new MemoryStorage({
      accessToken: 'expired',
      refreshToken: 'refresh_0',
      expiresAt: Date.now() - 1000,
      clientId: 'auto_dev_cli',
    })

    const res = await resolveAccessToken(storage)
    expect(res).toEqual({ token: 'access_1', refreshed: true })
    expect(server.calls.map((c) => c.client_id)).toEqual(['auto_dev_cli'])
    expect(storage.data).toMatchObject({ accessToken: 'access_1', refreshToken: 'refresh_1', clientId: 'auto_dev_cli' })
  })

  it('does NOT return the expired token when refresh is rejected — returns null with the reason', async () => {
    const server = fakeRefreshServer('id_org_ai_cli', { revoked: true })
    vi.stubGlobal('fetch', server.fetchMock)
    const storage = new MemoryStorage({ accessToken: 'expired', refreshToken: 'refresh_0', expiresAt: Date.now() - 1000 })

    const res = await resolveAccessToken(storage)
    expect(res.token).toBeNull()
    expect(res.reason).toBe('refresh_failed')
    expect(res.error?.description).toBe('Refresh token has been revoked')
    // and the legacy wrapper agrees
    expect(await ensureValidToken(storage)).toBeNull()
    // the stored data is left alone for `status` to explain
    expect(storage.data?.accessToken).toBe('expired')
  })

  it('does NOT return the expired token when there is no refresh token', async () => {
    const storage = new MemoryStorage({ accessToken: 'expired', expiresAt: Date.now() - 1000 })
    const res = await resolveAccessToken(storage)
    expect(res).toEqual({ token: null, reason: 'expired_no_refresh' })
    expect(await ensureValidToken(storage)).toBeNull()
  })

  it('treats a token inside the 30s refresh buffer as needing refresh', async () => {
    const server = fakeRefreshServer('id_org_ai_cli')
    vi.stubGlobal('fetch', server.fetchMock)
    const storage = new MemoryStorage({ accessToken: 'almost', refreshToken: 'refresh_0', expiresAt: Date.now() + 10_000 })
    expect((await resolveAccessToken(storage)).token).toBe('access_1')
  })

  it('reports no_token when nothing is stored', async () => {
    expect(await resolveAccessToken(new MemoryStorage())).toEqual({ token: null, reason: 'no_token' })
  })
})

// ── The reason printed by status / whoami ───────────────────────────────────

describe('describeTokenFailure', () => {
  it('explains a revoked refresh token', async () => {
    const server = fakeRefreshServer('id_org_ai_cli', { revoked: true })
    vi.stubGlobal('fetch', server.fetchMock)
    const storage = new MemoryStorage({
      accessToken: 'expired',
      refreshToken: 'refresh_0',
      expiresAt: Date.now() - 1000,
      clientId: 'id_org_ai_cli',
    })
    const msg = describeTokenFailure(await resolveAccessToken(storage))
    expect(msg).toBe('refresh rejected: Refresh token has been revoked [client_id id_org_ai_cli]')
  })

  it('lists every client tried on a wrong-client rejection', async () => {
    const server = fakeRefreshServer('nobody')
    vi.stubGlobal('fetch', server.fetchMock)
    const storage = new MemoryStorage({ accessToken: 'expired', refreshToken: 'refresh_0', expiresAt: Date.now() - 1000 })
    const msg = describeTokenFailure(await resolveAccessToken(storage))
    expect(msg).toContain('refresh rejected: Refresh token was not issued to this client')
    expect(msg).toContain('tried client_id id_org_ai_cli, oauth_do_cli, auto_dev_cli')
  })

  it('explains an expired token with no refresh token', () => {
    expect(describeTokenFailure({ token: null, reason: 'expired_no_refresh' })).toMatch(/expired and no refresh token/)
  })

  it('explains network failures', () => {
    const msg = describeTokenFailure({
      token: null,
      reason: 'refresh_failed',
      error: { code: 'network_error', description: 'fetch failed', clientId: 'id_org_ai_cli', triedClientIds: ['id_org_ai_cli'] },
    })
    expect(msg).toMatch(/could not reach/)
    expect(msg).toContain('fetch failed')
  })
})

// ── Device-code polling ─────────────────────────────────────────────────────

describe('pollForTokens', () => {
  it('keeps polling through authorization_pending, slow_down and transient failures, then returns tokens', async () => {
    vi.useFakeTimers()
    const responses = [
      () => oauthError('authorization_pending', 'not yet'),
      () => oauthError('slow_down', 'too fast'),
      () => {
        throw new TypeError('fetch failed')
      },
      () => new Response('<html>502</html>', { status: 502 }),
      () => tokenResponse('dev'),
    ]
    const fetchMock = vi.fn(async () => responses.shift()!())
    vi.stubGlobal('fetch', fetchMock)

    const promise = pollForTokens('id_org_ai_cli', 'dc_1', 5, 1800)
    // 5s, 5s, then 10s after slow_down, 10s, 10s
    for (const step of [5000, 5000, 10000, 10000, 10000]) await vi.advanceTimersByTimeAsync(step)

    const tokens = await promise
    expect(tokens.access_token).toBe('access_dev')
    expect(fetchMock).toHaveBeenCalledTimes(5)
  })

  it('surfaces a server-side expired_token with timing so it can be told apart from the local deadline', async () => {
    vi.useFakeTimers()
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => oauthError('expired_token', 'The device code has expired')),
    )
    const promise = pollForTokens('id_org_ai_cli', 'dc_1', 5, 1800)
    const failure = promise.catch((e: Error) => e)
    await vi.advanceTimersByTimeAsync(5000)
    const err = await failure
    expect(err).toBeInstanceOf(Error)
    expect((err as Error).message).toMatch(/^Device code expired \(server reported expired_token after \d+s; expires_in was 1800s\)/)
  })

  it('gives up at the local deadline derived from expires_in', async () => {
    vi.useFakeTimers()
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => oauthError('authorization_pending', 'not yet')),
    )
    const promise = pollForTokens('id_org_ai_cli', 'dc_1', 5, 12)
    const failure = promise.catch((e: Error) => e)
    await vi.advanceTimersByTimeAsync(20000)
    const err = await failure
    expect((err as Error).message).toMatch(/^Device authorization expired after \d+s \(expires_in was 12s\)/)
  })
})

// ── --version ───────────────────────────────────────────────────────────────

describe('getCliVersion', () => {
  it('reads the version from package.json', async () => {
    const fs = await import('fs/promises')
    const pkg = JSON.parse(await fs.readFile(new URL('../package.json', import.meta.url), 'utf-8')) as { version: string }
    expect(getCliVersion()).toBe(pkg.version)
    expect(getCliVersion()).not.toBe('0.0.1')
  })
})
