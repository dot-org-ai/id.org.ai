/**
 * Trusted-Account OAuth Mode (ADR-0007)
 *
 * Verifies the issuer-side relaxation:
 *   - The canonical shared client_id `cid_trusted_account_v1` bypasses DCR
 *     entirely. Its redirect_uri list is implicit-via-allowlist.
 *   - PKCE, scope, state validation are unchanged.
 *   - Non-trusted client_ids still hit the existing DCR path unchanged.
 *
 * See: docs/adr/0007-trusted-account-oauth-via-better-auth.md
 */

import { describe, it, expect, beforeEach } from 'vitest'
import { OAuthProvider } from '../src/sdk/oauth/provider'
import type { OAuthConfig } from '../src/sdk/oauth/provider'
import {
  parseTrustedAccountDomains,
  TRUSTED_ACCOUNT_CLIENT_ID,
} from '../worker/routes/oauth'

// ── Mirror the storage helper used by the broader OAuth tests ───────────────

type StorageLike = {
  get<T = unknown>(key: string): Promise<T | undefined>
  put(key: string, value: unknown, options?: { expirationTtl?: number }): Promise<void>
  delete(key: string): Promise<boolean>
  list<T = unknown>(options?: { prefix?: string; limit?: number }): Promise<Map<string, T>>
}

function createMockStorage(): StorageLike {
  const store = new Map<string, unknown>()
  return {
    async get<T = unknown>(key: string): Promise<T | undefined> {
      return store.get(key) as T | undefined
    },
    async put(key: string, value: unknown): Promise<void> {
      store.set(key, value)
    },
    async delete(key: string): Promise<boolean> {
      return store.delete(key)
    },
    async list<T = unknown>(options?: { prefix?: string; limit?: number }): Promise<Map<string, T>> {
      const result = new Map<string, T>()
      let count = 0
      for (const [key, value] of store) {
        if (options?.prefix && !key.startsWith(options.prefix)) continue
        if (options?.limit && count >= options.limit) break
        result.set(key, value as T)
        count++
      }
      return result
    },
  }
}

const TEST_CONFIG: OAuthConfig = {
  issuer: 'https://id.org.ai',
  authorizationEndpoint: 'https://id.org.ai/oauth/authorize',
  tokenEndpoint: 'https://id.org.ai/oauth/token',
  userinfoEndpoint: 'https://id.org.ai/oauth/userinfo',
  registrationEndpoint: 'https://id.org.ai/oauth/register',
  deviceAuthorizationEndpoint: 'https://id.org.ai/oauth/device',
  revocationEndpoint: 'https://id.org.ai/oauth/revoke',
  introspectionEndpoint: 'https://id.org.ai/oauth/introspect',
  jwksUri: 'https://id.org.ai/.well-known/jwks.json',
}

const TRUSTED_CLIENT_ID = TRUSTED_ACCOUNT_CLIENT_ID

const TEST_IDENTITIES: Record<string, { id: string; name?: string; email?: string; emailVerified?: boolean }> = {
  'user-1': {
    id: 'user-1',
    name: 'Alice',
    email: 'alice@example.com',
    emailVerified: true,
  },
}

function createTrustedProvider(allowedDomains: string[], storage?: StorageLike): OAuthProvider {
  return new OAuthProvider({
    storage: storage ?? createMockStorage(),
    config: TEST_CONFIG,
    getIdentity: async (id: string) => TEST_IDENTITIES[id] ?? null,
    trustedAccount: {
      clientId: TRUSTED_CLIENT_ID,
      allowedDomains: new Set(allowedDomains),
    },
  })
}

function createUntrustedProvider(storage?: StorageLike): OAuthProvider {
  return new OAuthProvider({
    storage: storage ?? createMockStorage(),
    config: TEST_CONFIG,
    getIdentity: async (id: string) => TEST_IDENTITIES[id] ?? null,
    // No trustedAccount config - should behave exactly like before.
  })
}

async function computeS256Challenge(verifier: string): Promise<string> {
  const data = new TextEncoder().encode(verifier)
  const hash = await crypto.subtle.digest('SHA-256', data)
  return btoa(String.fromCharCode(...new Uint8Array(hash)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '')
}

function buildAuthorizeUrl(params: Record<string, string>): string {
  const url = new URL('https://id.org.ai/oauth/authorize')
  for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v)
  return url.toString()
}

// ============================================================================
// Tests
// ============================================================================

describe('parseTrustedAccountDomains', () => {
  it('returns an empty set for undefined or empty input', () => {
    expect(parseTrustedAccountDomains(undefined).size).toBe(0)
    expect(parseTrustedAccountDomains('').size).toBe(0)
    expect(parseTrustedAccountDomains('   ').size).toBe(0)
  })

  it('parses comma-separated bare hostnames and lowercases them', () => {
    const set = parseTrustedAccountDomains('startup.games, Foo.Example , bar.test')
    expect(set.has('startup.games')).toBe(true)
    expect(set.has('foo.example')).toBe(true)
    expect(set.has('bar.test')).toBe(true)
    expect(set.size).toBe(3)
  })

  it('rejects entries that look like URLs (scheme, port, path)', () => {
    const set = parseTrustedAccountDomains('https://evil.com, ok.com, has space, port.com:8080, with/path')
    expect(set.has('ok.com')).toBe(true)
    // The above all contain characters we reject defensively.
    expect(set.has('https://evil.com')).toBe(false)
    expect(set.has('has space')).toBe(false)
    expect(set.has('port.com:8080')).toBe(false)
    expect(set.has('with/path')).toBe(false)
    expect(set.size).toBe(1)
  })
})

describe('OAuthProvider - trusted-account mode (ADR-0007)', () => {
  let storage: StorageLike

  beforeEach(() => {
    storage = createMockStorage()
  })

  // ── /oauth/authorize ──────────────────────────────────────────────────────

  describe('/oauth/authorize', () => {
    it('accepts trusted-account client + allowlisted redirect_uri and returns a code', async () => {
      const provider = createTrustedProvider(['startup.games'], storage)
      const codeChallenge = await computeS256Challenge('verifier-1234567890abcdef')

      const url = buildAuthorizeUrl({
        client_id: TRUSTED_CLIENT_ID,
        redirect_uri: 'https://startup.games/api/auth/callback/id-org-ai',
        response_type: 'code',
        scope: 'openid profile email',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
        state: 'test-state',
      })
      const req = new Request(url, { method: 'GET', redirect: 'manual' })
      const res = await provider.handleAuthorize(req, 'user-1')

      expect(res.status).toBe(302)
      const location = new URL(res.headers.get('location')!)
      expect(location.host).toBe('startup.games')
      expect(location.pathname).toBe('/api/auth/callback/id-org-ai')
      expect(location.searchParams.get('code')).toMatch(/^ac_/)
      expect(location.searchParams.get('state')).toBe('test-state')
      expect(location.searchParams.get('error')).toBeNull()
    })

    it('accepts allowlisted host on a sub-path/query', async () => {
      const provider = createTrustedProvider(['startup.games'])
      const codeChallenge = await computeS256Challenge('verifier-1234567890abcdef')
      const url = buildAuthorizeUrl({
        client_id: TRUSTED_CLIENT_ID,
        redirect_uri: 'https://startup.games/some/other/path?x=1',
        response_type: 'code',
        scope: 'openid',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      })
      const res = await provider.handleAuthorize(new Request(url, { method: 'GET', redirect: 'manual' }), 'user-1')
      expect(res.status).toBe(302)
      expect(new URL(res.headers.get('location')!).host).toBe('startup.games')
    })

    it('rejects trusted-account client + non-allowlisted redirect_uri with 400', async () => {
      const provider = createTrustedProvider(['startup.games'])
      const codeChallenge = await computeS256Challenge('verifier-1234567890abcdef')
      const url = buildAuthorizeUrl({
        client_id: TRUSTED_CLIENT_ID,
        redirect_uri: 'https://evil.example.com/callback',
        response_type: 'code',
        scope: 'openid',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      })
      const res = await provider.handleAuthorize(new Request(url, { method: 'GET', redirect: 'manual' }), 'user-1')

      expect(res.status).toBe(400)
      const body = (await res.json()) as { error: string; error_description: string }
      expect(body.error).toBe('invalid_request')
      expect(body.error_description).toMatch(/trusted-account allowlist/i)
    })

    it('rejects subdomain when only the apex is allowlisted (exact host match)', async () => {
      const provider = createTrustedProvider(['startup.games'])
      const codeChallenge = await computeS256Challenge('verifier-1234567890abcdef')
      const url = buildAuthorizeUrl({
        client_id: TRUSTED_CLIENT_ID,
        redirect_uri: 'https://app.startup.games/cb',
        response_type: 'code',
        scope: 'openid',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      })
      const res = await provider.handleAuthorize(new Request(url, { method: 'GET', redirect: 'manual' }), 'user-1')
      expect(res.status).toBe(400)
    })

    it('rejects http (non-https) redirect_uri even when host is allowlisted', async () => {
      const provider = createTrustedProvider(['startup.games'])
      const codeChallenge = await computeS256Challenge('verifier-1234567890abcdef')
      const url = buildAuthorizeUrl({
        client_id: TRUSTED_CLIENT_ID,
        redirect_uri: 'http://startup.games/cb',
        response_type: 'code',
        scope: 'openid',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      })
      const res = await provider.handleAuthorize(new Request(url, { method: 'GET', redirect: 'manual' }), 'user-1')
      expect(res.status).toBe(400)
    })

    it('still requires PKCE for the trusted-account public client', async () => {
      const provider = createTrustedProvider(['startup.games'])
      const url = buildAuthorizeUrl({
        client_id: TRUSTED_CLIENT_ID,
        redirect_uri: 'https://startup.games/cb',
        response_type: 'code',
        scope: 'openid',
        // no code_challenge
      })
      const res = await provider.handleAuthorize(new Request(url, { method: 'GET', redirect: 'manual' }), 'user-1')
      // PKCE failure is reported via redirect (302) with error=invalid_request
      expect(res.status).toBe(302)
      const location = new URL(res.headers.get('location')!)
      expect(location.searchParams.get('error')).toBe('invalid_request')
      expect(location.searchParams.get('error_description')).toMatch(/code_challenge/i)
    })

    it('non-trusted client_id still hits the DCR path unchanged (unknown client -> 400)', async () => {
      const provider = createTrustedProvider(['startup.games'], storage)
      const codeChallenge = await computeS256Challenge('verifier-1234567890abcdef')
      const url = buildAuthorizeUrl({
        // not the trusted client id; nothing is in storage for this id
        client_id: 'cid_some_unknown_app',
        redirect_uri: 'https://startup.games/cb',
        response_type: 'code',
        scope: 'openid',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      })
      const res = await provider.handleAuthorize(new Request(url, { method: 'GET', redirect: 'manual' }), 'user-1')
      expect(res.status).toBe(400)
      const body = (await res.json()) as { error: string }
      expect(body.error).toBe('invalid_client')
    })

    it('without trustedAccount config, the canonical client_id is rejected as unknown', async () => {
      const provider = createUntrustedProvider(storage)
      const codeChallenge = await computeS256Challenge('verifier-1234567890abcdef')
      const url = buildAuthorizeUrl({
        client_id: TRUSTED_CLIENT_ID,
        redirect_uri: 'https://startup.games/cb',
        response_type: 'code',
        scope: 'openid',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      })
      const res = await provider.handleAuthorize(new Request(url, { method: 'GET', redirect: 'manual' }), 'user-1')
      expect(res.status).toBe(400)
      const body = (await res.json()) as { error: string }
      expect(body.error).toBe('invalid_client')
    })
  })

  // ── /oauth/token ──────────────────────────────────────────────────────────

  describe('/oauth/token', () => {
    async function getCodeForTrusted(
      provider: OAuthProvider,
      redirectUri: string,
      codeVerifier: string,
    ): Promise<string> {
      const codeChallenge = await computeS256Challenge(codeVerifier)
      const url = buildAuthorizeUrl({
        client_id: TRUSTED_CLIENT_ID,
        redirect_uri: redirectUri,
        response_type: 'code',
        scope: 'openid profile email',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
        state: 'st-1',
      })
      const res = await provider.handleAuthorize(
        new Request(url, { method: 'GET', redirect: 'manual' }),
        'user-1',
      )
      return new URL(res.headers.get('location')!).searchParams.get('code')!
    }

    it('exchanges code -> tokens for trusted-account client with no client_secret', async () => {
      const provider = createTrustedProvider(['startup.games'], storage)
      const redirectUri = 'https://startup.games/api/auth/callback/id-org-ai'
      const verifier = 'verifier-1234567890abcdef'
      const code = await getCodeForTrusted(provider, redirectUri, verifier)

      const tokenReq = new Request('https://id.org.ai/oauth/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          redirect_uri: redirectUri,
          client_id: TRUSTED_CLIENT_ID,
          code_verifier: verifier,
          // intentionally no client_secret
        }),
      })
      const res = await provider.handleToken(tokenReq)
      expect(res.status).toBe(200)
      const body = (await res.json()) as Record<string, unknown>
      expect(body.access_token).toMatch(/^at_/)
      expect(body.refresh_token).toMatch(/^rt_/)
      expect(body.token_type).toBe('Bearer')
      expect(body.scope).toBe('openid profile email')
    })

    it('rejects token exchange if the allowlist no longer contains the host', async () => {
      const provider = createTrustedProvider(['startup.games'], storage)
      const redirectUri = 'https://startup.games/api/auth/callback/id-org-ai'
      const verifier = 'verifier-1234567890abcdef'
      const code = await getCodeForTrusted(provider, redirectUri, verifier)

      // Simulate the allowlist shrinking between /authorize and /token by
      // building a new provider with a different allowlist over the same store.
      const shrunkProvider = createTrustedProvider(['someone-else.com'], storage)

      const tokenReq = new Request('https://id.org.ai/oauth/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          redirect_uri: redirectUri,
          client_id: TRUSTED_CLIENT_ID,
          code_verifier: verifier,
        }),
      })
      const res = await shrunkProvider.handleToken(tokenReq)
      expect(res.status).toBe(400)
      const body = (await res.json()) as { error: string; error_description: string }
      expect(body.error).toBe('invalid_grant')
      expect(body.error_description).toMatch(/trusted-account allowlist/i)
    })

    it('rejects token exchange when redirect_uri body does not match the code', async () => {
      const provider = createTrustedProvider(['startup.games'], storage)
      const redirectUri = 'https://startup.games/api/auth/callback/id-org-ai'
      const verifier = 'verifier-1234567890abcdef'
      const code = await getCodeForTrusted(provider, redirectUri, verifier)

      const tokenReq = new Request('https://id.org.ai/oauth/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          // different path -> still allowlisted host, but mismatched against the code
          redirect_uri: 'https://startup.games/different/path',
          client_id: TRUSTED_CLIENT_ID,
          code_verifier: verifier,
        }),
      })
      const res = await provider.handleToken(tokenReq)
      expect(res.status).toBe(400)
      const body = (await res.json()) as { error: string }
      expect(body.error).toBe('invalid_grant')
    })

    it('rejects token exchange with wrong code_verifier (PKCE still enforced)', async () => {
      const provider = createTrustedProvider(['startup.games'], storage)
      const redirectUri = 'https://startup.games/api/auth/callback/id-org-ai'
      const verifier = 'verifier-1234567890abcdef'
      const code = await getCodeForTrusted(provider, redirectUri, verifier)

      const tokenReq = new Request('https://id.org.ai/oauth/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          redirect_uri: redirectUri,
          client_id: TRUSTED_CLIENT_ID,
          code_verifier: 'wrong-verifier-1234567890abcdef',
        }),
      })
      const res = await provider.handleToken(tokenReq)
      expect(res.status).toBe(400)
      const body = (await res.json()) as { error: string }
      expect(body.error).toBe('invalid_grant')
    })
  })
})
