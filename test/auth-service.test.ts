/**
 * AuthService Unit Tests
 *
 * Tests the AuthService (WorkerEntrypoint) and all helper functions
 * defined in worker/index.ts:
 *
 *   AuthService methods:
 *     - verifyToken(token) — session, API key, WorkOS key, own JWT, WorkOS JWT
 *     - getUser(token) — returns AuthUser | null
 *     - authenticate(authorization?, cookie?) — extracts + verifies from headers/cookies
 *     - hasRoles(token, roles) — checks if user has any role
 *     - hasPermissions(token, permissions) — checks if user has all permissions
 *     - isAdmin(token) — checks admin role
 *     - invalidate(token) — clears cache + KV entries
 *
 *   Helper functions:
 *     - parseCookieValue(cookieHeader, name)
 *     - hashToken(token)
 *     - getCachedUser(token) / cacheUser(token, user)
 *     - extractApiKey(request) / extractSessionToken(request)
 *     - isApiKeyPrefix(s)
 *     - resolveIdentityId(request, env)
 *     - resolveIdentityFromClaim(claimToken, env)
 *     - getJwksVerifier(jwksUri) — JWKS cache and expiry
 *
 * Since AuthService extends WorkerEntrypoint (Cloudflare runtime only),
 * we test the logic by constructing a mock instance with a fake env,
 * and by testing pure helper functions directly.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

// ============================================================================
// Types (mirrored from worker/index.ts since they're not exported as a package)
// ============================================================================

type AuthUser = {
  id: string
  email?: string
  name?: string
  image?: string
  organizationId?: string
  roles?: string[]
  permissions?: string[]
  metadata?: Record<string, unknown>
}

type VerifyResult =
  | { valid: true; user: AuthUser; cached?: boolean }
  | { valid: false; error: string }

type AuthRPCResult =
  | { ok: true; user: AuthUser }
  | { ok: false; status: number; error: string }

// ============================================================================
// Re-implement pure helper functions for testing
// (These are module-level functions in worker/index.ts, not exported.
//  We re-implement them identically to test their logic.)
// ============================================================================

/** Copied from worker/index.ts line ~155 */
function parseCookieValue(cookieHeader: string, name: string): string | null {
  const match = cookieHeader.match(new RegExp(`(?:^|;\\s*)${name}=([^;]*)`))
  return match ? decodeURIComponent(match[1]) : null
}

/** Copied from worker/index.ts line ~437 */
function isApiKeyPrefix(s: string): boolean {
  return s.startsWith('oai_') || s.startsWith('hly_sk_') || s.startsWith('sk_')
}

/** Copied from worker/index.ts line ~441 */
function extractApiKey(request: Request): string | null {
  const header = request.headers.get('x-api-key')
  if (header && isApiKeyPrefix(header)) return header
  const auth = request.headers.get('authorization')
  if (auth?.startsWith('Bearer ')) {
    const token = auth.slice(7)
    if (isApiKeyPrefix(token)) return token
  }
  try {
    const url = new URL(request.url)
    const keyParam = url.searchParams.get('api_key')
    if (keyParam && isApiKeyPrefix(keyParam)) return keyParam
  } catch { /* ignore */ }
  return null
}

/** Copied from worker/index.ts line ~460 */
function extractSessionToken(request: Request): string | null {
  const auth = request.headers.get('authorization')
  if (auth?.startsWith('Bearer ses_')) return auth.slice(7)
  return null
}

/** Copied from worker/index.ts line ~105 */
async function hashToken(token: string): Promise<string> {
  const data = new TextEncoder().encode(token)
  const hashBuffer = await crypto.subtle.digest('SHA-256', data)
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

/** Copied from worker/index.ts line ~470 */
async function resolveIdentityId(request: Request, env: { SESSIONS: { get: (key: string) => Promise<string | null> } }): Promise<string | null> {
  const apiKey = extractApiKey(request)
  if (apiKey) {
    return env.SESSIONS.get(`apikey:${apiKey}`)
  }
  const sessionToken = extractSessionToken(request)
  if (sessionToken) {
    return env.SESSIONS.get(`session:${sessionToken}`)
  }
  return null
}

/** Copied from worker/index.ts line ~492 */
async function resolveIdentityFromClaim(claimToken: string, env: { SESSIONS: { get: (key: string) => Promise<string | null> } }): Promise<string | null> {
  if (!claimToken?.startsWith('clm_')) return null
  return env.SESSIONS.get(`claim:${claimToken}`)
}

/**
 * Copied from worker/index.ts line ~164-173
 * Re-implement JWKS cache logic for testing.
 */
const jwksCache = new Map<string, { verifier: unknown; expiry: number }>()

function getJwksVerifier(jwksUri: string, createVerifier: (uri: string) => unknown): unknown {
  const now = Date.now()
  const cached = jwksCache.get(jwksUri)
  if (cached && cached.expiry > now) return cached.verifier
  const verifier = createVerifier(jwksUri)
  jwksCache.set(jwksUri, { verifier, expiry: now + 3600 * 1000 })
  return verifier
}

// ============================================================================
// Mock Factory Helpers
// ============================================================================

function createMockKV(data: Record<string, string> = {}) {
  return {
    get: vi.fn(async (key: string) => data[key] ?? null),
    put: vi.fn(async () => {}),
    delete: vi.fn(async () => {}),
  }
}

function createMockIdentityDO(options: {
  session?: { valid: boolean; identityId?: string; level?: number; expiresAt?: number }
  apiKey?: { valid: boolean; identityId?: string; scopes?: string[] }
  identity?: { id: string; name?: string; email?: string; level?: number; frozen?: boolean } | null
} = {}) {
  return {
    getSession: vi.fn(async () => options.session ?? { valid: false }),
    validateApiKey: vi.fn(async () => options.apiKey ?? { valid: false }),
    getIdentity: vi.fn(async () => options.identity ?? null),
    provisionAnonymous: vi.fn(),
    claim: vi.fn(),
    createApiKey: vi.fn(),
    listApiKeys: vi.fn(),
    revokeApiKey: vi.fn(),
    checkRateLimit: vi.fn(),
    verifyClaimToken: vi.fn(),
    freezeIdentity: vi.fn(),
    mcpSearch: vi.fn(),
    mcpFetch: vi.fn(),
    mcpDo: vi.fn(),
    oauthStorageOp: vi.fn(),
    writeAuditEvent: vi.fn(),
    queryAuditLog: vi.fn(),
  }
}

function createMockIdentityNS(stubMap: Record<string, ReturnType<typeof createMockIdentityDO>> = {}) {
  const defaultStub = createMockIdentityDO()
  return {
    idFromName: vi.fn((name: string) => ({ name })),
    get: vi.fn((id: { name: string }) => stubMap[id.name] ?? defaultStub),
  }
}

/**
 * Create a mock Cache API
 */
function createMockCache() {
  const store = new Map<string, Response>()
  return {
    match: vi.fn(async (req: Request) => store.get(req.url) ?? undefined),
    put: vi.fn(async (req: Request, res: Response) => { store.set(req.url, res) }),
    delete: vi.fn(async (req: Request) => store.delete(req.url)),
    _store: store,
  }
}

// ============================================================================
// AuthService Mock
//
// We can't import WorkerEntrypoint in test env, so we create a mock class
// that replicates the AuthService logic from worker/index.ts.
// This tests the LOGIC, not the Cloudflare runtime integration.
// ============================================================================

const TOKEN_CACHE_TTL = 5 * 60

class MockAuthService {
  env: {
    SESSIONS: ReturnType<typeof createMockKV>
    IDENTITY: ReturnType<typeof createMockIdentityNS>
    WORKOS_CLIENT_ID?: string
    WORKOS_API_KEY?: string
  }

  private _validateWorkOSApiKey: (apiKey: string, workosApiKey: string) => Promise<{ valid: boolean; id?: string; name?: string; organization_id?: string; permissions?: string[] }>
  private _verifyOwnJWT: (token: string) => Promise<AuthUser | null>
  private _verifyWorkOSJWT: (token: string) => Promise<AuthUser | null>
  private _getCachedUser: (token: string) => Promise<AuthUser | null>
  private _cacheUser: (token: string, user: AuthUser) => Promise<void>
  private _invalidateCachedToken: (token: string) => Promise<boolean>

  constructor(
    env: typeof MockAuthService.prototype.env,
    options: {
      validateWorkOSApiKey?: typeof MockAuthService.prototype._validateWorkOSApiKey
      verifyOwnJWT?: typeof MockAuthService.prototype._verifyOwnJWT
      verifyWorkOSJWT?: typeof MockAuthService.prototype._verifyWorkOSJWT
      getCachedUser?: typeof MockAuthService.prototype._getCachedUser
      cacheUser?: typeof MockAuthService.prototype._cacheUser
      invalidateCachedToken?: typeof MockAuthService.prototype._invalidateCachedToken
    } = {},
  ) {
    this.env = env
    this._validateWorkOSApiKey = options.validateWorkOSApiKey ?? (async () => ({ valid: false }))
    this._verifyOwnJWT = options.verifyOwnJWT ?? (async () => null)
    this._verifyWorkOSJWT = options.verifyWorkOSJWT ?? (async () => null)
    this._getCachedUser = options.getCachedUser ?? (async () => null)
    this._cacheUser = options.cacheUser ?? (async () => {})
    this._invalidateCachedToken = options.invalidateCachedToken ?? (async () => false)
  }

  async verifyToken(token: string): Promise<VerifyResult> {
    // Check cache first
    const cached = await this._getCachedUser(token)
    if (cached) return { valid: true, user: cached, cached: true }

    // Session token (ses_*)
    if (token.startsWith('ses_')) {
      const identityId = await this.env.SESSIONS.get(`session:${token}`)
      if (!identityId) return { valid: false, error: 'Invalid or expired session' }

      const id = this.env.IDENTITY.idFromName(identityId)
      const stub = this.env.IDENTITY.get(id) as unknown as ReturnType<typeof createMockIdentityDO>
      const session = await stub.getSession(token)
      if (!session?.valid) return { valid: false, error: 'Invalid session' }

      const identity = await stub.getIdentity(identityId)
      const user: AuthUser = {
        id: identityId,
        name: identity?.name,
        email: identity?.email,
        organizationId: identity?.name,
        permissions: ['read', 'write', 'delete', 'search', 'fetch', 'do', 'try', 'claim'],
      }
      await this._cacheUser(token, user)
      return { valid: true, user }
    }

    // API key (oai_* or hly_sk_*)
    if (token.startsWith('oai_') || token.startsWith('hly_sk_')) {
      const identityId = await this.env.SESSIONS.get(`apikey:${token}`)
      if (!identityId) return { valid: false, error: 'Invalid API key' }

      const id = this.env.IDENTITY.idFromName(identityId)
      const stub = this.env.IDENTITY.get(id) as unknown as ReturnType<typeof createMockIdentityDO>
      const result = await stub.validateApiKey(token)
      if (!result?.valid) return { valid: false, error: 'Invalid or revoked API key' }

      const identity = await stub.getIdentity(identityId)
      const user: AuthUser = {
        id: identityId,
        name: identity?.name,
        email: identity?.email,
        organizationId: identity?.name,
        permissions: result.scopes || ['read', 'write', 'export', 'webhook'],
      }
      await this._cacheUser(token, user)
      return { valid: true, user }
    }

    // WorkOS API key (sk_*) — validated against WorkOS API
    if (token.startsWith('sk_') && this.env.WORKOS_API_KEY) {
      const result = await this._validateWorkOSApiKey(token, this.env.WORKOS_API_KEY)
      if (result.valid) {
        const user: AuthUser = {
          id: result.id || 'workos-key',
          name: result.name,
          organizationId: result.organization_id,
          permissions: result.permissions || ['read', 'write'],
        }
        await this._cacheUser(token, user)
        return { valid: true, user }
      }
      return { valid: false, error: 'Invalid WorkOS API key' }
    }

    // JWT — try our own JWKS first, then WorkOS JWKS
    const ownUser = await this._verifyOwnJWT(token)
    if (ownUser) {
      await this._cacheUser(token, ownUser)
      return { valid: true, user: ownUser }
    }

    const workosUser = await this._verifyWorkOSJWT(token)
    if (workosUser) {
      await this._cacheUser(token, workosUser)
      return { valid: true, user: workosUser }
    }

    return { valid: false, error: 'Unrecognized token format. Use ses_* (session), oai_*/hly_sk_* (API key), sk_* (WorkOS key), or a JWT.' }
  }

  async getUser(token: string): Promise<AuthUser | null> {
    const result = await this.verifyToken(token)
    return result.valid ? result.user : null
  }

  async authenticate(authorization?: string | null, cookie?: string | null): Promise<AuthRPCResult> {
    let token: string | null = null

    if (authorization?.startsWith('Bearer ')) {
      token = authorization.slice(7)
    }

    if (!token && cookie) {
      token = parseCookieValue(cookie, 'auth') ?? parseCookieValue(cookie, 'wos-session') ?? null
    }

    if (!token) {
      return { ok: false, status: 401, error: 'No credentials provided' }
    }

    const result = await this.verifyToken(token)
    if (result.valid) {
      return { ok: true, user: result.user }
    }
    return { ok: false, status: 401, error: result.error }
  }

  async hasRoles(token: string, roles: string[]): Promise<boolean> {
    const user = await this.getUser(token)
    if (!user) return false
    const userRoles = user.roles || []
    return roles.some((r) => userRoles.includes(r))
  }

  async hasPermissions(token: string, permissions: string[]): Promise<boolean> {
    const user = await this.getUser(token)
    if (!user) return false
    const userPerms = user.permissions || []
    return permissions.every((p) => userPerms.includes(p))
  }

  async isAdmin(token: string): Promise<boolean> {
    return this.hasRoles(token, ['admin', 'superadmin'])
  }

  async invalidate(token: string): Promise<boolean> {
    await this._invalidateCachedToken(token)

    if (token.startsWith('ses_')) {
      await this.env.SESSIONS.delete(`session:${token}`)
      return true
    }

    if (token.startsWith('oai_') || token.startsWith('hly_sk_')) {
      await this.env.SESSIONS.delete(`apikey:${token}`)
      return true
    }

    return true
  }
}

// ============================================================================
// 1. parseCookieValue Tests
// ============================================================================

describe('parseCookieValue', () => {
  it('extracts a named cookie from a simple header', () => {
    expect(parseCookieValue('auth=abc123', 'auth')).toBe('abc123')
  })

  it('extracts a named cookie from multiple cookies', () => {
    expect(parseCookieValue('foo=bar; auth=token123; baz=qux', 'auth')).toBe('token123')
  })

  it('returns null for a missing cookie name', () => {
    expect(parseCookieValue('foo=bar; baz=qux', 'auth')).toBeNull()
  })

  it('handles URL-encoded values', () => {
    expect(parseCookieValue('auth=hello%20world', 'auth')).toBe('hello world')
  })

  it('handles URL-encoded special characters', () => {
    expect(parseCookieValue('token=a%3Db%26c%3Dd', 'token')).toBe('a=b&c=d')
  })

  it('extracts the first cookie when name appears at the start', () => {
    expect(parseCookieValue('auth=first; other=second', 'auth')).toBe('first')
  })

  it('returns empty string for cookie with empty value', () => {
    expect(parseCookieValue('auth=', 'auth')).toBe('')
  })

  it('handles wos-session cookie', () => {
    expect(parseCookieValue('wos-session=jwt_token_here; auth=other', 'wos-session')).toBe('jwt_token_here')
  })

  it('does not match partial cookie names', () => {
    // 'auth-token' should not match 'auth' since the regex requires = after name
    expect(parseCookieValue('auth-token=value', 'auth')).toBeNull()
  })

  it('handles cookies with spaces in values', () => {
    expect(parseCookieValue('msg=hello%20there', 'msg')).toBe('hello there')
  })

  it('handles cookie at the very end of header', () => {
    expect(parseCookieValue('foo=bar; auth=lastvalue', 'auth')).toBe('lastvalue')
  })

  it('handles percent-encoded JWT-like value', () => {
    const encoded = encodeURIComponent('eyJhbGciOiJSUzI1NiJ9.payload.sig')
    expect(parseCookieValue(`auth=${encoded}`, 'auth')).toBe('eyJhbGciOiJSUzI1NiJ9.payload.sig')
  })
})

// ============================================================================
// 2. hashToken Tests
// ============================================================================

describe('hashToken', () => {
  it('returns a 64-char hex string', async () => {
    const hash = await hashToken('test_token')
    expect(hash).toHaveLength(64)
    expect(hash).toMatch(/^[0-9a-f]{64}$/)
  })

  it('produces consistent output for same input', async () => {
    const hash1 = await hashToken('same_token')
    const hash2 = await hashToken('same_token')
    expect(hash1).toBe(hash2)
  })

  it('produces different output for different inputs', async () => {
    const hash1 = await hashToken('token_a')
    const hash2 = await hashToken('token_b')
    expect(hash1).not.toBe(hash2)
  })

  it('handles empty string input', async () => {
    const hash = await hashToken('')
    expect(hash).toHaveLength(64)
    expect(hash).toMatch(/^[0-9a-f]{64}$/)
  })

  it('handles unicode input', async () => {
    const hash = await hashToken('token_with_emoji_\u{1F600}')
    expect(hash).toHaveLength(64)
    expect(hash).toMatch(/^[0-9a-f]{64}$/)
  })

  it('handles very long input', async () => {
    const longToken = 'x'.repeat(10000)
    const hash = await hashToken(longToken)
    expect(hash).toHaveLength(64)
    expect(hash).toMatch(/^[0-9a-f]{64}$/)
  })
})

// ============================================================================
// 3. isApiKeyPrefix Tests
// ============================================================================

describe('isApiKeyPrefix', () => {
  it('recognizes oai_ prefix', () => {
    expect(isApiKeyPrefix('oai_abc123')).toBe(true)
  })

  it('recognizes hly_sk_ prefix', () => {
    expect(isApiKeyPrefix('hly_sk_test123')).toBe(true)
  })

  it('recognizes sk_ prefix', () => {
    expect(isApiKeyPrefix('sk_live_abc')).toBe(true)
  })

  it('rejects ses_ prefix', () => {
    expect(isApiKeyPrefix('ses_token123')).toBe(false)
  })

  it('rejects arbitrary string', () => {
    expect(isApiKeyPrefix('some_random_token')).toBe(false)
  })

  it('rejects empty string', () => {
    expect(isApiKeyPrefix('')).toBe(false)
  })

  it('rejects JWT-like string', () => {
    expect(isApiKeyPrefix('eyJhbGciOiJSUzI1NiJ9')).toBe(false)
  })

  it('rejects clm_ prefix', () => {
    expect(isApiKeyPrefix('clm_claim_token')).toBe(false)
  })

  it('recognizes bare oai_ prefix with no suffix', () => {
    expect(isApiKeyPrefix('oai_')).toBe(true)
  })

  it('recognizes bare sk_ prefix with no suffix', () => {
    expect(isApiKeyPrefix('sk_')).toBe(true)
  })
})

// ============================================================================
// 4. extractApiKey Tests
// ============================================================================

describe('extractApiKey', () => {
  it('extracts oai_ key from X-API-Key header', () => {
    const request = new Request('https://id.org.ai/mcp', {
      headers: { 'X-API-Key': 'oai_key_from_header' },
    })
    expect(extractApiKey(request)).toBe('oai_key_from_header')
  })

  it('extracts hly_sk_ key from X-API-Key header', () => {
    const request = new Request('https://id.org.ai/mcp', {
      headers: { 'X-API-Key': 'hly_sk_mykey' },
    })
    expect(extractApiKey(request)).toBe('hly_sk_mykey')
  })

  it('extracts sk_ key from X-API-Key header', () => {
    const request = new Request('https://id.org.ai/mcp', {
      headers: { 'X-API-Key': 'sk_test_abc' },
    })
    expect(extractApiKey(request)).toBe('sk_test_abc')
  })

  it('extracts oai_ key from Bearer header', () => {
    const request = new Request('https://id.org.ai/mcp', {
      headers: { Authorization: 'Bearer oai_bearer_key' },
    })
    expect(extractApiKey(request)).toBe('oai_bearer_key')
  })

  it('extracts hly_sk_ key from Bearer header', () => {
    const request = new Request('https://id.org.ai/mcp', {
      headers: { Authorization: 'Bearer hly_sk_bearer' },
    })
    expect(extractApiKey(request)).toBe('hly_sk_bearer')
  })

  it('extracts sk_ key from Bearer header', () => {
    const request = new Request('https://id.org.ai/mcp', {
      headers: { Authorization: 'Bearer sk_live_key' },
    })
    expect(extractApiKey(request)).toBe('sk_live_key')
  })

  it('extracts key from query parameter', () => {
    const request = new Request('https://id.org.ai/mcp?api_key=oai_query_key')
    expect(extractApiKey(request)).toBe('oai_query_key')
  })

  it('returns null for non-API-key Bearer token', () => {
    const request = new Request('https://id.org.ai/mcp', {
      headers: { Authorization: 'Bearer ses_session_token' },
    })
    expect(extractApiKey(request)).toBeNull()
  })

  it('returns null for JWT Bearer token', () => {
    const request = new Request('https://id.org.ai/mcp', {
      headers: { Authorization: 'Bearer eyJhbGciOiJSUzI1NiJ9.payload.sig' },
    })
    expect(extractApiKey(request)).toBeNull()
  })

  it('returns null when no credentials present', () => {
    const request = new Request('https://id.org.ai/mcp')
    expect(extractApiKey(request)).toBeNull()
  })

  it('ignores non-API-key X-API-Key header', () => {
    const request = new Request('https://id.org.ai/mcp', {
      headers: { 'X-API-Key': 'not_a_valid_prefix' },
    })
    expect(extractApiKey(request)).toBeNull()
  })

  it('prefers X-API-Key header over Bearer', () => {
    const request = new Request('https://id.org.ai/mcp', {
      headers: {
        'X-API-Key': 'oai_from_header',
        Authorization: 'Bearer oai_from_bearer',
      },
    })
    expect(extractApiKey(request)).toBe('oai_from_header')
  })

  it('ignores non-API-key query parameter', () => {
    const request = new Request('https://id.org.ai/mcp?api_key=not_valid_prefix')
    expect(extractApiKey(request)).toBeNull()
  })

  it('extracts sk_ key from query parameter', () => {
    const request = new Request('https://id.org.ai/mcp?api_key=sk_test_query')
    expect(extractApiKey(request)).toBe('sk_test_query')
  })

  it('falls through to Bearer when X-API-Key has non-API-key value', () => {
    const request = new Request('https://id.org.ai/mcp', {
      headers: {
        'X-API-Key': 'not_valid',
        Authorization: 'Bearer oai_from_bearer',
      },
    })
    expect(extractApiKey(request)).toBe('oai_from_bearer')
  })
})

// ============================================================================
// 5. extractSessionToken Tests
// ============================================================================

describe('extractSessionToken', () => {
  it('extracts ses_ token from Bearer header', () => {
    const request = new Request('https://id.org.ai/mcp', {
      headers: { Authorization: 'Bearer ses_abc123' },
    })
    expect(extractSessionToken(request)).toBe('ses_abc123')
  })

  it('returns null for non-ses_ Bearer token', () => {
    const request = new Request('https://id.org.ai/mcp', {
      headers: { Authorization: 'Bearer oai_key123' },
    })
    expect(extractSessionToken(request)).toBeNull()
  })

  it('returns null when no Authorization header', () => {
    const request = new Request('https://id.org.ai/mcp')
    expect(extractSessionToken(request)).toBeNull()
  })

  it('returns null for Basic auth header', () => {
    const request = new Request('https://id.org.ai/mcp', {
      headers: { Authorization: 'Basic dXNlcjpwYXNz' },
    })
    expect(extractSessionToken(request)).toBeNull()
  })

  it('returns the full session token including prefix', () => {
    const request = new Request('https://id.org.ai/mcp', {
      headers: { Authorization: 'Bearer ses_long_session_token_value_here' },
    })
    expect(extractSessionToken(request)).toBe('ses_long_session_token_value_here')
  })

  it('returns null for JWT in Bearer header', () => {
    const request = new Request('https://id.org.ai/mcp', {
      headers: { Authorization: 'Bearer eyJhbGciOiJSUzI1NiJ9.payload.sig' },
    })
    expect(extractSessionToken(request)).toBeNull()
  })
})

// ============================================================================
// 6. resolveIdentityId Tests
// ============================================================================

describe('resolveIdentityId', () => {
  it('resolves identity from API key via KV', async () => {
    const env = { SESSIONS: createMockKV({ 'apikey:oai_key123': 'identity-abc' }) }
    const request = new Request('https://id.org.ai/mcp', {
      headers: { 'X-API-Key': 'oai_key123' },
    })
    const result = await resolveIdentityId(request, env)
    expect(result).toBe('identity-abc')
    expect(env.SESSIONS.get).toHaveBeenCalledWith('apikey:oai_key123')
  })

  it('resolves identity from session token via KV', async () => {
    const env = { SESSIONS: createMockKV({ 'session:ses_tok123': 'identity-xyz' }) }
    const request = new Request('https://id.org.ai/mcp', {
      headers: { Authorization: 'Bearer ses_tok123' },
    })
    const result = await resolveIdentityId(request, env)
    expect(result).toBe('identity-xyz')
    expect(env.SESSIONS.get).toHaveBeenCalledWith('session:ses_tok123')
  })

  it('returns null for anonymous requests', async () => {
    const env = { SESSIONS: createMockKV() }
    const request = new Request('https://id.org.ai/mcp')
    const result = await resolveIdentityId(request, env)
    expect(result).toBeNull()
  })

  it('returns null when KV has no entry for the API key', async () => {
    const env = { SESSIONS: createMockKV() }
    const request = new Request('https://id.org.ai/mcp', {
      headers: { 'X-API-Key': 'oai_nonexistent' },
    })
    const result = await resolveIdentityId(request, env)
    expect(result).toBeNull()
  })

  it('returns null when KV has no entry for the session token', async () => {
    const env = { SESSIONS: createMockKV() }
    const request = new Request('https://id.org.ai/mcp', {
      headers: { Authorization: 'Bearer ses_nonexistent' },
    })
    const result = await resolveIdentityId(request, env)
    expect(result).toBeNull()
  })

  it('prefers API key over session token', async () => {
    const env = {
      SESSIONS: createMockKV({
        'apikey:oai_key1': 'from-apikey',
        'session:ses_tok1': 'from-session',
      }),
    }
    const request = new Request('https://id.org.ai/mcp', {
      headers: {
        'X-API-Key': 'oai_key1',
        Authorization: 'Bearer ses_tok1',
      },
    })
    const result = await resolveIdentityId(request, env)
    expect(result).toBe('from-apikey')
  })
})

// ============================================================================
// 7. resolveIdentityFromClaim Tests
// ============================================================================

describe('resolveIdentityFromClaim', () => {
  it('resolves identity from valid clm_ token via KV', async () => {
    const env = { SESSIONS: createMockKV({ 'claim:clm_abc123': 'identity-claimed' }) }
    const result = await resolveIdentityFromClaim('clm_abc123', env)
    expect(result).toBe('identity-claimed')
    expect(env.SESSIONS.get).toHaveBeenCalledWith('claim:clm_abc123')
  })

  it('returns null for non-clm_ prefix token', async () => {
    const env = { SESSIONS: createMockKV({ 'claim:ses_abc': 'should-not-reach' }) }
    const result = await resolveIdentityFromClaim('ses_abc', env)
    expect(result).toBeNull()
    expect(env.SESSIONS.get).not.toHaveBeenCalled()
  })

  it('returns null for oai_ prefix token', async () => {
    const env = { SESSIONS: createMockKV() }
    const result = await resolveIdentityFromClaim('oai_key', env)
    expect(result).toBeNull()
  })

  it('returns null for empty string', async () => {
    const env = { SESSIONS: createMockKV() }
    const result = await resolveIdentityFromClaim('', env)
    expect(result).toBeNull()
  })

  it('returns null when KV has no entry for the claim token', async () => {
    const env = { SESSIONS: createMockKV() }
    const result = await resolveIdentityFromClaim('clm_nonexistent', env)
    expect(result).toBeNull()
  })

  it('handles clm_ token with complex suffix', async () => {
    const env = { SESSIONS: createMockKV({ 'claim:clm_long-complex_token-value_123': 'identity-complex' }) }
    const result = await resolveIdentityFromClaim('clm_long-complex_token-value_123', env)
    expect(result).toBe('identity-complex')
  })
})

// ============================================================================
// 8. getJwksVerifier (JWKS Cache) Tests
// ============================================================================

describe('getJwksVerifier', () => {
  beforeEach(() => {
    jwksCache.clear()
  })

  it('creates a new verifier on first call', () => {
    const factory = vi.fn((uri: string) => ({ uri, type: 'verifier' }))
    const result = getJwksVerifier('https://id.org.ai/.well-known/jwks.json', factory)

    expect(factory).toHaveBeenCalledTimes(1)
    expect(factory).toHaveBeenCalledWith('https://id.org.ai/.well-known/jwks.json')
    expect(result).toEqual({ uri: 'https://id.org.ai/.well-known/jwks.json', type: 'verifier' })
  })

  it('returns cached verifier on subsequent calls within TTL', () => {
    const factory = vi.fn((uri: string) => ({ uri, call: factory.mock.calls.length }))

    const first = getJwksVerifier('https://id.org.ai/.well-known/jwks.json', factory)
    const second = getJwksVerifier('https://id.org.ai/.well-known/jwks.json', factory)

    expect(factory).toHaveBeenCalledTimes(1)
    expect(second).toBe(first) // Same reference, not just equal
  })

  it('creates separate verifiers for different URIs', () => {
    const factory = vi.fn((uri: string) => ({ uri }))

    const v1 = getJwksVerifier('https://id.org.ai/.well-known/jwks.json', factory)
    const v2 = getJwksVerifier('https://api.workos.com/sso/jwks/client_123', factory)

    expect(factory).toHaveBeenCalledTimes(2)
    expect(v1).not.toBe(v2)
  })

  it('creates new verifier when cache entry is expired', () => {
    const factory = vi.fn((uri: string) => ({ uri, call: factory.mock.calls.length }))
    const uri = 'https://id.org.ai/.well-known/jwks.json'

    // Manually insert an expired entry
    jwksCache.set(uri, { verifier: { uri, call: 0 }, expiry: Date.now() - 1000 })

    const result = getJwksVerifier(uri, factory)

    expect(factory).toHaveBeenCalledTimes(1)
    expect(result).toEqual({ uri, call: 1 })
  })

  it('stores cache entry with 1-hour expiry', () => {
    const factory = vi.fn((uri: string) => ({ uri }))
    const uri = 'https://example.com/jwks'
    const before = Date.now()

    getJwksVerifier(uri, factory)

    const entry = jwksCache.get(uri)
    expect(entry).toBeDefined()
    // Expiry should be ~1 hour from now
    expect(entry!.expiry).toBeGreaterThanOrEqual(before + 3600 * 1000 - 100)
    expect(entry!.expiry).toBeLessThanOrEqual(before + 3600 * 1000 + 100)
  })
})

// ============================================================================
// 9. Token Verification Chain (priority order) Tests
// ============================================================================

describe('Token verification chain priority', () => {
  it('ses_ token is handled by session verification, not JWT', async () => {
    const mockKV = createMockKV()
    const mockNS = createMockIdentityNS()
    const verifyOwnJWT = vi.fn(async () => ({ id: 'jwt-user' }))

    const stub = createMockIdentityDO({
      session: { valid: true },
      identity: { id: 'ses-user' },
    })
    mockKV.get.mockResolvedValueOnce('ses-user')
    mockNS.get.mockReturnValueOnce(stub)

    const service = new MockAuthService(
      { SESSIONS: mockKV, IDENTITY: mockNS },
      { verifyOwnJWT },
    )

    const result = await service.verifyToken('ses_mytoken')

    expect(result.valid).toBe(true)
    if (result.valid) expect(result.user.id).toBe('ses-user')
    expect(verifyOwnJWT).not.toHaveBeenCalled()
  })

  it('oai_ token is handled by API key verification, not JWT', async () => {
    const mockKV = createMockKV()
    const mockNS = createMockIdentityNS()
    const verifyOwnJWT = vi.fn(async () => ({ id: 'jwt-user' }))

    const stub = createMockIdentityDO({
      apiKey: { valid: true, scopes: ['read'] },
      identity: { id: 'api-user' },
    })
    mockKV.get.mockResolvedValueOnce('api-user')
    mockNS.get.mockReturnValueOnce(stub)

    const service = new MockAuthService(
      { SESSIONS: mockKV, IDENTITY: mockNS },
      { verifyOwnJWT },
    )

    const result = await service.verifyToken('oai_mykey')

    expect(result.valid).toBe(true)
    if (result.valid) expect(result.user.id).toBe('api-user')
    expect(verifyOwnJWT).not.toHaveBeenCalled()
  })

  it('hly_sk_ token is handled by API key verification', async () => {
    const mockKV = createMockKV()
    const mockNS = createMockIdentityNS()

    const stub = createMockIdentityDO({
      apiKey: { valid: true, scopes: ['read', 'write'] },
      identity: { id: 'hly-user' },
    })
    mockKV.get.mockResolvedValueOnce('hly-user')
    mockNS.get.mockReturnValueOnce(stub)

    const service = new MockAuthService(
      { SESSIONS: mockKV, IDENTITY: mockNS },
    )

    const result = await service.verifyToken('hly_sk_mykey')

    expect(result.valid).toBe(true)
    if (result.valid) expect(result.user.id).toBe('hly-user')
  })

  it('sk_ token goes to WorkOS validation when WORKOS_API_KEY is set', async () => {
    const mockKV = createMockKV()
    const mockNS = createMockIdentityNS()
    const validateWorkOS = vi.fn(async () => ({ valid: true, id: 'workos-id' }))

    const service = new MockAuthService(
      { SESSIONS: mockKV, IDENTITY: mockNS, WORKOS_API_KEY: 'sk_platform' },
      { validateWorkOSApiKey: validateWorkOS },
    )

    const result = await service.verifyToken('sk_test_mykey')

    expect(validateWorkOS).toHaveBeenCalledWith('sk_test_mykey', 'sk_platform')
    expect(result.valid).toBe(true)
  })

  it('sk_ token falls through to JWT when WORKOS_API_KEY is not set', async () => {
    const mockKV = createMockKV()
    const mockNS = createMockIdentityNS()
    const verifyOwnJWT = vi.fn(async () => ({ id: 'jwt-fallback' }))

    const service = new MockAuthService(
      { SESSIONS: mockKV, IDENTITY: mockNS }, // no WORKOS_API_KEY
      { verifyOwnJWT },
    )

    const result = await service.verifyToken('sk_test_noconfig')

    expect(verifyOwnJWT).toHaveBeenCalledWith('sk_test_noconfig')
    expect(result.valid).toBe(true)
    if (result.valid) expect(result.user.id).toBe('jwt-fallback')
  })

  it('own JWT is tried before WorkOS JWT', async () => {
    const mockKV = createMockKV()
    const mockNS = createMockIdentityNS()
    const verifyOwnJWT = vi.fn(async () => ({ id: 'own-jwt-user' }))
    const verifyWorkOSJWT = vi.fn(async () => ({ id: 'workos-jwt-user' }))

    const service = new MockAuthService(
      { SESSIONS: mockKV, IDENTITY: mockNS },
      { verifyOwnJWT, verifyWorkOSJWT },
    )

    const result = await service.verifyToken('eyJ.test.jwt')

    expect(verifyOwnJWT).toHaveBeenCalled()
    expect(verifyWorkOSJWT).not.toHaveBeenCalled()
    if (result.valid) expect(result.user.id).toBe('own-jwt-user')
  })

  it('WorkOS JWT is tried only when own JWT verification fails', async () => {
    const mockKV = createMockKV()
    const mockNS = createMockIdentityNS()
    const verifyOwnJWT = vi.fn(async () => null)
    const verifyWorkOSJWT = vi.fn(async () => ({ id: 'workos-jwt-user' }))

    const service = new MockAuthService(
      { SESSIONS: mockKV, IDENTITY: mockNS },
      { verifyOwnJWT, verifyWorkOSJWT },
    )

    const result = await service.verifyToken('eyJ.test.jwt')

    expect(verifyOwnJWT).toHaveBeenCalled()
    expect(verifyWorkOSJWT).toHaveBeenCalled()
    if (result.valid) expect(result.user.id).toBe('workos-jwt-user')
  })
})

// ============================================================================
// AuthService.verifyToken Tests
// ============================================================================

describe('AuthService.verifyToken', () => {
  let service: MockAuthService
  let mockKV: ReturnType<typeof createMockKV>
  let mockNS: ReturnType<typeof createMockIdentityNS>
  let cacheUserSpy: ReturnType<typeof vi.fn>

  beforeEach(() => {
    mockKV = createMockKV()
    mockNS = createMockIdentityNS()
    cacheUserSpy = vi.fn()
    service = new MockAuthService(
      { SESSIONS: mockKV, IDENTITY: mockNS },
      { cacheUser: cacheUserSpy },
    )
  })

  // -- Session tokens (ses_*) --

  describe('Session tokens (ses_*)', () => {
    it('returns valid user for valid session', async () => {
      const stub = createMockIdentityDO({
        session: { valid: true, identityId: 'id-1', level: 1, expiresAt: Date.now() + 86400000 },
        identity: { id: 'id-1', name: 'Test User', email: 'test@example.com', level: 1 },
      })
      mockKV.get.mockResolvedValueOnce('id-1')
      mockNS.get.mockReturnValueOnce(stub)

      const result = await service.verifyToken('ses_validtoken123')

      expect(result.valid).toBe(true)
      if (result.valid) {
        expect(result.user.id).toBe('id-1')
        expect(result.user.name).toBe('Test User')
        expect(result.user.email).toBe('test@example.com')
        expect(result.user.permissions).toContain('read')
        expect(result.user.permissions).toContain('write')
        expect(result.user.permissions).toContain('delete')
        expect(result.user.permissions).toContain('do')
        expect(result.user.permissions).toContain('try')
        expect(result.user.permissions).toContain('claim')
      }
    })

    it('caches user after successful session verification', async () => {
      const stub = createMockIdentityDO({
        session: { valid: true, identityId: 'id-1' },
        identity: { id: 'id-1', name: 'Alice' },
      })
      mockKV.get.mockResolvedValueOnce('id-1')
      mockNS.get.mockReturnValueOnce(stub)

      await service.verifyToken('ses_tok')

      expect(cacheUserSpy).toHaveBeenCalledTimes(1)
      expect(cacheUserSpy).toHaveBeenCalledWith('ses_tok', expect.objectContaining({ id: 'id-1' }))
    })

    it('returns error for session token not found in KV', async () => {
      mockKV.get.mockResolvedValueOnce(null)

      const result = await service.verifyToken('ses_missing')

      expect(result.valid).toBe(false)
      if (!result.valid) {
        expect(result.error).toBe('Invalid or expired session')
      }
    })

    it('returns error for invalid session in DO', async () => {
      const stub = createMockIdentityDO({ session: { valid: false } })
      mockKV.get.mockResolvedValueOnce('id-2')
      mockNS.get.mockReturnValueOnce(stub)

      const result = await service.verifyToken('ses_invalid')

      expect(result.valid).toBe(false)
      if (!result.valid) {
        expect(result.error).toBe('Invalid session')
      }
    })

    it('sets organizationId to identity name', async () => {
      const stub = createMockIdentityDO({
        session: { valid: true },
        identity: { id: 'id-org', name: 'acme-corp' },
      })
      mockKV.get.mockResolvedValueOnce('id-org')
      mockNS.get.mockReturnValueOnce(stub)

      const result = await service.verifyToken('ses_orgtest')

      expect(result.valid).toBe(true)
      if (result.valid) {
        expect(result.user.organizationId).toBe('acme-corp')
      }
    })

    it('handles session with null identity gracefully', async () => {
      const stub = createMockIdentityDO({
        session: { valid: true },
        identity: null,
      })
      mockKV.get.mockResolvedValueOnce('id-null')
      mockNS.get.mockReturnValueOnce(stub)

      const result = await service.verifyToken('ses_nullident')

      expect(result.valid).toBe(true)
      if (result.valid) {
        expect(result.user.id).toBe('id-null')
        expect(result.user.name).toBeUndefined()
        expect(result.user.email).toBeUndefined()
      }
    })
  })

  // -- API keys (oai_* / hly_sk_*) --

  describe('API keys (oai_* / hly_sk_*)', () => {
    it('returns valid user for valid oai_ key with scopes', async () => {
      const stub = createMockIdentityDO({
        apiKey: { valid: true, identityId: 'id-api', scopes: ['read', 'write', 'admin'] },
        identity: { id: 'id-api', name: 'API User', email: 'api@example.com' },
      })
      mockKV.get.mockResolvedValueOnce('id-api')
      mockNS.get.mockReturnValueOnce(stub)

      const result = await service.verifyToken('oai_validkey123')

      expect(result.valid).toBe(true)
      if (result.valid) {
        expect(result.user.id).toBe('id-api')
        expect(result.user.permissions).toEqual(['read', 'write', 'admin'])
      }
    })

    it('returns default permissions when scopes are not set', async () => {
      const stub = createMockIdentityDO({
        apiKey: { valid: true, identityId: 'id-api' },
        identity: { id: 'id-api' },
      })
      mockKV.get.mockResolvedValueOnce('id-api')
      mockNS.get.mockReturnValueOnce(stub)

      const result = await service.verifyToken('oai_noscopes')

      expect(result.valid).toBe(true)
      if (result.valid) {
        expect(result.user.permissions).toEqual(['read', 'write', 'export', 'webhook'])
      }
    })

    it('returns valid user for hly_sk_ key', async () => {
      const stub = createMockIdentityDO({
        apiKey: { valid: true, identityId: 'id-hly', scopes: ['read'] },
        identity: { id: 'id-hly', name: 'HLY User' },
      })
      mockKV.get.mockResolvedValueOnce('id-hly')
      mockNS.get.mockReturnValueOnce(stub)

      const result = await service.verifyToken('hly_sk_keyvalue')

      expect(result.valid).toBe(true)
      if (result.valid) {
        expect(result.user.id).toBe('id-hly')
        expect(result.user.name).toBe('HLY User')
      }
    })

    it('returns error when API key not found in KV', async () => {
      mockKV.get.mockResolvedValueOnce(null)

      const result = await service.verifyToken('oai_missing')

      expect(result.valid).toBe(false)
      if (!result.valid) {
        expect(result.error).toBe('Invalid API key')
      }
    })

    it('returns error for revoked API key', async () => {
      const stub = createMockIdentityDO({
        apiKey: { valid: false },
      })
      mockKV.get.mockResolvedValueOnce('id-revoked')
      mockNS.get.mockReturnValueOnce(stub)

      const result = await service.verifyToken('oai_revokedkey')

      expect(result.valid).toBe(false)
      if (!result.valid) {
        expect(result.error).toBe('Invalid or revoked API key')
      }
    })

    it('caches user after successful API key verification', async () => {
      const stub = createMockIdentityDO({
        apiKey: { valid: true, identityId: 'id-cache', scopes: ['read'] },
        identity: { id: 'id-cache' },
      })
      mockKV.get.mockResolvedValueOnce('id-cache')
      mockNS.get.mockReturnValueOnce(stub)

      await service.verifyToken('oai_cacheable')

      expect(cacheUserSpy).toHaveBeenCalledTimes(1)
    })
  })

  // -- WorkOS API keys (sk_*) --

  describe('WorkOS API keys (sk_*)', () => {
    it('returns valid user for valid WorkOS key', async () => {
      const workosService = new MockAuthService(
        { SESSIONS: mockKV, IDENTITY: mockNS, WORKOS_API_KEY: 'sk_platform_key' },
        {
          validateWorkOSApiKey: async () => ({
            valid: true,
            id: 'workos-key-id',
            name: 'My WorkOS Key',
            organization_id: 'org_workos123',
            permissions: ['read', 'write', 'admin'],
          }),
          cacheUser: cacheUserSpy,
        },
      )

      const result = await workosService.verifyToken('sk_test_key123')

      expect(result.valid).toBe(true)
      if (result.valid) {
        expect(result.user.id).toBe('workos-key-id')
        expect(result.user.name).toBe('My WorkOS Key')
        expect(result.user.organizationId).toBe('org_workos123')
        expect(result.user.permissions).toEqual(['read', 'write', 'admin'])
      }
    })

    it('returns default permissions when WorkOS key has none', async () => {
      const workosService = new MockAuthService(
        { SESSIONS: mockKV, IDENTITY: mockNS, WORKOS_API_KEY: 'sk_platform' },
        {
          validateWorkOSApiKey: async () => ({
            valid: true,
            id: 'wk-1',
          }),
          cacheUser: cacheUserSpy,
        },
      )

      const result = await workosService.verifyToken('sk_test_noperms')

      expect(result.valid).toBe(true)
      if (result.valid) {
        expect(result.user.permissions).toEqual(['read', 'write'])
      }
    })

    it('returns fallback id when WorkOS key result has no id', async () => {
      const workosService = new MockAuthService(
        { SESSIONS: mockKV, IDENTITY: mockNS, WORKOS_API_KEY: 'sk_platform' },
        {
          validateWorkOSApiKey: async () => ({ valid: true }),
          cacheUser: cacheUserSpy,
        },
      )

      const result = await workosService.verifyToken('sk_test_noid')

      expect(result.valid).toBe(true)
      if (result.valid) {
        expect(result.user.id).toBe('workos-key')
      }
    })

    it('returns error for invalid WorkOS key', async () => {
      const workosService = new MockAuthService(
        { SESSIONS: mockKV, IDENTITY: mockNS, WORKOS_API_KEY: 'sk_platform' },
        { validateWorkOSApiKey: async () => ({ valid: false }) },
      )

      const result = await workosService.verifyToken('sk_test_invalid')

      expect(result.valid).toBe(false)
      if (!result.valid) {
        expect(result.error).toBe('Invalid WorkOS API key')
      }
    })

    it('falls through to JWT when WORKOS_API_KEY is not configured', async () => {
      // sk_ token with no WORKOS_API_KEY should skip WorkOS validation
      // and fall through to JWT verification (which returns null by default)
      const result = await service.verifyToken('sk_test_noconfig')

      expect(result.valid).toBe(false)
      if (!result.valid) {
        expect(result.error).toContain('Unrecognized token format')
      }
    })

    it('caches user after successful WorkOS key verification', async () => {
      const workosService = new MockAuthService(
        { SESSIONS: mockKV, IDENTITY: mockNS, WORKOS_API_KEY: 'sk_platform' },
        {
          validateWorkOSApiKey: async () => ({ valid: true, id: 'wk-cache' }),
          cacheUser: cacheUserSpy,
        },
      )

      await workosService.verifyToken('sk_test_cacheable')

      expect(cacheUserSpy).toHaveBeenCalledTimes(1)
    })
  })

  // -- JWT verification --

  describe('JWT verification', () => {
    it('returns valid user for own JWT', async () => {
      const jwtUser: AuthUser = {
        id: 'jwt-user-1',
        email: 'jwt@example.com',
        name: 'JWT User',
        organizationId: 'org-jwt',
        roles: ['member'],
        permissions: ['read', 'write'],
      }
      const jwtService = new MockAuthService(
        { SESSIONS: mockKV, IDENTITY: mockNS },
        {
          verifyOwnJWT: async () => jwtUser,
          cacheUser: cacheUserSpy,
        },
      )

      const result = await jwtService.verifyToken('eyJhbGciOiJSUzI1NiJ9.own.jwt')

      expect(result.valid).toBe(true)
      if (result.valid) {
        expect(result.user.id).toBe('jwt-user-1')
        expect(result.user.email).toBe('jwt@example.com')
        expect(result.user.roles).toContain('member')
      }
    })

    it('returns valid user for WorkOS JWT when own JWT fails', async () => {
      const workosUser: AuthUser = {
        id: 'workos-jwt-user',
        email: 'workos@example.com',
        organizationId: 'org_workos',
        roles: ['admin'],
        permissions: ['read', 'write', 'delete'],
      }
      const jwtService = new MockAuthService(
        { SESSIONS: mockKV, IDENTITY: mockNS },
        {
          verifyOwnJWT: async () => null,
          verifyWorkOSJWT: async () => workosUser,
          cacheUser: cacheUserSpy,
        },
      )

      const result = await jwtService.verifyToken('eyJhbGciOiJSUzI1NiJ9.workos.jwt')

      expect(result.valid).toBe(true)
      if (result.valid) {
        expect(result.user.id).toBe('workos-jwt-user')
        expect(result.user.organizationId).toBe('org_workos')
      }
    })

    it('prefers own JWT over WorkOS JWT', async () => {
      const ownUser: AuthUser = { id: 'own-jwt' }
      const workosUser: AuthUser = { id: 'workos-jwt' }
      const jwtService = new MockAuthService(
        { SESSIONS: mockKV, IDENTITY: mockNS },
        {
          verifyOwnJWT: async () => ownUser,
          verifyWorkOSJWT: async () => workosUser,
          cacheUser: cacheUserSpy,
        },
      )

      const result = await jwtService.verifyToken('eyJhbGciOiJSUzI1NiJ9.test.jwt')

      expect(result.valid).toBe(true)
      if (result.valid) {
        expect(result.user.id).toBe('own-jwt')
      }
    })

    it('returns error when both JWT verifications fail', async () => {
      const jwtService = new MockAuthService(
        { SESSIONS: mockKV, IDENTITY: mockNS },
        {
          verifyOwnJWT: async () => null,
          verifyWorkOSJWT: async () => null,
        },
      )

      const result = await jwtService.verifyToken('eyJhbGciOiJSUzI1NiJ9.bad.jwt')

      expect(result.valid).toBe(false)
      if (!result.valid) {
        expect(result.error).toContain('Unrecognized token format')
      }
    })

    it('caches user after successful JWT verification', async () => {
      const jwtService = new MockAuthService(
        { SESSIONS: mockKV, IDENTITY: mockNS },
        {
          verifyOwnJWT: async () => ({ id: 'jwt-cached' }),
          cacheUser: cacheUserSpy,
        },
      )

      await jwtService.verifyToken('eyJhbGciOiJSUzI1NiJ9.cache.jwt')

      expect(cacheUserSpy).toHaveBeenCalledTimes(1)
    })
  })

  // -- Cache behavior --

  describe('Cache behavior', () => {
    it('returns cached result without verifying again', async () => {
      const cachedUser: AuthUser = { id: 'cached-user', name: 'Cached', permissions: ['read'] }
      const cachedService = new MockAuthService(
        { SESSIONS: mockKV, IDENTITY: mockNS },
        { getCachedUser: async () => cachedUser },
      )

      const result = await cachedService.verifyToken('ses_anything')

      expect(result.valid).toBe(true)
      if (result.valid) {
        expect(result.user.id).toBe('cached-user')
        expect(result.cached).toBe(true)
      }
      // KV should NOT have been called since cache hit
      expect(mockKV.get).not.toHaveBeenCalled()
    })

    it('verifies and caches on cache miss', async () => {
      const stub = createMockIdentityDO({
        session: { valid: true },
        identity: { id: 'id-miss' },
      })
      mockKV.get.mockResolvedValueOnce('id-miss')
      mockNS.get.mockReturnValueOnce(stub)

      const result = await service.verifyToken('ses_cachemiss')

      expect(result.valid).toBe(true)
      expect(cacheUserSpy).toHaveBeenCalled()
    })

    it('cache hit skips all token type checks', async () => {
      const cachedUser: AuthUser = { id: 'any-cached' }
      const validateWorkOS = vi.fn(async () => ({ valid: true, id: 'should-not-reach' }))

      const cachedService = new MockAuthService(
        { SESSIONS: mockKV, IDENTITY: mockNS, WORKOS_API_KEY: 'sk_platform' },
        {
          getCachedUser: async () => cachedUser,
          validateWorkOSApiKey: validateWorkOS,
        },
      )

      const result = await cachedService.verifyToken('sk_test_cached')

      expect(result.valid).toBe(true)
      if (result.valid) expect(result.cached).toBe(true)
      expect(validateWorkOS).not.toHaveBeenCalled()
      expect(mockKV.get).not.toHaveBeenCalled()
    })
  })

  // -- Unrecognized format --

  describe('Unrecognized token format', () => {
    it('returns error for completely unrecognized token', async () => {
      const result = await service.verifyToken('random_garbage_string')

      expect(result.valid).toBe(false)
      if (!result.valid) {
        expect(result.error).toContain('Unrecognized token format')
        expect(result.error).toContain('ses_')
        expect(result.error).toContain('oai_')
        expect(result.error).toContain('hly_sk_')
        expect(result.error).toContain('sk_')
        expect(result.error).toContain('JWT')
      }
    })

    it('returns error for empty token', async () => {
      const result = await service.verifyToken('')

      expect(result.valid).toBe(false)
    })
  })
})

// ============================================================================
// AuthService.getUser Tests
// ============================================================================

describe('AuthService.getUser', () => {
  it('returns AuthUser for valid token', async () => {
    const stub = createMockIdentityDO({
      session: { valid: true },
      identity: { id: 'user-1', name: 'Alice', email: 'alice@test.com' },
    })
    const mockKV = createMockKV()
    mockKV.get.mockResolvedValueOnce('user-1')
    const mockNS = createMockIdentityNS()
    mockNS.get.mockReturnValueOnce(stub)

    const service = new MockAuthService({ SESSIONS: mockKV, IDENTITY: mockNS })
    const user = await service.getUser('ses_valid')

    expect(user).not.toBeNull()
    expect(user!.id).toBe('user-1')
    expect(user!.name).toBe('Alice')
  })

  it('returns null for invalid token', async () => {
    const mockKV = createMockKV()
    mockKV.get.mockResolvedValueOnce(null)
    const mockNS = createMockIdentityNS()

    const service = new MockAuthService({ SESSIONS: mockKV, IDENTITY: mockNS })
    const user = await service.getUser('ses_invalid')

    expect(user).toBeNull()
  })

  it('returns null for unrecognized token format', async () => {
    const service = new MockAuthService({ SESSIONS: createMockKV(), IDENTITY: createMockIdentityNS() })
    const user = await service.getUser('totally_unknown')

    expect(user).toBeNull()
  })
})

// ============================================================================
// 10. AuthService.authenticate Tests
// ============================================================================

describe('AuthService.authenticate', () => {
  let service: MockAuthService
  let mockKV: ReturnType<typeof createMockKV>
  let mockNS: ReturnType<typeof createMockIdentityNS>

  beforeEach(() => {
    mockKV = createMockKV()
    mockNS = createMockIdentityNS()
    service = new MockAuthService({ SESSIONS: mockKV, IDENTITY: mockNS })
  })

  it('extracts and verifies Bearer token', async () => {
    const stub = createMockIdentityDO({
      session: { valid: true },
      identity: { id: 'bearer-user', name: 'Bearer' },
    })
    mockKV.get.mockResolvedValueOnce('bearer-user')
    mockNS.get.mockReturnValueOnce(stub)

    const result = await service.authenticate('Bearer ses_bearer123')

    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.user.id).toBe('bearer-user')
    }
  })

  it('extracts token from auth cookie', async () => {
    const stub = createMockIdentityDO({
      session: { valid: true },
      identity: { id: 'cookie-user' },
    })
    mockKV.get.mockResolvedValueOnce('cookie-user')
    mockNS.get.mockReturnValueOnce(stub)

    const result = await service.authenticate(null, 'auth=ses_fromcookie')

    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.user.id).toBe('cookie-user')
    }
  })

  it('extracts token from wos-session cookie', async () => {
    const jwtUser: AuthUser = { id: 'wos-user', name: 'WorkOS User' }
    const jwtService = new MockAuthService(
      { SESSIONS: mockKV, IDENTITY: mockNS },
      { verifyOwnJWT: async () => jwtUser },
    )

    const result = await jwtService.authenticate(null, 'wos-session=eyJhbGciOiJSUzI1NiJ9.test.jwt')

    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.user.id).toBe('wos-user')
    }
  })

  it('prefers auth cookie over wos-session cookie', async () => {
    const stub = createMockIdentityDO({
      session: { valid: true },
      identity: { id: 'auth-cookie-user' },
    })
    mockKV.get.mockResolvedValueOnce('auth-cookie-user')
    mockNS.get.mockReturnValueOnce(stub)

    const result = await service.authenticate(null, 'auth=ses_authcookie; wos-session=jwt_wos')

    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.user.id).toBe('auth-cookie-user')
    }
  })

  it('Bearer header takes priority over cookie', async () => {
    const stub = createMockIdentityDO({
      session: { valid: true },
      identity: { id: 'bearer-wins' },
    })
    mockKV.get.mockResolvedValueOnce('bearer-wins')
    mockNS.get.mockReturnValueOnce(stub)

    const result = await service.authenticate('Bearer ses_bearer', 'auth=ses_cookie')

    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.user.id).toBe('bearer-wins')
    }
  })

  it('returns 401 when no credentials provided', async () => {
    const result = await service.authenticate()

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.status).toBe(401)
      expect(result.error).toBe('No credentials provided')
    }
  })

  it('returns 401 when both params are null', async () => {
    const result = await service.authenticate(null, null)

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.status).toBe(401)
      expect(result.error).toBe('No credentials provided')
    }
  })

  it('returns 401 when authorization header is not Bearer', async () => {
    // 'Basic' auth is not supported, and cookie is empty
    const result = await service.authenticate('Basic dXNlcjpwYXNz')

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.status).toBe(401)
      expect(result.error).toBe('No credentials provided')
    }
  })

  it('returns 401 for invalid credentials', async () => {
    mockKV.get.mockResolvedValueOnce(null)

    const result = await service.authenticate('Bearer ses_invalid_session')

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.status).toBe(401)
      expect(result.error).toBe('Invalid or expired session')
    }
  })

  it('returns 401 for empty Bearer value', async () => {
    // 'Bearer ' with nothing after is treated as empty token after slice
    // which won't match any prefix, so falls through to JWT and returns unrecognized
    const result = await service.authenticate('Bearer ')

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.status).toBe(401)
    }
  })

  it('handles cookie-only auth with empty cookie header', async () => {
    const result = await service.authenticate(null, '')

    // parseCookieValue on '' will return null for both 'auth' and 'wos-session'
    // so token remains null -> 'No credentials provided'
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.status).toBe(401)
      expect(result.error).toBe('No credentials provided')
    }
  })

  it('falls back to wos-session when auth cookie is missing', async () => {
    const jwtUser: AuthUser = { id: 'wos-fallback' }
    const jwtService = new MockAuthService(
      { SESSIONS: mockKV, IDENTITY: mockNS },
      { verifyOwnJWT: async () => jwtUser },
    )

    const result = await jwtService.authenticate(null, 'other=value; wos-session=eyJ.test.jwt')

    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.user.id).toBe('wos-fallback')
    }
  })

  it('propagates specific error message from verifyToken', async () => {
    const mockKV = createMockKV()
    const mockNS = createMockIdentityNS()
    const stub = createMockIdentityDO({ apiKey: { valid: false } })
    mockKV.get.mockResolvedValueOnce('id-revoked')
    mockNS.get.mockReturnValueOnce(stub)

    const service = new MockAuthService({ SESSIONS: mockKV, IDENTITY: mockNS })
    const result = await service.authenticate('Bearer oai_revokedkey')

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.error).toBe('Invalid or revoked API key')
    }
  })
})

// ============================================================================
// 11. hasRoles / hasPermissions / isAdmin Tests
// ============================================================================

describe('AuthService.hasRoles', () => {
  it('returns true when user has one of the specified roles', async () => {
    const jwtUser: AuthUser = { id: 'u1', roles: ['member', 'editor'] }
    const service = new MockAuthService(
      { SESSIONS: createMockKV(), IDENTITY: createMockIdentityNS() },
      { verifyOwnJWT: async () => jwtUser },
    )

    const result = await service.hasRoles('eyJ.test.jwt', ['admin', 'editor'])
    expect(result).toBe(true)
  })

  it('returns false when user has none of the specified roles', async () => {
    const jwtUser: AuthUser = { id: 'u1', roles: ['member'] }
    const service = new MockAuthService(
      { SESSIONS: createMockKV(), IDENTITY: createMockIdentityNS() },
      { verifyOwnJWT: async () => jwtUser },
    )

    const result = await service.hasRoles('eyJ.test.jwt', ['admin', 'superadmin'])
    expect(result).toBe(false)
  })

  it('returns false when user has no roles', async () => {
    const jwtUser: AuthUser = { id: 'u1' }
    const service = new MockAuthService(
      { SESSIONS: createMockKV(), IDENTITY: createMockIdentityNS() },
      { verifyOwnJWT: async () => jwtUser },
    )

    const result = await service.hasRoles('eyJ.test.jwt', ['admin'])
    expect(result).toBe(false)
  })

  it('returns false for invalid token', async () => {
    const service = new MockAuthService(
      { SESSIONS: createMockKV(), IDENTITY: createMockIdentityNS() },
    )

    const result = await service.hasRoles('invalid_token', ['admin'])
    expect(result).toBe(false)
  })

  it('returns false when checking against empty roles array (some() on empty)', async () => {
    const jwtUser: AuthUser = { id: 'u1', roles: ['admin'] }
    const service = new MockAuthService(
      { SESSIONS: createMockKV(), IDENTITY: createMockIdentityNS() },
      { verifyOwnJWT: async () => jwtUser },
    )

    // some() on empty array returns false
    const result = await service.hasRoles('eyJ.test.jwt', [])
    expect(result).toBe(false)
  })

  it('uses some() semantics: any match is sufficient', async () => {
    const jwtUser: AuthUser = { id: 'u1', roles: ['viewer'] }
    const service = new MockAuthService(
      { SESSIONS: createMockKV(), IDENTITY: createMockIdentityNS() },
      { verifyOwnJWT: async () => jwtUser },
    )

    const result = await service.hasRoles('eyJ.test.jwt', ['viewer', 'admin', 'superadmin'])
    expect(result).toBe(true)
  })
})

describe('AuthService.hasPermissions', () => {
  it('returns true when user has all specified permissions', async () => {
    const jwtUser: AuthUser = { id: 'u1', permissions: ['read', 'write', 'delete'] }
    const service = new MockAuthService(
      { SESSIONS: createMockKV(), IDENTITY: createMockIdentityNS() },
      { verifyOwnJWT: async () => jwtUser },
    )

    const result = await service.hasPermissions('eyJ.test.jwt', ['read', 'write'])
    expect(result).toBe(true)
  })

  it('returns false when user is missing one permission', async () => {
    const jwtUser: AuthUser = { id: 'u1', permissions: ['read', 'write'] }
    const service = new MockAuthService(
      { SESSIONS: createMockKV(), IDENTITY: createMockIdentityNS() },
      { verifyOwnJWT: async () => jwtUser },
    )

    const result = await service.hasPermissions('eyJ.test.jwt', ['read', 'write', 'admin'])
    expect(result).toBe(false)
  })

  it('returns false when user has no permissions', async () => {
    const jwtUser: AuthUser = { id: 'u1' }
    const service = new MockAuthService(
      { SESSIONS: createMockKV(), IDENTITY: createMockIdentityNS() },
      { verifyOwnJWT: async () => jwtUser },
    )

    const result = await service.hasPermissions('eyJ.test.jwt', ['read'])
    expect(result).toBe(false)
  })

  it('returns false for invalid token', async () => {
    const service = new MockAuthService(
      { SESSIONS: createMockKV(), IDENTITY: createMockIdentityNS() },
    )

    const result = await service.hasPermissions('invalid', ['read'])
    expect(result).toBe(false)
  })

  it('returns true when checking empty permissions array (every() on empty)', async () => {
    const jwtUser: AuthUser = { id: 'u1', permissions: ['read'] }
    const service = new MockAuthService(
      { SESSIONS: createMockKV(), IDENTITY: createMockIdentityNS() },
      { verifyOwnJWT: async () => jwtUser },
    )

    // every() on empty array returns true
    const result = await service.hasPermissions('eyJ.test.jwt', [])
    expect(result).toBe(true)
  })

  it('requires ALL permissions (not just some)', async () => {
    const jwtUser: AuthUser = { id: 'u1', permissions: ['read'] }
    const service = new MockAuthService(
      { SESSIONS: createMockKV(), IDENTITY: createMockIdentityNS() },
      { verifyOwnJWT: async () => jwtUser },
    )

    const result = await service.hasPermissions('eyJ.test.jwt', ['read', 'write'])
    expect(result).toBe(false)
  })
})

describe('AuthService.isAdmin', () => {
  it('returns true for user with admin role', async () => {
    const jwtUser: AuthUser = { id: 'u1', roles: ['admin'] }
    const service = new MockAuthService(
      { SESSIONS: createMockKV(), IDENTITY: createMockIdentityNS() },
      { verifyOwnJWT: async () => jwtUser },
    )

    expect(await service.isAdmin('eyJ.test.jwt')).toBe(true)
  })

  it('returns true for user with superadmin role', async () => {
    const jwtUser: AuthUser = { id: 'u1', roles: ['superadmin'] }
    const service = new MockAuthService(
      { SESSIONS: createMockKV(), IDENTITY: createMockIdentityNS() },
      { verifyOwnJWT: async () => jwtUser },
    )

    expect(await service.isAdmin('eyJ.test.jwt')).toBe(true)
  })

  it('returns true for user with both admin and superadmin', async () => {
    const jwtUser: AuthUser = { id: 'u1', roles: ['admin', 'superadmin'] }
    const service = new MockAuthService(
      { SESSIONS: createMockKV(), IDENTITY: createMockIdentityNS() },
      { verifyOwnJWT: async () => jwtUser },
    )

    expect(await service.isAdmin('eyJ.test.jwt')).toBe(true)
  })

  it('returns false for user with member role only', async () => {
    const jwtUser: AuthUser = { id: 'u1', roles: ['member'] }
    const service = new MockAuthService(
      { SESSIONS: createMockKV(), IDENTITY: createMockIdentityNS() },
      { verifyOwnJWT: async () => jwtUser },
    )

    expect(await service.isAdmin('eyJ.test.jwt')).toBe(false)
  })

  it('returns false for user with no roles', async () => {
    const jwtUser: AuthUser = { id: 'u1' }
    const service = new MockAuthService(
      { SESSIONS: createMockKV(), IDENTITY: createMockIdentityNS() },
      { verifyOwnJWT: async () => jwtUser },
    )

    expect(await service.isAdmin('eyJ.test.jwt')).toBe(false)
  })

  it('returns false for invalid token', async () => {
    const service = new MockAuthService(
      { SESSIONS: createMockKV(), IDENTITY: createMockIdentityNS() },
    )

    expect(await service.isAdmin('bad_token')).toBe(false)
  })
})

// ============================================================================
// 12. AuthService.invalidate Tests
// ============================================================================

describe('AuthService.invalidate', () => {
  let service: MockAuthService
  let mockKV: ReturnType<typeof createMockKV>
  let invalidateCacheSpy: ReturnType<typeof vi.fn>

  beforeEach(() => {
    mockKV = createMockKV()
    invalidateCacheSpy = vi.fn(async () => true)
    service = new MockAuthService(
      { SESSIONS: mockKV, IDENTITY: createMockIdentityNS() },
      { invalidateCachedToken: invalidateCacheSpy },
    )
  })

  it('clears cache and KV for session token', async () => {
    const result = await service.invalidate('ses_torevoke')

    expect(result).toBe(true)
    expect(invalidateCacheSpy).toHaveBeenCalledWith('ses_torevoke')
    expect(mockKV.delete).toHaveBeenCalledWith('session:ses_torevoke')
  })

  it('clears cache and KV for oai_ API key', async () => {
    const result = await service.invalidate('oai_keytorevoke')

    expect(result).toBe(true)
    expect(invalidateCacheSpy).toHaveBeenCalledWith('oai_keytorevoke')
    expect(mockKV.delete).toHaveBeenCalledWith('apikey:oai_keytorevoke')
  })

  it('clears cache and KV for hly_sk_ API key', async () => {
    const result = await service.invalidate('hly_sk_keytorevoke')

    expect(result).toBe(true)
    expect(invalidateCacheSpy).toHaveBeenCalledWith('hly_sk_keytorevoke')
    expect(mockKV.delete).toHaveBeenCalledWith('apikey:hly_sk_keytorevoke')
  })

  it('clears only cache for JWT token', async () => {
    const result = await service.invalidate('eyJhbGciOiJSUzI1NiJ9.test.jwt')

    expect(result).toBe(true)
    expect(invalidateCacheSpy).toHaveBeenCalled()
    // JWT invalidation should NOT call KV delete
    expect(mockKV.delete).not.toHaveBeenCalled()
  })

  it('clears only cache for WorkOS sk_ key', async () => {
    const result = await service.invalidate('sk_test_key')

    expect(result).toBe(true)
    expect(invalidateCacheSpy).toHaveBeenCalled()
    // sk_ keys don't have KV entries managed by us
    expect(mockKV.delete).not.toHaveBeenCalled()
  })

  it('clears only cache for unrecognized token', async () => {
    const result = await service.invalidate('unknown_token')

    expect(result).toBe(true)
    expect(invalidateCacheSpy).toHaveBeenCalled()
    expect(mockKV.delete).not.toHaveBeenCalled()
  })

  it('always returns true even for unrecognized tokens', async () => {
    const result = await service.invalidate('completely_unknown_format')
    expect(result).toBe(true)
  })

  it('calls invalidateCachedToken before KV delete for session', async () => {
    const callOrder: string[] = []
    const orderedService = new MockAuthService(
      { SESSIONS: mockKV, IDENTITY: createMockIdentityNS() },
      {
        invalidateCachedToken: vi.fn(async () => {
          callOrder.push('cache')
          return true
        }),
      },
    )
    mockKV.delete.mockImplementation(async () => { callOrder.push('kv') })

    await orderedService.invalidate('ses_ordered')

    expect(callOrder).toEqual(['cache', 'kv'])
  })
})

// ============================================================================
// Integration-style Tests (full flow)
// ============================================================================

describe('AuthService integration flows', () => {
  it('authenticate -> getUser -> hasPermissions flow', async () => {
    const stub = createMockIdentityDO({
      session: { valid: true },
      identity: { id: 'flow-user', name: 'Flow User' },
    })
    const mockKV = createMockKV()
    mockKV.get.mockResolvedValue('flow-user')
    const mockNS = createMockIdentityNS()
    mockNS.get.mockReturnValue(stub)

    const service = new MockAuthService({ SESSIONS: mockKV, IDENTITY: mockNS })

    // Step 1: Authenticate
    const authResult = await service.authenticate('Bearer ses_flow')
    expect(authResult.ok).toBe(true)

    // Step 2: getUser
    const user = await service.getUser('ses_flow')
    expect(user).not.toBeNull()
    expect(user!.id).toBe('flow-user')

    // Step 3: hasPermissions (session tokens get full permissions)
    const hasPerm = await service.hasPermissions('ses_flow', ['read', 'write', 'do'])
    expect(hasPerm).toBe(true)
  })

  it('verify -> invalidate -> verify shows token no longer cached', async () => {
    const stub = createMockIdentityDO({
      session: { valid: true },
      identity: { id: 'inv-user' },
    })
    const mockKV = createMockKV()
    mockKV.get.mockResolvedValue('inv-user')
    const mockNS = createMockIdentityNS()
    mockNS.get.mockReturnValue(stub)

    let cachedUser: AuthUser | null = null
    const service = new MockAuthService(
      { SESSIONS: mockKV, IDENTITY: mockNS },
      {
        getCachedUser: async () => cachedUser,
        cacheUser: async (_t, u) => { cachedUser = u },
        invalidateCachedToken: async () => { cachedUser = null; return true },
      },
    )

    // Verify -- should populate cache
    const r1 = await service.verifyToken('ses_invtest')
    expect(r1.valid).toBe(true)
    expect(cachedUser).not.toBeNull()

    // Invalidate -- should clear cache
    await service.invalidate('ses_invtest')
    expect(cachedUser).toBeNull()

    // Verify again -- cache miss, goes to KV + DO
    const r2 = await service.verifyToken('ses_invtest')
    expect(r2.valid).toBe(true)
    if (r2.valid) {
      expect(r2.cached).toBeUndefined() // not from cache
    }
  })

  it('API key verify -> get permissions -> check admin flow', async () => {
    const jwtUser: AuthUser = {
      id: 'admin-user',
      roles: ['admin'],
      permissions: ['read', 'write', 'delete', 'admin'],
    }
    const service = new MockAuthService(
      { SESSIONS: createMockKV(), IDENTITY: createMockIdentityNS() },
      { verifyOwnJWT: async () => jwtUser },
    )

    const token = 'eyJ.admin.jwt'

    // Verify
    const result = await service.verifyToken(token)
    expect(result.valid).toBe(true)

    // Check admin
    expect(await service.isAdmin(token)).toBe(true)

    // Check permissions
    expect(await service.hasPermissions(token, ['read', 'write', 'admin'])).toBe(true)
    expect(await service.hasPermissions(token, ['read', 'write', 'admin', 'superpower'])).toBe(false)
  })

  it('WorkOS key verify -> check permissions -> invalidate flow', async () => {
    const invalidateSpy = vi.fn(async () => true)
    const service = new MockAuthService(
      { SESSIONS: createMockKV(), IDENTITY: createMockIdentityNS(), WORKOS_API_KEY: 'sk_platform' },
      {
        validateWorkOSApiKey: async () => ({
          valid: true,
          id: 'wk-flow',
          permissions: ['read', 'write', 'manage'],
        }),
        invalidateCachedToken: invalidateSpy,
      },
    )

    const token = 'sk_test_flow'

    // Verify
    const result = await service.verifyToken(token)
    expect(result.valid).toBe(true)
    if (result.valid) {
      expect(result.user.permissions).toContain('manage')
    }

    // Check permissions
    expect(await service.hasPermissions(token, ['read', 'manage'])).toBe(true)
    expect(await service.hasPermissions(token, ['admin'])).toBe(false)

    // Invalidate -- sk_ keys only clear cache
    await service.invalidate(token)
    expect(invalidateSpy).toHaveBeenCalledWith(token)
  })
})
