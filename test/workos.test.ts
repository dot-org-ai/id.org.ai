/**
 * WorkOS Module Unit Tests
 *
 * Tests for upstream authentication (auth URL building, code exchange,
 * login state encoding/decoding) and API key validation.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import {
  buildWorkOSAuthUrl,
  exchangeWorkOSCode,
  encodeLoginState,
  decodeLoginState,
} from '../src/workos/upstream'
import { validateWorkOSApiKey } from '../src/workos/apikey'

// ── Helpers ────────────────────────────────────────────────────────────

/** Build a minimal JWT with the given payload (no real signature). */
function fakeJWT(payload: Record<string, unknown>): string {
  const header = btoa(JSON.stringify({ alg: 'RS256', typ: 'JWT' }))
  const body = btoa(JSON.stringify(payload))
  const sig = btoa('fake-signature')
  return `${header}.${body}.${sig}`
}

/** Create a mock Response for fetch. */
function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function textResponse(body: string, status = 200): Response {
  return new Response(body, { status })
}

// ============================================================================
// buildWorkOSAuthUrl
// ============================================================================

describe('buildWorkOSAuthUrl', () => {
  it('returns a URL to api.workos.com/user_management/authorize', () => {
    const url = buildWorkOSAuthUrl('client_123', 'https://id.org.ai/callback', 'state_abc')
    expect(url).toContain('https://api.workos.com/user_management/authorize')
  })

  it('includes client_id parameter', () => {
    const url = buildWorkOSAuthUrl('client_123', 'https://id.org.ai/callback', 'state_abc')
    const parsed = new URL(url)
    expect(parsed.searchParams.get('client_id')).toBe('client_123')
  })

  it('includes redirect_uri parameter', () => {
    const url = buildWorkOSAuthUrl('client_123', 'https://id.org.ai/callback', 'state_abc')
    const parsed = new URL(url)
    expect(parsed.searchParams.get('redirect_uri')).toBe('https://id.org.ai/callback')
  })

  it('includes response_type=code', () => {
    const url = buildWorkOSAuthUrl('client_123', 'https://id.org.ai/callback', 'state_abc')
    const parsed = new URL(url)
    expect(parsed.searchParams.get('response_type')).toBe('code')
  })

  it('includes state parameter', () => {
    const url = buildWorkOSAuthUrl('client_123', 'https://id.org.ai/callback', 'state_abc')
    const parsed = new URL(url)
    expect(parsed.searchParams.get('state')).toBe('state_abc')
  })

  it('includes provider=authkit', () => {
    const url = buildWorkOSAuthUrl('client_123', 'https://id.org.ai/callback', 'state_abc')
    const parsed = new URL(url)
    expect(parsed.searchParams.get('provider')).toBe('authkit')
  })

  it('URL-encodes special characters in redirect_uri', () => {
    const redirectUri = 'https://id.org.ai/callback?foo=bar&baz=qux'
    const url = buildWorkOSAuthUrl('client_123', redirectUri, 'state_abc')
    const parsed = new URL(url)
    expect(parsed.searchParams.get('redirect_uri')).toBe(redirectUri)
    // The raw URL string should have the special chars encoded
    expect(url).toContain('redirect_uri=')
  })

  it('URL-encodes special characters in state', () => {
    const state = 'state+with/special=chars'
    const url = buildWorkOSAuthUrl('client_123', 'https://id.org.ai/callback', state)
    const parsed = new URL(url)
    expect(parsed.searchParams.get('state')).toBe(state)
  })

  it('URL-encodes spaces in parameters', () => {
    const url = buildWorkOSAuthUrl('client 123', 'https://id.org.ai/callback', 'my state')
    const parsed = new URL(url)
    expect(parsed.searchParams.get('client_id')).toBe('client 123')
    expect(parsed.searchParams.get('state')).toBe('my state')
  })

  it('returns a parseable URL', () => {
    const url = buildWorkOSAuthUrl('client_123', 'https://id.org.ai/callback', 'state_abc')
    expect(() => new URL(url)).not.toThrow()
  })

  it('includes exactly 5 query parameters', () => {
    const url = buildWorkOSAuthUrl('client_123', 'https://id.org.ai/callback', 'state_abc')
    const parsed = new URL(url)
    const params = Array.from(parsed.searchParams.keys())
    expect(params).toHaveLength(5)
    expect(params).toContain('client_id')
    expect(params).toContain('redirect_uri')
    expect(params).toContain('response_type')
    expect(params).toContain('state')
    expect(params).toContain('provider')
  })
})

// ============================================================================
// exchangeWorkOSCode
// ============================================================================

describe('exchangeWorkOSCode', () => {
  let mockFetch: ReturnType<typeof vi.fn>

  beforeEach(() => {
    mockFetch = vi.fn()
    vi.stubGlobal('fetch', mockFetch)
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('sends POST to api.workos.com/user_management/authenticate', async () => {
    const token = fakeJWT({ sub: 'user_1' })
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        access_token: token,
        user: { id: 'user_1', email: 'a@b.com' },
      }),
    )

    await exchangeWorkOSCode('client_123', 'sk_test_123', 'code_abc')

    expect(mockFetch).toHaveBeenCalledOnce()
    const [url, options] = mockFetch.mock.calls[0]
    expect(url).toBe('https://api.workos.com/user_management/authenticate')
    expect(options.method).toBe('POST')
  })

  it('sends correct form-encoded body with grant_type, client_id, client_secret, code', async () => {
    const token = fakeJWT({ sub: 'user_1' })
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        access_token: token,
        user: { id: 'user_1', email: 'a@b.com' },
      }),
    )

    await exchangeWorkOSCode('client_ABC', 'sk_secret', 'code_XYZ')

    const [, options] = mockFetch.mock.calls[0]
    expect(options.headers['Content-Type']).toBe('application/x-www-form-urlencoded')

    const body = new URLSearchParams(options.body)
    expect(body.get('grant_type')).toBe('authorization_code')
    expect(body.get('client_id')).toBe('client_ABC')
    expect(body.get('client_secret')).toBe('sk_secret')
    expect(body.get('code')).toBe('code_XYZ')
  })

  it('returns user data on successful response', async () => {
    const token = fakeJWT({ sub: 'user_1' })
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        access_token: token,
        refresh_token: 'rt_123',
        expires_in: 3600,
        user: { id: 'user_1', email: 'alice@example.com', first_name: 'Alice' },
      }),
    )

    const result = await exchangeWorkOSCode('client_123', 'sk_test', 'code_abc')

    expect(result.user.id).toBe('user_1')
    expect(result.user.email).toBe('alice@example.com')
    expect(result.user.first_name).toBe('Alice')
    expect(result.access_token).toBe(token)
    expect(result.refresh_token).toBe('rt_123')
    expect(result.expires_in).toBe(3600)
  })

  it('extracts role (singular) from JWT access_token payload', async () => {
    const token = fakeJWT({ sub: 'user_1', role: 'admin' })
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        access_token: token,
        user: { id: 'user_1', email: 'a@b.com' },
      }),
    )

    const result = await exchangeWorkOSCode('c', 'k', 'x')

    expect(result.user.role).toBe('admin')
    expect(result.user.roles).toEqual(['admin'])
  })

  it('extracts roles (array) from JWT access_token payload', async () => {
    const token = fakeJWT({ sub: 'user_1', roles: ['admin', 'editor'] })
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        access_token: token,
        user: { id: 'user_1', email: 'a@b.com' },
      }),
    )

    const result = await exchangeWorkOSCode('c', 'k', 'x')

    expect(result.user.roles).toEqual(['admin', 'editor'])
    expect(result.user.role).toBeUndefined()
  })

  it('merges role into roles when both are present', async () => {
    const token = fakeJWT({ sub: 'user_1', role: 'owner', roles: ['admin', 'editor'] })
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        access_token: token,
        user: { id: 'user_1', email: 'a@b.com' },
      }),
    )

    const result = await exchangeWorkOSCode('c', 'k', 'x')

    expect(result.user.role).toBe('owner')
    expect(result.user.roles).toEqual(['admin', 'editor', 'owner'])
  })

  it('extracts permissions from JWT access_token payload', async () => {
    const token = fakeJWT({ sub: 'user_1', permissions: ['read', 'write', 'delete'] })
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        access_token: token,
        user: { id: 'user_1', email: 'a@b.com' },
      }),
    )

    const result = await exchangeWorkOSCode('c', 'k', 'x')

    expect(result.user.permissions).toEqual(['read', 'write', 'delete'])
  })

  it('does not set role/roles when neither present in JWT', async () => {
    const token = fakeJWT({ sub: 'user_1' })
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        access_token: token,
        user: { id: 'user_1', email: 'a@b.com' },
      }),
    )

    const result = await exchangeWorkOSCode('c', 'k', 'x')

    expect(result.user.role).toBeUndefined()
    expect(result.user.roles).toBeUndefined()
  })

  it('throws on non-200 response', async () => {
    mockFetch.mockResolvedValueOnce(textResponse('Unauthorized', 401))

    await expect(exchangeWorkOSCode('c', 'k', 'x')).rejects.toThrow('WorkOS authentication failed: 401 - Unauthorized')
  })

  it('throws with error message including status code', async () => {
    mockFetch.mockResolvedValueOnce(textResponse('Not Found', 404))

    await expect(exchangeWorkOSCode('c', 'k', 'x')).rejects.toThrow('404')
  })

  it('throws with error message including response body', async () => {
    mockFetch.mockResolvedValueOnce(textResponse('{"error":"invalid_grant","description":"Code expired"}', 400))

    await expect(exchangeWorkOSCode('c', 'k', 'x')).rejects.toThrow('invalid_grant')
  })

  it('handles malformed JWT gracefully (non-3-part token)', async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        access_token: 'not-a-jwt',
        user: { id: 'user_1', email: 'a@b.com' },
      }),
    )

    const result = await exchangeWorkOSCode('c', 'k', 'x')

    // Should succeed but without roles/permissions
    expect(result.user.id).toBe('user_1')
    expect(result.user.role).toBeUndefined()
    expect(result.user.roles).toBeUndefined()
    expect(result.user.permissions).toBeUndefined()
  })

  it('handles malformed JWT gracefully (invalid base64 payload)', async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        access_token: 'header.!!!invalid-base64!!!.signature',
        user: { id: 'user_1', email: 'a@b.com' },
      }),
    )

    const result = await exchangeWorkOSCode('c', 'k', 'x')

    // Should succeed but without roles/permissions
    expect(result.user.id).toBe('user_1')
    expect(result.user.role).toBeUndefined()
  })

  it('handles malformed JWT gracefully (valid base64 but not JSON)', async () => {
    const nonJsonB64 = btoa('this is not json')
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        access_token: `header.${nonJsonB64}.signature`,
        user: { id: 'user_1', email: 'a@b.com' },
      }),
    )

    const result = await exchangeWorkOSCode('c', 'k', 'x')

    expect(result.user.id).toBe('user_1')
    expect(result.user.role).toBeUndefined()
  })
})

// ============================================================================
// encodeLoginState / decodeLoginState
// ============================================================================

describe('encodeLoginState / decodeLoginState', () => {
  it('round-trips csrf + continue URL', () => {
    const encoded = encodeLoginState('csrf_token_123', 'https://headless.ly/dashboard')
    const decoded = decodeLoginState(encoded)

    expect(decoded).not.toBeNull()
    expect(decoded!.csrf).toBe('csrf_token_123')
    expect(decoded!.continue).toBe('https://headless.ly/dashboard')
  })

  it('round-trips csrf without continue URL', () => {
    const encoded = encodeLoginState('csrf_only')
    const decoded = decodeLoginState(encoded)

    expect(decoded).not.toBeNull()
    expect(decoded!.csrf).toBe('csrf_only')
    expect(decoded!.continue).toBeUndefined()
  })

  it('handles special characters in continue URL', () => {
    const continueUrl = 'https://headless.ly/~acme/deals?status=open&sort=desc#top'
    const encoded = encodeLoginState('csrf_abc', continueUrl)
    const decoded = decodeLoginState(encoded)

    expect(decoded).not.toBeNull()
    expect(decoded!.continue).toBe(continueUrl)
  })

  it('handles unicode characters in continue URL', () => {
    const continueUrl = 'https://headless.ly/orgs/caf\u00e9-plus'
    const encoded = encodeLoginState('csrf_abc', continueUrl)
    const decoded = decodeLoginState(encoded)

    expect(decoded).not.toBeNull()
    expect(decoded!.continue).toBe(continueUrl)
  })

  it('produces base64url-safe output (no +, /, =)', () => {
    // Use values likely to produce +, /, = in base64
    const encoded = encodeLoginState('token+with/special==chars', 'https://example.com/path?q=a+b')
    expect(encoded).not.toContain('+')
    expect(encoded).not.toContain('/')
    expect(encoded).not.toContain('=')
  })

  it('returns null for invalid base64 state', () => {
    const result = decodeLoginState('!!!not-base64!!!')
    expect(result).toBeNull()
  })

  it('returns null for non-JSON state', () => {
    const encoded = btoa('not json at all').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
    const result = decodeLoginState(encoded)
    expect(result).toBeNull()
  })

  it('returns null for missing csrf field', () => {
    const encoded = btoa(JSON.stringify({ foo: 'bar' })).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
    const result = decodeLoginState(encoded)
    expect(result).toBeNull()
  })

  it('returns null for empty csrf field', () => {
    const encoded = btoa(JSON.stringify({ csrf: '' })).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
    const result = decodeLoginState(encoded)
    expect(result).toBeNull()
  })

  it('returns null for empty string', () => {
    const result = decodeLoginState('')
    expect(result).toBeNull()
  })

  it('handles continue explicitly set to undefined', () => {
    const encoded = encodeLoginState('csrf_x', undefined)
    const decoded = decodeLoginState(encoded)

    expect(decoded).not.toBeNull()
    expect(decoded!.csrf).toBe('csrf_x')
    expect(decoded!.continue).toBeUndefined()
  })

  it('preserves long csrf tokens', () => {
    const longCsrf = 'a'.repeat(256)
    const encoded = encodeLoginState(longCsrf, 'https://example.com')
    const decoded = decodeLoginState(encoded)

    expect(decoded).not.toBeNull()
    expect(decoded!.csrf).toBe(longCsrf)
  })
})

// ============================================================================
// validateWorkOSApiKey
// ============================================================================

describe('validateWorkOSApiKey', () => {
  let mockFetch: ReturnType<typeof vi.fn>

  beforeEach(() => {
    mockFetch = vi.fn()
    vi.stubGlobal('fetch', mockFetch)
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('returns valid: false for non-sk_ prefixed keys', async () => {
    const result = await validateWorkOSApiKey('pk_test_123', 'sk_platform_key')

    expect(result.valid).toBe(false)
    // Should not make any fetch call
    expect(mockFetch).not.toHaveBeenCalled()
  })

  it('returns valid: false for empty string key', async () => {
    const result = await validateWorkOSApiKey('', 'sk_platform_key')

    expect(result.valid).toBe(false)
    expect(mockFetch).not.toHaveBeenCalled()
  })

  it('returns valid: false for key starting with sk but no underscore', async () => {
    const result = await validateWorkOSApiKey('sknotvalid', 'sk_platform_key')

    expect(result.valid).toBe(false)
    expect(mockFetch).not.toHaveBeenCalled()
  })

  it('sends POST to api.workos.com/api_keys/validations with correct auth', async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({ id: 'key_1', name: 'Test Key' }),
    )

    await validateWorkOSApiKey('sk_test_api_key', 'sk_platform_secret')

    expect(mockFetch).toHaveBeenCalledOnce()
    const [url, options] = mockFetch.mock.calls[0]
    expect(url).toBe('https://api.workos.com/api_keys/validations')
    expect(options.method).toBe('POST')
    expect(options.headers['Content-Type']).toBe('application/json')
    expect(options.headers['Authorization']).toBe('Bearer sk_platform_secret')
  })

  it('sends the api_key in the request body', async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({ id: 'key_1', name: 'Test Key' }),
    )

    await validateWorkOSApiKey('sk_test_api_key', 'sk_platform_secret')

    const [, options] = mockFetch.mock.calls[0]
    const body = JSON.parse(options.body)
    expect(body.api_key).toBe('sk_test_api_key')
  })

  it('returns valid: true with id, name, organization_id on success', async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        id: 'key_abc123',
        name: 'Production API Key',
        organization_id: 'org_xyz',
      }),
    )

    const result = await validateWorkOSApiKey('sk_live_key', 'sk_platform')

    expect(result.valid).toBe(true)
    expect(result.id).toBe('key_abc123')
    expect(result.name).toBe('Production API Key')
    expect(result.organization_id).toBe('org_xyz')
  })

  it('returns valid: false on non-200 response', async () => {
    mockFetch.mockResolvedValueOnce(textResponse('Unauthorized', 401))

    const result = await validateWorkOSApiKey('sk_invalid', 'sk_platform')

    expect(result.valid).toBe(false)
    expect(result.id).toBeUndefined()
    expect(result.name).toBeUndefined()
  })

  it('returns valid: false on 403 forbidden response', async () => {
    mockFetch.mockResolvedValueOnce(textResponse('Forbidden', 403))

    const result = await validateWorkOSApiKey('sk_forbidden', 'sk_platform')

    expect(result.valid).toBe(false)
  })

  it('returns valid: false on 500 server error', async () => {
    mockFetch.mockResolvedValueOnce(textResponse('Internal Server Error', 500))

    const result = await validateWorkOSApiKey('sk_server_err', 'sk_platform')

    expect(result.valid).toBe(false)
  })

  it('returns valid: false on fetch error (network failure)', async () => {
    mockFetch.mockRejectedValueOnce(new Error('Network error'))

    const result = await validateWorkOSApiKey('sk_network_fail', 'sk_platform')

    expect(result.valid).toBe(false)
  })

  it('returns valid: false on fetch error (DNS failure)', async () => {
    mockFetch.mockRejectedValueOnce(new TypeError('Failed to fetch'))

    const result = await validateWorkOSApiKey('sk_dns_fail', 'sk_platform')

    expect(result.valid).toBe(false)
  })

  it('returns permissions array when present', async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        id: 'key_perm',
        name: 'Scoped Key',
        organization_id: 'org_1',
        permissions: ['read:contacts', 'write:contacts', 'delete:contacts'],
      }),
    )

    const result = await validateWorkOSApiKey('sk_scoped', 'sk_platform')

    expect(result.valid).toBe(true)
    expect(result.permissions).toEqual(['read:contacts', 'write:contacts', 'delete:contacts'])
  })

  it('returns undefined permissions when not present in response', async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        id: 'key_no_perms',
        name: 'Basic Key',
      }),
    )

    const result = await validateWorkOSApiKey('sk_basic', 'sk_platform')

    expect(result.valid).toBe(true)
    expect(result.permissions).toBeUndefined()
  })

  it('returns undefined organization_id when not present in response', async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        id: 'key_no_org',
        name: 'Personal Key',
      }),
    )

    const result = await validateWorkOSApiKey('sk_personal', 'sk_platform')

    expect(result.valid).toBe(true)
    expect(result.organization_id).toBeUndefined()
  })
})
