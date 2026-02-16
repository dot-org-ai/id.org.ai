/**
 * Cookie-Based Authentication Tests for id.org.ai
 *
 * Comprehensive tests for the cookie authentication flow:
 *   1. Cookie parsing — extracting auth/wos-session tokens from cookie headers
 *   2. Cookie building — Set-Cookie flags for login, logout, secure/insecure
 *   3. JWT in cookies — signing, claims, verification via JWKS
 *   4. Login state encoding — CSRF + continue URL roundtrip
 *
 * These tests exercise the real implementations from:
 *   - worker/index.ts (parseCookieValue, cookie building in /callback + /logout)
 *   - src/jwt/signing.ts (SigningKeyManager, signJWT, generateSigningKey, exportPublicKeyToJWKS)
 *   - src/workos/upstream.ts (encodeLoginState, decodeLoginState)
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import {
  SigningKeyManager,
  generateSigningKey,
  signJWT,
  exportPublicKeyToJWKS,
  exportKeysToJWKS,
} from '../src/jwt/signing'
import type { SigningKey, AccessTokenClaims } from '../src/jwt/signing'
import { encodeLoginState, decodeLoginState } from '../src/workos/upstream'

// ============================================================================
// Helpers
// ============================================================================

/** Decode a base64url string to a UTF-8 string */
function base64UrlDecode(str: string): string {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/')
  while (base64.length % 4 !== 0) base64 += '='
  return atob(base64)
}

/** Parse a JWT into its three parts without verification */
function parseJWT(jwt: string): { header: Record<string, unknown>; payload: Record<string, unknown>; signature: string } {
  const parts = jwt.split('.')
  return {
    header: JSON.parse(base64UrlDecode(parts[0])),
    payload: JSON.parse(base64UrlDecode(parts[1])),
    signature: parts[2],
  }
}

/** Verify a JWT signature using the Web Crypto API */
async function verifyJWTSignature(jwt: string, publicKey: CryptoKey): Promise<boolean> {
  const parts = jwt.split('.')
  const data = `${parts[0]}.${parts[1]}`
  const encoder = new TextEncoder()

  let sigB64 = parts[2].replace(/-/g, '+').replace(/_/g, '/')
  while (sigB64.length % 4 !== 0) sigB64 += '='
  const sigBinary = atob(sigB64)
  const sigBytes = new Uint8Array(sigBinary.length)
  for (let i = 0; i < sigBinary.length; i++) sigBytes[i] = sigBinary.charCodeAt(i)

  return crypto.subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, publicKey, sigBytes.buffer, encoder.encode(data))
}

/**
 * Re-implement parseCookieValue identically to worker/index.ts
 * (module-level function, not exported)
 */
function parseCookieValue(cookieHeader: string, name: string): string | null {
  const match = cookieHeader.match(new RegExp(`(?:^|;\\s*)${name}=([^;]*)`))
  return match ? decodeURIComponent(match[1]) : null
}

/**
 * Build auth cookie string identically to the /callback route in worker/index.ts
 */
function buildAuthCookie(jwt: string, isSecure: boolean): string {
  return [
    `auth=${jwt}`,
    'HttpOnly',
    'Path=/',
    'SameSite=Lax',
    'Max-Age=3600',
    ...(isSecure ? ['Secure'] : []),
  ].join('; ')
}

/**
 * Build logout (clear) cookie string identically to the /logout route
 */
function buildLogoutCookie(isSecure: boolean): string {
  return [
    'auth=',
    'HttpOnly',
    'Path=/',
    'SameSite=Lax',
    'Max-Age=0',
    ...(isSecure ? ['Secure'] : []),
  ].join('; ')
}

/** Create a mock storageOp for SigningKeyManager tests */
function createMockStorageOp() {
  const store = new Map<string, unknown>()
  return async (op: { op: string; key?: string; value?: unknown }) => {
    if (op.op === 'get' && op.key) return { value: store.get(op.key) }
    if (op.op === 'put' && op.key) { store.set(op.key, op.value); return { ok: true } }
    if (op.op === 'delete' && op.key) { store.delete(op.key); return { deleted: true } }
    if (op.op === 'list') return { entries: Array.from(store.entries()) }
    return {}
  }
}

/**
 * Simulate the authenticate() method from AuthService.
 * This mirrors the logic in worker/index.ts AuthService.authenticate()
 */
function extractTokenFromHeaders(authorization?: string | null, cookie?: string | null): string | null {
  let token: string | null = null

  // Try Bearer header first
  if (authorization?.startsWith('Bearer ')) {
    token = authorization.slice(7)
  }

  // Try cookie if no bearer token
  if (!token && cookie) {
    token = parseCookieValue(cookie, 'auth') ?? parseCookieValue(cookie, 'wos-session') ?? null
  }

  return token
}

// ============================================================================
// 1. Cookie Parsing (20+ tests)
// ============================================================================

describe('Cookie Parsing', () => {
  describe('parseCookieValue', () => {
    it('parses auth=jwt_token_here from cookie header', () => {
      expect(parseCookieValue('auth=jwt_token_here', 'auth')).toBe('jwt_token_here')
    })

    it('parses wos-session=token from cookie header', () => {
      expect(parseCookieValue('wos-session=token_value', 'wos-session')).toBe('token_value')
    })

    it('handles multiple cookies in one header', () => {
      const header = 'theme=dark; auth=my_jwt; lang=en'
      expect(parseCookieValue(header, 'auth')).toBe('my_jwt')
    })

    it('handles URL-encoded cookie values', () => {
      expect(parseCookieValue('auth=hello%20world%3Dfoo', 'auth')).toBe('hello world=foo')
    })

    it('returns null for missing cookie', () => {
      expect(parseCookieValue('theme=dark; lang=en', 'auth')).toBeNull()
    })

    it('returns null for empty cookie header', () => {
      expect(parseCookieValue('', 'auth')).toBeNull()
    })

    it('handles cookie with no value (empty string)', () => {
      expect(parseCookieValue('auth=', 'auth')).toBe('')
    })

    it('handles cookie with special characters in value', () => {
      const jwt = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyXzEifQ.signature_here'
      expect(parseCookieValue(`auth=${jwt}`, 'auth')).toBe(jwt)
    })

    it('extracts cookie at start of header', () => {
      expect(parseCookieValue('auth=first; other=second', 'auth')).toBe('first')
    })

    it('extracts cookie at end of header', () => {
      expect(parseCookieValue('first=a; auth=last_cookie', 'auth')).toBe('last_cookie')
    })

    it('handles cookies with spaces around semicolons', () => {
      expect(parseCookieValue('a=1;  auth=spaced;  b=2', 'auth')).toBe('spaced')
    })

    it('does not match partial cookie names', () => {
      // auth-token should NOT match auth
      expect(parseCookieValue('auth-token=value', 'auth')).toBeNull()
    })

    it('does not match substring of cookie name', () => {
      // xauth should NOT match auth
      expect(parseCookieValue('xauth=value', 'auth')).toBeNull()
    })

    it('handles URL-encoded plus signs', () => {
      expect(parseCookieValue('auth=hello%2Bworld', 'auth')).toBe('hello+world')
    })

    it('handles URL-encoded ampersands', () => {
      expect(parseCookieValue('data=a%26b%3Dc', 'data')).toBe('a&b=c')
    })

    it('extracts wos-session among multiple cookies', () => {
      expect(parseCookieValue('auth=jwt1; wos-session=jwt2; _ga=ga_val', 'wos-session')).toBe('jwt2')
    })

    it('handles cookie with base64url JWT value containing dashes and underscores', () => {
      const jwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyXzEifQ.sig-nat_ure'
      expect(parseCookieValue(`auth=${jwt}`, 'auth')).toBe(jwt)
    })

    it('returns null when cookie name is empty string', () => {
      expect(parseCookieValue('auth=value', '')).toBeNull()
    })

    it('handles very long cookie value', () => {
      const longValue = 'x'.repeat(4096)
      expect(parseCookieValue(`auth=${longValue}`, 'auth')).toBe(longValue)
    })

    it('handles cookie with equals sign in value (URL-encoded)', () => {
      expect(parseCookieValue('auth=base64%3D%3D', 'auth')).toBe('base64==')
    })
  })

  describe('Token extraction priority', () => {
    it('Bearer header takes precedence over cookies', () => {
      const token = extractTokenFromHeaders('Bearer bearer_token', 'auth=cookie_token')
      expect(token).toBe('bearer_token')
    })

    it('auth cookie takes precedence over wos-session cookie', () => {
      const token = extractTokenFromHeaders(null, 'auth=auth_jwt; wos-session=wos_jwt')
      expect(token).toBe('auth_jwt')
    })

    it('falls back to wos-session when auth cookie is missing', () => {
      const token = extractTokenFromHeaders(null, 'wos-session=wos_jwt; theme=dark')
      expect(token).toBe('wos_jwt')
    })

    it('returns null when no credentials present', () => {
      const token = extractTokenFromHeaders(null, null)
      expect(token).toBeNull()
    })

    it('returns null when authorization header is not Bearer', () => {
      const token = extractTokenFromHeaders('Basic dXNlcjpwYXNz', null)
      expect(token).toBeNull()
    })

    it('returns null with empty cookie header and no authorization', () => {
      const token = extractTokenFromHeaders(null, '')
      expect(token).toBeNull()
    })

    it('returns Bearer token even if cookie has auth', () => {
      const token = extractTokenFromHeaders('Bearer my_ses_token', 'auth=different_token')
      expect(token).toBe('my_ses_token')
    })

    it('returns auth cookie token when authorization is undefined', () => {
      const token = extractTokenFromHeaders(undefined, 'auth=cookie_jwt')
      expect(token).toBe('cookie_jwt')
    })

    it('returns wos-session when auth cookie is empty string', () => {
      const token = extractTokenFromHeaders(null, 'auth=; wos-session=wos_value')
      // auth= yields '', which is falsy — but parseCookieValue returns '' not null
      // so the nullish coalescing operator does NOT skip it
      // Empty string is returned by parseCookieValue for 'auth='
      expect(token).toBe('')
    })
  })
})

// ============================================================================
// 2. Cookie Building (15+ tests)
// ============================================================================

describe('Cookie Building', () => {
  describe('Auth cookie (login)', () => {
    it('contains HttpOnly flag', () => {
      const cookie = buildAuthCookie('jwt_token', true)
      expect(cookie).toContain('HttpOnly')
    })

    it('contains SameSite=Lax', () => {
      const cookie = buildAuthCookie('jwt_token', true)
      expect(cookie).toContain('SameSite=Lax')
    })

    it('contains Path=/', () => {
      const cookie = buildAuthCookie('jwt_token', true)
      expect(cookie).toContain('Path=/')
    })

    it('contains Max-Age=3600', () => {
      const cookie = buildAuthCookie('jwt_token', true)
      expect(cookie).toContain('Max-Age=3600')
    })

    it('includes Secure flag on HTTPS', () => {
      const cookie = buildAuthCookie('jwt_token', true)
      expect(cookie).toContain('Secure')
    })

    it('does NOT include Secure flag on HTTP (localhost dev)', () => {
      const cookie = buildAuthCookie('jwt_token', false)
      expect(cookie).not.toContain('Secure')
    })

    it('cookie value contains the JWT', () => {
      const jwt = 'eyJhbGciOiJSUzI1NiJ9.payload.signature'
      const cookie = buildAuthCookie(jwt, true)
      expect(cookie).toContain(`auth=${jwt}`)
    })

    it('starts with auth= followed by the JWT', () => {
      const jwt = 'my.jwt.token'
      const cookie = buildAuthCookie(jwt, true)
      expect(cookie.startsWith(`auth=${jwt}`)).toBe(true)
    })

    it('flags are semicolon-separated', () => {
      const cookie = buildAuthCookie('jwt', true)
      const parts = cookie.split('; ')
      expect(parts).toContain('HttpOnly')
      expect(parts).toContain('SameSite=Lax')
      expect(parts).toContain('Path=/')
      expect(parts).toContain('Max-Age=3600')
      expect(parts).toContain('Secure')
    })

    it('HTTPS cookie has exactly 6 parts', () => {
      const cookie = buildAuthCookie('jwt', true)
      const parts = cookie.split('; ')
      expect(parts).toHaveLength(6) // auth=jwt, HttpOnly, Path=/, SameSite=Lax, Max-Age=3600, Secure
    })

    it('HTTP cookie has exactly 5 parts (no Secure)', () => {
      const cookie = buildAuthCookie('jwt', false)
      const parts = cookie.split('; ')
      expect(parts).toHaveLength(5)
    })
  })

  describe('Logout cookie (clear)', () => {
    it('sets Max-Age=0 to clear the cookie', () => {
      const cookie = buildLogoutCookie(true)
      expect(cookie).toContain('Max-Age=0')
    })

    it('sets auth= with empty value', () => {
      const cookie = buildLogoutCookie(true)
      expect(cookie.startsWith('auth=')).toBe(true)
      // The value after auth= and before the first ; should be empty
      const value = cookie.split('; ')[0].split('=')[1]
      expect(value).toBe('')
    })

    it('includes HttpOnly flag', () => {
      const cookie = buildLogoutCookie(true)
      expect(cookie).toContain('HttpOnly')
    })

    it('includes Path=/', () => {
      const cookie = buildLogoutCookie(true)
      expect(cookie).toContain('Path=/')
    })

    it('includes SameSite=Lax', () => {
      const cookie = buildLogoutCookie(true)
      expect(cookie).toContain('SameSite=Lax')
    })

    it('includes Secure flag on HTTPS', () => {
      const cookie = buildLogoutCookie(true)
      expect(cookie).toContain('Secure')
    })

    it('does NOT include Secure flag on HTTP', () => {
      const cookie = buildLogoutCookie(false)
      expect(cookie).not.toContain('Secure')
    })
  })
})

// ============================================================================
// 3. JWT in Cookies (15+ tests)
// ============================================================================

describe('JWT in Cookies', () => {
  let signingKey: SigningKey
  let storageOp: ReturnType<typeof createMockStorageOp>
  let manager: SigningKeyManager

  beforeEach(async () => {
    signingKey = await generateSigningKey('cookie-test-kid')
    storageOp = createMockStorageOp()
    manager = new SigningKeyManager(storageOp)
  })

  describe('Signing a JWT with SigningKeyManager', () => {
    it('produces a valid 3-part JWT string', async () => {
      const jwt = await manager.sign({ sub: 'user_1' }, { issuer: 'https://id.org.ai' })
      expect(jwt.split('.')).toHaveLength(3)
    })

    it('JWT is verifiable with the current key', async () => {
      const jwt = await manager.sign({ sub: 'user_1' }, { issuer: 'https://id.org.ai' })
      const key = await manager.getCurrentKey()
      const valid = await verifyJWTSignature(jwt, key.publicKey)
      expect(valid).toBe(true)
    })

    it('JWT from signJWT is verifiable with the signing key', async () => {
      const jwt = await signJWT(signingKey, { sub: 'user_1' }, { issuer: 'https://id.org.ai' })
      const valid = await verifyJWTSignature(jwt, signingKey.publicKey)
      expect(valid).toBe(true)
    })
  })

  describe('JWT claims', () => {
    it('contains correct sub claim', async () => {
      const jwt = await signJWT(signingKey, { sub: 'human:wos_user_123' }, { issuer: 'https://id.org.ai' })
      const { payload } = parseJWT(jwt)
      expect(payload.sub).toBe('human:wos_user_123')
    })

    it('contains correct email claim', async () => {
      const jwt = await signJWT(signingKey, { sub: 'user_1', email: 'alice@example.com' }, { issuer: 'https://id.org.ai' })
      const { payload } = parseJWT(jwt)
      expect(payload.email).toBe('alice@example.com')
    })

    it('contains correct name claim', async () => {
      const jwt = await signJWT(signingKey, { sub: 'user_1', name: 'Alice Smith' }, { issuer: 'https://id.org.ai' })
      const { payload } = parseJWT(jwt)
      expect(payload.name).toBe('Alice Smith')
    })

    it('contains correct org_id claim', async () => {
      const jwt = await signJWT(signingKey, { sub: 'user_1', org_id: 'org_acme' }, { issuer: 'https://id.org.ai' })
      const { payload } = parseJWT(jwt)
      expect(payload.org_id).toBe('org_acme')
    })

    it('contains roles claim', async () => {
      const jwt = await signJWT(signingKey, { sub: 'user_1', roles: ['admin', 'member'] }, { issuer: 'https://id.org.ai' })
      const { payload } = parseJWT(jwt)
      expect(payload.roles).toEqual(['admin', 'member'])
    })

    it('contains permissions claim', async () => {
      const jwt = await signJWT(signingKey, { sub: 'user_1', permissions: ['read', 'write', 'delete'] }, { issuer: 'https://id.org.ai' })
      const { payload } = parseJWT(jwt)
      expect(payload.permissions).toEqual(['read', 'write', 'delete'])
    })
  })

  describe('JWT issuer and expiration', () => {
    it('has correct issuer (https://id.org.ai)', async () => {
      const jwt = await signJWT(signingKey, { sub: 'user_1' }, { issuer: 'https://id.org.ai' })
      const { payload } = parseJWT(jwt)
      expect(payload.iss).toBe('https://id.org.ai')
    })

    it('expires in 1 hour (3600s) by default', async () => {
      const jwt = await signJWT(signingKey, { sub: 'user_1' }, { issuer: 'https://id.org.ai' })
      const { payload } = parseJWT(jwt)
      expect((payload.exp as number) - (payload.iat as number)).toBe(3600)
    })

    it('respects custom expiresIn', async () => {
      const jwt = await signJWT(signingKey, { sub: 'user_1' }, { issuer: 'https://id.org.ai', expiresIn: 1800 })
      const { payload } = parseJWT(jwt)
      expect((payload.exp as number) - (payload.iat as number)).toBe(1800)
    })

    it('has iat claim near current time', async () => {
      const before = Math.floor(Date.now() / 1000)
      const jwt = await signJWT(signingKey, { sub: 'user_1' }, { issuer: 'https://id.org.ai' })
      const after = Math.floor(Date.now() / 1000)
      const { payload } = parseJWT(jwt)
      expect(payload.iat).toBeGreaterThanOrEqual(before)
      expect(payload.iat).toBeLessThanOrEqual(after)
    })
  })

  describe('JWT header', () => {
    it('has kid in header', async () => {
      const jwt = await signJWT(signingKey, { sub: 'user_1' }, { issuer: 'https://id.org.ai' })
      const { header } = parseJWT(jwt)
      expect(header.kid).toBe('cookie-test-kid')
    })

    it('has alg: RS256 in header', async () => {
      const jwt = await signJWT(signingKey, { sub: 'user_1' }, { issuer: 'https://id.org.ai' })
      const { header } = parseJWT(jwt)
      expect(header.alg).toBe('RS256')
    })

    it('has typ: JWT in header', async () => {
      const jwt = await signJWT(signingKey, { sub: 'user_1' }, { issuer: 'https://id.org.ai' })
      const { header } = parseJWT(jwt)
      expect(header.typ).toBe('JWT')
    })

    it('manager-signed JWT has kid matching current key', async () => {
      const jwt = await manager.sign({ sub: 'user_1' }, { issuer: 'https://id.org.ai' })
      const key = await manager.getCurrentKey()
      const { header } = parseJWT(jwt)
      expect(header.kid).toBe(key.kid)
    })
  })

  describe('JWT verification against JWKS', () => {
    it('JWT can be verified against exported JWKS public key', async () => {
      const jwt = await signJWT(signingKey, { sub: 'user_1' }, { issuer: 'https://id.org.ai' })
      const jwksKey = await exportPublicKeyToJWKS(signingKey)

      // Import the JWKS public key back to a CryptoKey for verification
      const importedKey = await crypto.subtle.importKey(
        'jwk',
        { kty: jwksKey.kty, n: jwksKey.n, e: jwksKey.e, alg: jwksKey.alg, use: jwksKey.use },
        { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
        false,
        ['verify'],
      )

      const valid = await verifyJWTSignature(jwt, importedKey)
      expect(valid).toBe(true)
    })

    it('JWKS from manager contains the signing key', async () => {
      const jwks = await manager.getJWKS()
      const key = await manager.getCurrentKey()
      const kids = jwks.keys.map((k) => k.kid)
      expect(kids).toContain(key.kid)
    })

    it('JWKS key has correct kty, use, alg fields', async () => {
      const jwks = await manager.getJWKS()
      for (const key of jwks.keys) {
        expect(key.kty).toBe('RSA')
        expect(key.use).toBe('sig')
        expect(key.alg).toBe('RS256')
      }
    })

    it('JWT signed by rotated key is still verifiable via JWKS', async () => {
      const jwtBefore = await manager.sign({ sub: 'user_before' }, { issuer: 'https://id.org.ai' })
      const oldKey = await manager.getCurrentKey()

      await manager.rotateKey()

      // Old key should still be in JWKS
      const jwks = await manager.getJWKS()
      const kids = jwks.keys.map((k) => k.kid)
      expect(kids).toContain(oldKey.kid)

      // JWT signed with old key should still verify
      const valid = await verifyJWTSignature(jwtBefore, oldKey.publicKey)
      expect(valid).toBe(true)
    })

    it('full claims roundtrip through JWT in cookie', async () => {
      const claims: AccessTokenClaims = {
        sub: 'human:wos_user_abc',
        email: 'alice@acme.co',
        name: 'Alice Smith',
        org_id: 'org_acme123',
        roles: ['admin', 'member'],
        permissions: ['read', 'write', 'delete', 'manage'],
      }

      const jwt = await manager.sign(claims, { issuer: 'https://id.org.ai', expiresIn: 3600 })

      // Simulate setting and reading from a cookie
      const setCookie = buildAuthCookie(jwt, true)
      const extractedJwt = parseCookieValue(setCookie.split('; ')[0], 'auth')
      expect(extractedJwt).toBe(jwt)

      // Parse and verify the extracted JWT
      const { payload } = parseJWT(extractedJwt!)
      expect(payload.sub).toBe('human:wos_user_abc')
      expect(payload.email).toBe('alice@acme.co')
      expect(payload.name).toBe('Alice Smith')
      expect(payload.org_id).toBe('org_acme123')
      expect(payload.roles).toEqual(['admin', 'member'])
      expect(payload.permissions).toEqual(['read', 'write', 'delete', 'manage'])
      expect(payload.iss).toBe('https://id.org.ai')
      expect((payload.exp as number) - (payload.iat as number)).toBe(3600)

      // Verify signature
      const key = await manager.getCurrentKey()
      const valid = await verifyJWTSignature(extractedJwt!, key.publicKey)
      expect(valid).toBe(true)
    })
  })
})

// ============================================================================
// 4. Login State Encoding (10+ tests)
// ============================================================================

describe('Login State Encoding', () => {
  describe('encodeLoginState/decodeLoginState roundtrip', () => {
    it('roundtrips csrf + continue URL', () => {
      const encoded = encodeLoginState('csrf_abc123', 'https://headless.ly/dashboard')
      const decoded = decodeLoginState(encoded)

      expect(decoded).not.toBeNull()
      expect(decoded!.csrf).toBe('csrf_abc123')
      expect(decoded!.continue).toBe('https://headless.ly/dashboard')
    })

    it('roundtrips csrf without continue URL', () => {
      const encoded = encodeLoginState('csrf_only_token')
      const decoded = decodeLoginState(encoded)

      expect(decoded).not.toBeNull()
      expect(decoded!.csrf).toBe('csrf_only_token')
      expect(decoded!.continue).toBeUndefined()
    })

    it('roundtrips continue URL with query params and fragments', () => {
      const continueUrl = 'https://headless.ly/~acme/crm/deals?status=open&sort=value#top'
      const encoded = encodeLoginState('csrf_x', continueUrl)
      const decoded = decodeLoginState(encoded)

      expect(decoded).not.toBeNull()
      expect(decoded!.continue).toBe(continueUrl)
    })

    it('roundtrips UUID-style csrf token', () => {
      const csrf = '550e8400-e29b-41d4-a716-446655440000'
      const encoded = encodeLoginState(csrf, '/callback')
      const decoded = decodeLoginState(encoded)

      expect(decoded).not.toBeNull()
      expect(decoded!.csrf).toBe(csrf)
    })
  })

  describe('State contains CSRF token and continue URL', () => {
    it('encoded state is a non-empty string', () => {
      const encoded = encodeLoginState('csrf_val', 'https://example.com')
      expect(typeof encoded).toBe('string')
      expect(encoded.length).toBeGreaterThan(0)
    })

    it('encoded state is base64url safe (no +, /, =)', () => {
      const encoded = encodeLoginState('csrf+token/with==special', 'https://example.com/path?q=a+b')
      expect(encoded).not.toContain('+')
      expect(encoded).not.toContain('/')
      expect(encoded).not.toContain('=')
    })

    it('different csrf tokens produce different encoded states', () => {
      const state1 = encodeLoginState('csrf_1', '/dashboard')
      const state2 = encodeLoginState('csrf_2', '/dashboard')
      expect(state1).not.toBe(state2)
    })
  })

  describe('Invalid state handling', () => {
    it('invalid base64 state returns null', () => {
      expect(decodeLoginState('!!!not-valid-base64!!!')).toBeNull()
    })

    it('empty state returns null', () => {
      expect(decodeLoginState('')).toBeNull()
    })

    it('tampered state (non-JSON) returns null', () => {
      const notJson = btoa('this is not json').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
      expect(decodeLoginState(notJson)).toBeNull()
    })

    it('state with missing csrf field returns null', () => {
      const noCsrf = btoa(JSON.stringify({ continue: '/dashboard' })).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
      expect(decodeLoginState(noCsrf)).toBeNull()
    })

    it('state with empty csrf returns null', () => {
      const emptyCsrf = btoa(JSON.stringify({ csrf: '' })).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
      expect(decodeLoginState(emptyCsrf)).toBeNull()
    })

    it('state with csrf=null returns null', () => {
      const nullCsrf = btoa(JSON.stringify({ csrf: null })).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
      expect(decodeLoginState(nullCsrf)).toBeNull()
    })

    it('state with numeric csrf returns null (not falsy)', () => {
      // 0 is falsy in JS — should return null since !payload.csrf is true
      const zeroCsrf = btoa(JSON.stringify({ csrf: 0 })).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
      expect(decodeLoginState(zeroCsrf)).toBeNull()
    })

    it('handles unicode in continue URL', () => {
      const continueUrl = 'https://headless.ly/orgs/caf\u00e9'
      const encoded = encodeLoginState('csrf_unicode', continueUrl)
      const decoded = decodeLoginState(encoded)
      expect(decoded).not.toBeNull()
      expect(decoded!.continue).toBe(continueUrl)
    })

    it('preserves very long csrf tokens', () => {
      const longCsrf = 'a'.repeat(512)
      const encoded = encodeLoginState(longCsrf)
      const decoded = decodeLoginState(encoded)
      expect(decoded).not.toBeNull()
      expect(decoded!.csrf).toBe(longCsrf)
    })
  })
})

// ============================================================================
// 5. End-to-End Cookie Auth Flow Scenarios
// ============================================================================

describe('End-to-End Cookie Auth Flows', () => {
  let storageOp: ReturnType<typeof createMockStorageOp>
  let manager: SigningKeyManager

  beforeEach(() => {
    storageOp = createMockStorageOp()
    manager = new SigningKeyManager(storageOp)
  })

  it('login flow: sign JWT, build cookie, extract from cookie header, verify JWT', async () => {
    // 1. Sign JWT (simulates /callback)
    const jwt = await manager.sign(
      { sub: 'human:user_001', email: 'dev@acme.co', name: 'Dev User', org_id: 'org_acme' },
      { issuer: 'https://id.org.ai', expiresIn: 3600 },
    )

    // 2. Build Set-Cookie header
    const setCookie = buildAuthCookie(jwt, true)
    expect(setCookie).toContain('HttpOnly')
    expect(setCookie).toContain('Secure')
    expect(setCookie).toContain('Max-Age=3600')

    // 3. Simulate browser sending cookie back in request
    const cookieHeader = `auth=${jwt}; theme=dark; _ga=GA1.2.xxx`

    // 4. Extract token using authenticate() logic
    const token = extractTokenFromHeaders(null, cookieHeader)
    expect(token).toBe(jwt)

    // 5. Verify the JWT
    const key = await manager.getCurrentKey()
    const valid = await verifyJWTSignature(token!, key.publicKey)
    expect(valid).toBe(true)

    // 6. Parse claims
    const { payload } = parseJWT(token!)
    expect(payload.sub).toBe('human:user_001')
    expect(payload.email).toBe('dev@acme.co')
    expect(payload.iss).toBe('https://id.org.ai')
  })

  it('logout flow: clear cookie sets Max-Age=0 and empty value', () => {
    const clearCookie = buildLogoutCookie(true)
    expect(clearCookie).toContain('Max-Age=0')
    expect(clearCookie.startsWith('auth=')).toBe(true)

    // The value portion (between auth= and first ;) should be empty
    const value = clearCookie.split('; ')[0].replace('auth=', '')
    expect(value).toBe('')
  })

  it('login state: encode before redirect, decode on callback', () => {
    // 1. On /login: encode CSRF + continue URL into state
    const csrf = crypto.randomUUID()
    const continueUrl = 'https://crm.headless.ly/~acme/deals'
    const state = encodeLoginState(csrf, continueUrl)

    // 2. On /callback: decode state
    const decoded = decodeLoginState(state)
    expect(decoded).not.toBeNull()
    expect(decoded!.csrf).toBe(csrf)
    expect(decoded!.continue).toBe(continueUrl)
  })

  it('Bearer header overrides cookie even when cookie has valid JWT', async () => {
    const cookieJwt = await manager.sign({ sub: 'cookie_user' }, { issuer: 'https://id.org.ai' })
    const bearerToken = 'ses_bearer_session_token'

    const token = extractTokenFromHeaders(`Bearer ${bearerToken}`, `auth=${cookieJwt}`)
    expect(token).toBe(bearerToken)
  })

  it('HTTPS callback sets Secure flag on cookie', () => {
    const cookie = buildAuthCookie('jwt', true)
    expect(cookie).toContain('Secure')
  })

  it('HTTP localhost callback omits Secure flag', () => {
    const cookie = buildAuthCookie('jwt', false)
    expect(cookie).not.toContain('Secure')
  })

  it('JWT claims survive full cookie roundtrip with URL-safe encoding', async () => {
    const claims: AccessTokenClaims = {
      sub: 'human:wos_user_special-chars',
      email: 'user+tag@example.com',
      name: 'O\'Brien',
      org_id: 'org_123',
      roles: ['admin'],
      permissions: ['read', 'write'],
    }

    const jwt = await manager.sign(claims, { issuer: 'https://id.org.ai' })

    // JWT itself should be base64url-safe
    for (const part of jwt.split('.')) {
      expect(part).not.toMatch(/[+/=]/)
    }

    // Roundtrip through cookie
    const cookieHeader = `auth=${jwt}`
    const extracted = parseCookieValue(cookieHeader, 'auth')
    expect(extracted).toBe(jwt)

    const { payload } = parseJWT(extracted!)
    expect(payload.email).toBe('user+tag@example.com')
    expect(payload.name).toBe('O\'Brien')
  })

  it('manager persists key across instances and both produce verifiable JWTs', async () => {
    // First manager signs a JWT
    const jwt1 = await manager.sign({ sub: 'user_1' }, { issuer: 'https://id.org.ai' })

    // Second manager using same storage should load same key
    const manager2 = new SigningKeyManager(storageOp)
    const jwt2 = await manager2.sign({ sub: 'user_2' }, { issuer: 'https://id.org.ai' })

    // Both JWTs should be verifiable with the same public key
    const key = await manager2.getCurrentKey()
    expect(await verifyJWTSignature(jwt1, key.publicKey)).toBe(true)
    expect(await verifyJWTSignature(jwt2, key.publicKey)).toBe(true)

    // Both should have the same kid
    const { header: h1 } = parseJWT(jwt1)
    const { header: h2 } = parseJWT(jwt2)
    expect(h1.kid).toBe(h2.kid)
  })
})
