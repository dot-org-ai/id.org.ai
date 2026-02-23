/**
 * CSRF Protection Unit Tests
 *
 * Tests token generation, double-submit cookie pattern, origin validation,
 * state encoding/decoding, and the CSRFProtection class.
 */

import { describe, it, expect, vi } from 'vitest'
import {
  generateCSRFToken,
  encodeStateWithCSRF,
  decodeStateWithCSRF,
  buildCSRFCookie,
  extractCSRFFromCookie,
  isAllowedOrigin,
  isSafeRedirectUrl,
  getCorsOrigin,
  validateOrigin,
  CSRF_COOKIE_NAME,
  ALLOWED_ORIGIN_PATTERNS,
} from '../src/csrf'

// ── Token Generation ──────────────────────────────────────────────────────

describe('generateCSRFToken', () => {
  it('generates a 64-character hex string (32 bytes)', () => {
    const token = generateCSRFToken()
    expect(token).toMatch(/^[0-9a-f]{64}$/)
  })

  it('generates unique tokens each call', () => {
    const tokens = new Set(Array.from({ length: 100 }, () => generateCSRFToken()))
    expect(tokens.size).toBe(100)
  })

  it('generates tokens that are valid hex', () => {
    const token = generateCSRFToken()
    expect(() => parseInt(token.slice(0, 8), 16)).not.toThrow()
  })
})

// ── State Encoding/Decoding ──────────────────────────────────────────────

describe('encodeStateWithCSRF / decodeStateWithCSRF', () => {
  it('round-trips CSRF token without original state', () => {
    const csrfToken = 'abc123'
    const encoded = encodeStateWithCSRF(csrfToken)
    const decoded = decodeStateWithCSRF(encoded)

    expect(decoded).not.toBeNull()
    expect(decoded!.csrf).toBe('abc123')
    expect(decoded!.originalState).toBeUndefined()
  })

  it('round-trips CSRF token with original state', () => {
    const csrfToken = 'csrf_value'
    const originalState = 'user_state_data'
    const encoded = encodeStateWithCSRF(csrfToken, originalState)
    const decoded = decodeStateWithCSRF(encoded)

    expect(decoded).not.toBeNull()
    expect(decoded!.csrf).toBe('csrf_value')
    expect(decoded!.originalState).toBe('user_state_data')
  })

  it('produces base64url-safe output (no +, /, =)', () => {
    const encoded = encodeStateWithCSRF('test-token', 'some+state/value==')
    expect(encoded).not.toContain('+')
    expect(encoded).not.toContain('/')
    expect(encoded).not.toContain('=')
  })

  it('returns null for invalid base64', () => {
    const result = decodeStateWithCSRF('not-valid-base64!!!')
    expect(result).toBeNull()
  })

  it('returns null for valid base64 but invalid JSON', () => {
    const encoded = btoa('not json').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
    const result = decodeStateWithCSRF(encoded)
    expect(result).toBeNull()
  })

  it('returns null for JSON without csrf field', () => {
    const encoded = btoa(JSON.stringify({ foo: 'bar' })).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
    const result = decodeStateWithCSRF(encoded)
    expect(result).toBeNull()
  })

  it('returns null for empty string', () => {
    const result = decodeStateWithCSRF('')
    expect(result).toBeNull()
  })
})

// ── Cookie Building ──────────────────────────────────────────────────────

describe('buildCSRFCookie', () => {
  it('includes the cookie name and token value', () => {
    const cookie = buildCSRFCookie('my_token')
    expect(cookie).toContain(`${CSRF_COOKIE_NAME}=my_token`)
  })

  it('includes Path=/', () => {
    const cookie = buildCSRFCookie('token')
    expect(cookie).toContain('Path=/')
  })

  it('includes Max-Age=1800 (30 minutes)', () => {
    const cookie = buildCSRFCookie('token')
    expect(cookie).toContain('Max-Age=1800')
  })

  it('includes SameSite=Lax', () => {
    const cookie = buildCSRFCookie('token')
    expect(cookie).toContain('SameSite=Lax')
  })

  it('includes HttpOnly', () => {
    const cookie = buildCSRFCookie('token')
    expect(cookie).toContain('HttpOnly')
  })

  it('includes Secure when secure=true (default)', () => {
    const cookie = buildCSRFCookie('token')
    expect(cookie).toContain('Secure')
  })

  it('excludes Secure when secure=false', () => {
    const cookie = buildCSRFCookie('token', false)
    expect(cookie).not.toContain('Secure')
  })
})

// ── Cookie Extraction ────────────────────────────────────────────────────

describe('extractCSRFFromCookie', () => {
  it('extracts the CSRF token from a cookie header', () => {
    const request = new Request('https://example.com', {
      headers: { cookie: `${CSRF_COOKIE_NAME}=my_csrf_token; other_cookie=value` },
    })
    expect(extractCSRFFromCookie(request)).toBe('my_csrf_token')
  })

  it('returns null when cookie header is missing', () => {
    const request = new Request('https://example.com')
    expect(extractCSRFFromCookie(request)).toBeNull()
  })

  it('returns null when CSRF cookie is not present', () => {
    const request = new Request('https://example.com', {
      headers: { cookie: 'other_cookie=value; another=val' },
    })
    expect(extractCSRFFromCookie(request)).toBeNull()
  })

  it('handles CSRF cookie being the only cookie', () => {
    const request = new Request('https://example.com', {
      headers: { cookie: `${CSRF_COOKIE_NAME}=token123` },
    })
    expect(extractCSRFFromCookie(request)).toBe('token123')
  })

  it('handles cookies with = in value', () => {
    const request = new Request('https://example.com', {
      headers: { cookie: `${CSRF_COOKIE_NAME}=base64value==; other=x` },
    })
    expect(extractCSRFFromCookie(request)).toBe('base64value==')
  })
})

// ── Origin Validation ────────────────────────────────────────────────────

describe('isAllowedOrigin', () => {
  it('allows headless.ly', () => {
    expect(isAllowedOrigin('https://headless.ly')).toBe(true)
  })

  it('allows subdomains of headless.ly', () => {
    expect(isAllowedOrigin('https://crm.headless.ly')).toBe(true)
    expect(isAllowedOrigin('https://db.headless.ly')).toBe(true)
    expect(isAllowedOrigin('https://build.headless.ly')).toBe(true)
  })

  it('allows org.ai', () => {
    expect(isAllowedOrigin('https://org.ai')).toBe(true)
  })

  it('allows subdomains of org.ai', () => {
    expect(isAllowedOrigin('https://id.org.ai')).toBe(true)
    expect(isAllowedOrigin('https://schema.org.ai')).toBe(true)
  })

  it('allows localhost with port', () => {
    expect(isAllowedOrigin('http://localhost:3000')).toBe(true)
    expect(isAllowedOrigin('http://localhost:8787')).toBe(true)
  })

  it('allows localhost without port', () => {
    expect(isAllowedOrigin('http://localhost')).toBe(true)
  })

  it('allows 127.0.0.1 with port', () => {
    expect(isAllowedOrigin('http://127.0.0.1:3000')).toBe(true)
  })

  it('rejects unknown origins', () => {
    expect(isAllowedOrigin('https://evil.com')).toBe(false)
    expect(isAllowedOrigin('https://not-headless.ly')).toBe(false)
  })

  it('rejects empty string', () => {
    expect(isAllowedOrigin('')).toBe(false)
  })

  it('rejects origins that embed allowed domains in subdomain', () => {
    // headless.ly.evil.com should NOT match
    expect(isAllowedOrigin('https://headless.ly.evil.com')).toBe(false)
  })

  it('allows .do domains', () => {
    expect(isAllowedOrigin('https://oauth.do')).toBe(true)
    expect(isAllowedOrigin('https://events.do')).toBe(true)
    expect(isAllowedOrigin('https://database.do')).toBe(true)
    expect(isAllowedOrigin('https://functions.do')).toBe(true)
    expect(isAllowedOrigin('https://agents.do')).toBe(true)
  })

  it('allows subdomains of .do domains', () => {
    expect(isAllowedOrigin('https://api.events.do')).toBe(true)
    expect(isAllowedOrigin('https://sub.oauth.do')).toBe(true)
  })

  it('rejects bare .do without name', () => {
    expect(isAllowedOrigin('https://.do')).toBe(false)
  })
})

describe('getCorsOrigin', () => {
  it('returns origin for allowed origins', () => {
    const request = new Request('https://example.com', {
      headers: { origin: 'https://headless.ly' },
    })
    expect(getCorsOrigin(request)).toBe('https://headless.ly')
  })

  it('returns null for disallowed origins', () => {
    const request = new Request('https://example.com', {
      headers: { origin: 'https://evil.com' },
    })
    expect(getCorsOrigin(request)).toBeNull()
  })

  it('returns null when no origin header', () => {
    const request = new Request('https://example.com')
    expect(getCorsOrigin(request)).toBeNull()
  })
})

describe('validateOrigin', () => {
  it('allows GET requests regardless of origin', () => {
    const request = new Request('https://example.com', {
      method: 'GET',
      headers: { origin: 'https://evil.com' },
    })
    expect(validateOrigin(request)).toBeNull()
  })

  it('allows HEAD requests regardless of origin', () => {
    const request = new Request('https://example.com', {
      method: 'HEAD',
      headers: { origin: 'https://evil.com' },
    })
    expect(validateOrigin(request)).toBeNull()
  })

  it('allows OPTIONS requests regardless of origin', () => {
    const request = new Request('https://example.com', {
      method: 'OPTIONS',
      headers: { origin: 'https://evil.com' },
    })
    expect(validateOrigin(request)).toBeNull()
  })

  it('allows POST requests with no origin header (same-origin/non-browser)', () => {
    const request = new Request('https://example.com', {
      method: 'POST',
    })
    expect(validateOrigin(request)).toBeNull()
  })

  it('allows POST requests with valid origin', () => {
    const request = new Request('https://example.com', {
      method: 'POST',
      headers: { origin: 'https://crm.headless.ly' },
    })
    expect(validateOrigin(request)).toBeNull()
  })

  it('rejects POST requests with invalid origin', () => {
    const request = new Request('https://example.com', {
      method: 'POST',
      headers: { origin: 'https://evil.com' },
    })
    const response = validateOrigin(request)
    expect(response).not.toBeNull()
    expect(response!.status).toBe(403)
  })

  it('rejects PUT requests with invalid origin', () => {
    const request = new Request('https://example.com', {
      method: 'PUT',
      headers: { origin: 'https://evil.com' },
    })
    const response = validateOrigin(request)
    expect(response).not.toBeNull()
    expect(response!.status).toBe(403)
  })

  it('rejects DELETE requests with invalid origin', () => {
    const request = new Request('https://example.com', {
      method: 'DELETE',
      headers: { origin: 'https://evil.com' },
    })
    const response = validateOrigin(request)
    expect(response).not.toBeNull()
    expect(response!.status).toBe(403)
  })

  it('returns a JSON error response for rejected requests', async () => {
    const request = new Request('https://example.com', {
      method: 'POST',
      headers: { origin: 'https://evil.com' },
    })
    const response = validateOrigin(request)!
    const body = await response.json() as { error: string; message: string }
    expect(body.error).toBe('forbidden')
    expect(body.message).toBe('Origin not allowed')
  })
})

// ── Safe Redirect URL Validation ────────────────────────────────────────

describe('isSafeRedirectUrl', () => {
  it('allows relative paths', () => {
    expect(isSafeRedirectUrl('/')).toBe(true)
    expect(isSafeRedirectUrl('/dashboard')).toBe(true)
    expect(isSafeRedirectUrl('/~acme/settings')).toBe(true)
  })

  it('rejects protocol-relative URLs (//evil.com)', () => {
    expect(isSafeRedirectUrl('//evil.com')).toBe(false)
    expect(isSafeRedirectUrl('//evil.com/path')).toBe(false)
  })

  it('allows absolute URLs on allowed origins', () => {
    expect(isSafeRedirectUrl('https://headless.ly/dashboard')).toBe(true)
    expect(isSafeRedirectUrl('https://crm.headless.ly/contacts')).toBe(true)
    expect(isSafeRedirectUrl('https://id.org.ai/settings')).toBe(true)
    expect(isSafeRedirectUrl('https://oauth.do/callback')).toBe(true)
    expect(isSafeRedirectUrl('http://localhost:3000/dev')).toBe(true)
  })

  it('rejects absolute URLs to unknown domains', () => {
    expect(isSafeRedirectUrl('https://evil.com')).toBe(false)
    expect(isSafeRedirectUrl('https://evil.com/phish')).toBe(false)
    expect(isSafeRedirectUrl('https://headless.ly.evil.com/steal')).toBe(false)
  })

  it('rejects javascript: URIs', () => {
    expect(isSafeRedirectUrl('javascript:alert(1)')).toBe(false)
  })

  it('rejects data: URIs', () => {
    expect(isSafeRedirectUrl('data:text/html,<h1>pwned</h1>')).toBe(false)
  })

  it('rejects empty string', () => {
    expect(isSafeRedirectUrl('')).toBe(false)
  })

  it('rejects malformed URLs', () => {
    expect(isSafeRedirectUrl('not a url at all')).toBe(false)
  })
})
