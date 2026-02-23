/**
 * JWT Verification Tests
 *
 * Tests for decodeJWT, isJWTExpired, and clearJWKSCache from jwt-verify.ts.
 * These tests use crafted tokens (no signature verification) to validate
 * decoding and expiration logic without needing real keys.
 */

import { describe, it, expect } from 'vitest'
import { decodeJWT, isJWTExpired, clearJWKSCache } from '../src/oauth/jwt-verify'
import type { JWTVerifyResult, JWTVerifyOptions, JWTHeader, JWTPayload } from '../src/oauth/jwt-verify'

// ── Helpers ─────────────────────────────────────────────────────────────

function base64UrlEncodeStr(str: string): string {
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

function craftToken(header: Record<string, unknown>, payload: Record<string, unknown>, signature = 'fake-sig'): string {
  return `${base64UrlEncodeStr(JSON.stringify(header))}.${base64UrlEncodeStr(JSON.stringify(payload))}.${signature}`
}

// ── decodeJWT ───────────────────────────────────────────────────────────

describe('decodeJWT', () => {
  it('decodes a well-formed JWT without verification', () => {
    const token = craftToken({ alg: 'RS256', typ: 'JWT', kid: 'key-1' }, { sub: 'user_42', iss: 'https://id.org.ai', exp: 9999999999 })

    const result = decodeJWT(token)
    expect(result).not.toBeNull()
    expect(result!.header.alg).toBe('RS256')
    expect(result!.header.typ).toBe('JWT')
    expect(result!.header.kid).toBe('key-1')
    expect(result!.payload.sub).toBe('user_42')
    expect(result!.payload.iss).toBe('https://id.org.ai')
    expect(result!.payload.exp).toBe(9999999999)
  })

  it('decodes a token with audience array', () => {
    const token = craftToken({ alg: 'ES256' }, { sub: 'agent_1', aud: ['app1', 'app2'] })
    const result = decodeJWT(token)
    expect(result).not.toBeNull()
    expect(result!.payload.aud).toEqual(['app1', 'app2'])
  })

  it('decodes a token with custom claims', () => {
    const token = craftToken({ alg: 'RS256' }, { sub: 'user_1', org_id: 'org_123', role: 'admin' })
    const result = decodeJWT(token)
    expect(result).not.toBeNull()
    expect(result!.payload['org_id']).toBe('org_123')
    expect(result!.payload['role']).toBe('admin')
  })

  it('returns null for malformed tokens', () => {
    expect(decodeJWT('')).toBeNull()
    expect(decodeJWT('a.b')).toBeNull()
    expect(decodeJWT('not-a-jwt')).toBeNull()
    expect(decodeJWT('....')).toBeNull()
  })

  it('returns null for invalid base64url in header', () => {
    expect(decodeJWT('!!!invalid!!!.eyJzdWIiOiJ0ZXN0In0.sig')).toBeNull()
  })

  it('returns null for invalid JSON in payload', () => {
    const badPayload = base64UrlEncodeStr('{not json')
    const header = base64UrlEncodeStr(JSON.stringify({ alg: 'RS256' }))
    expect(decodeJWT(`${header}.${badPayload}.sig`)).toBeNull()
  })

  it('returns null when header fails type guard (missing alg)', () => {
    const token = craftToken({ typ: 'JWT' } as Record<string, unknown>, { sub: 'test' })
    expect(decodeJWT(token)).toBeNull()
  })

  it('returns null when payload has invalid field types', () => {
    // exp must be a number
    const token = craftToken({ alg: 'RS256' }, { sub: 'test', exp: 'not-a-number' })
    expect(decodeJWT(token)).toBeNull()
  })
})

// ── isJWTExpired ────────────────────────────────────────────────────────

describe('isJWTExpired', () => {
  it('returns false for a token with future exp', () => {
    const futureExp = Math.floor(Date.now() / 1000) + 3600
    const token = craftToken({ alg: 'RS256' }, { sub: 'user_1', exp: futureExp })
    expect(isJWTExpired(token)).toBe(false)
  })

  it('returns true for a token with past exp', () => {
    const pastExp = Math.floor(Date.now() / 1000) - 3600
    const token = craftToken({ alg: 'RS256' }, { sub: 'user_1', exp: pastExp })
    expect(isJWTExpired(token)).toBe(true)
  })

  it('returns false for a token with no exp claim', () => {
    const token = craftToken({ alg: 'RS256' }, { sub: 'user_1' })
    expect(isJWTExpired(token)).toBe(false)
  })

  it('respects clockTolerance', () => {
    // Token expired 30 seconds ago
    const recentlyExpired = Math.floor(Date.now() / 1000) - 30
    const token = craftToken({ alg: 'RS256' }, { sub: 'user_1', exp: recentlyExpired })

    // Without tolerance, it's expired
    expect(isJWTExpired(token, 0)).toBe(true)

    // With 60s tolerance, it's not expired yet
    expect(isJWTExpired(token, 60)).toBe(false)
  })

  it('returns false for malformed tokens', () => {
    expect(isJWTExpired('not-a-jwt')).toBe(false)
    expect(isJWTExpired('')).toBe(false)
  })
})

// ── clearJWKSCache ──────────────────────────────────────────────────────

describe('clearJWKSCache', () => {
  it('does not throw when called', () => {
    expect(() => clearJWKSCache()).not.toThrow()
  })

  it('can be called multiple times', () => {
    clearJWKSCache()
    clearJWKSCache()
    clearJWKSCache()
    // No assertions needed — just verify it doesn't throw
  })
})

// ── Type exports compile check ──────────────────────────────────────────

describe('Type exports', () => {
  it('JWTHeader shape', () => {
    const header: JWTHeader = { alg: 'RS256', typ: 'JWT', kid: 'key-1' }
    expect(header.alg).toBe('RS256')
  })

  it('JWTPayload shape', () => {
    const payload: JWTPayload = {
      iss: 'https://id.org.ai',
      sub: 'user_1',
      aud: 'my-app',
      exp: 9999999999,
      nbf: 0,
      iat: 1000000000,
      jti: 'unique-id',
      custom: 'value',
    }
    expect(payload.sub).toBe('user_1')
    expect(payload['custom']).toBe('value')
  })

  it('JWTVerifyOptions shape', () => {
    const opts: JWTVerifyOptions = {
      jwksUrl: 'https://example.com/.well-known/jwks.json',
      issuer: 'https://example.com',
      audience: ['app1', 'app2'],
      clockTolerance: 30,
      ignoreExpiration: false,
    }
    expect(opts.issuer).toBe('https://example.com')
  })

  it('JWTVerifyResult discriminated union', () => {
    const success: JWTVerifyResult = { valid: true, payload: { sub: 'user_1' }, header: { alg: 'RS256' } }
    const failure: JWTVerifyResult = { valid: false, error: 'Invalid token' }
    const failureWithPayload: JWTVerifyResult = {
      valid: false,
      error: 'Expired',
      payload: { sub: 'user_1', exp: 0 },
      header: { alg: 'RS256' },
    }

    expect(success.valid).toBe(true)
    expect(failure.valid).toBe(false)
    expect(failureWithPayload.valid).toBe(false)
  })
})
