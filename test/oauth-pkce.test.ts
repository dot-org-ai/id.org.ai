import { describe, it, expect } from 'vitest'
import {
  generateCodeVerifier,
  generateCodeChallenge,
  verifyCodeChallenge,
  generatePkce,
  generateState,
  generateToken,
  generateAuthorizationCode,
  hashClientSecret,
  verifyClientSecret,
  base64UrlEncode,
  base64UrlDecode,
  constantTimeEqual,
} from '../src/oauth/pkce'

describe('PKCE Utilities', () => {
  describe('generateCodeVerifier', () => {
    it('generates a verifier of default length 64', () => {
      const verifier = generateCodeVerifier()
      expect(verifier).toHaveLength(64)
    })

    it('generates a verifier of specified length', () => {
      const verifier = generateCodeVerifier(43)
      expect(verifier).toHaveLength(43)

      const verifier128 = generateCodeVerifier(128)
      expect(verifier128).toHaveLength(128)
    })

    it('only contains unreserved URI characters', () => {
      const verifier = generateCodeVerifier()
      // RFC 7636: [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
      expect(verifier).toMatch(/^[A-Za-z0-9\-._~]+$/)
    })

    it('throws for length < 43', () => {
      expect(() => generateCodeVerifier(42)).toThrow('Code verifier length must be between 43 and 128 characters')
    })

    it('throws for length > 128', () => {
      expect(() => generateCodeVerifier(129)).toThrow('Code verifier length must be between 43 and 128 characters')
    })

    it('generates unique verifiers', () => {
      const a = generateCodeVerifier()
      const b = generateCodeVerifier()
      expect(a).not.toBe(b)
    })
  })

  describe('generateCodeChallenge + verifyCodeChallenge', () => {
    it('S256 round-trip: challenge verifies against its verifier', async () => {
      const verifier = generateCodeVerifier()
      const challenge = await generateCodeChallenge(verifier)

      expect(typeof challenge).toBe('string')
      expect(challenge.length).toBeGreaterThan(0)
      // Base64URL: no +, /, or = padding
      expect(challenge).toMatch(/^[A-Za-z0-9_-]+$/)

      const valid = await verifyCodeChallenge(verifier, challenge, 'S256')
      expect(valid).toBe(true)
    })

    it('rejects wrong verifier', async () => {
      const verifier = generateCodeVerifier()
      const challenge = await generateCodeChallenge(verifier)

      const wrongVerifier = generateCodeVerifier()
      const valid = await verifyCodeChallenge(wrongVerifier, challenge, 'S256')
      expect(valid).toBe(false)
    })

    it('rejects plain method (OAuth 2.1 only supports S256)', async () => {
      const verifier = generateCodeVerifier()
      const valid = await verifyCodeChallenge(verifier, verifier, 'plain')
      expect(valid).toBe(false)
    })

    it('defaults to S256 when method is omitted', async () => {
      const verifier = generateCodeVerifier()
      const challenge = await generateCodeChallenge(verifier)
      const valid = await verifyCodeChallenge(verifier, challenge)
      expect(valid).toBe(true)
    })
  })

  describe('generatePkce', () => {
    it('returns matched verifier and challenge pair', async () => {
      const { verifier, challenge } = await generatePkce()

      expect(verifier).toHaveLength(64)
      expect(typeof challenge).toBe('string')
      expect(challenge.length).toBeGreaterThan(0)

      const valid = await verifyCodeChallenge(verifier, challenge)
      expect(valid).toBe(true)
    })

    it('accepts custom length', async () => {
      const { verifier, challenge } = await generatePkce(96)

      expect(verifier).toHaveLength(96)
      const valid = await verifyCodeChallenge(verifier, challenge)
      expect(valid).toBe(true)
    })
  })

  describe('generateState', () => {
    it('generates a state string of default length 32', () => {
      const state = generateState()
      expect(state).toHaveLength(32)
      expect(state).toMatch(/^[A-Za-z0-9]+$/)
    })

    it('generates a state string of specified length', () => {
      const state = generateState(64)
      expect(state).toHaveLength(64)
    })
  })

  describe('generateToken', () => {
    it('generates unique tokens', () => {
      const a = generateToken()
      const b = generateToken()
      expect(a).not.toBe(b)
    })

    it('generates token of default length 32', () => {
      const token = generateToken()
      expect(token).toHaveLength(32)
      expect(token).toMatch(/^[A-Za-z0-9]+$/)
    })

    it('generates token of specified length', () => {
      const token = generateToken(64)
      expect(token).toHaveLength(64)
    })
  })

  describe('generateAuthorizationCode', () => {
    it('generates a 48-character alphanumeric code', () => {
      const code = generateAuthorizationCode()
      expect(code).toHaveLength(48)
      expect(code).toMatch(/^[A-Za-z0-9]+$/)
    })

    it('generates unique codes', () => {
      const a = generateAuthorizationCode()
      const b = generateAuthorizationCode()
      expect(a).not.toBe(b)
    })
  })

  describe('hashClientSecret + verifyClientSecret', () => {
    it('round-trip: hashed secret verifies correctly', async () => {
      const secret = generateToken(64)
      const hash = await hashClientSecret(secret)

      expect(typeof hash).toBe('string')
      expect(hash.length).toBeGreaterThan(0)

      const valid = await verifyClientSecret(secret, hash)
      expect(valid).toBe(true)
    })

    it('rejects wrong secret', async () => {
      const secret = generateToken(64)
      const hash = await hashClientSecret(secret)

      const wrongSecret = generateToken(64)
      const valid = await verifyClientSecret(wrongSecret, hash)
      expect(valid).toBe(false)
    })

    it('produces consistent hashes for the same input', async () => {
      const secret = 'test-client-secret-12345'
      const hash1 = await hashClientSecret(secret)
      const hash2 = await hashClientSecret(secret)
      expect(hash1).toBe(hash2)
    })
  })

  describe('base64UrlEncode / base64UrlDecode', () => {
    it('round-trip: encode then decode returns original bytes', () => {
      const original = new Uint8Array([0, 1, 2, 127, 128, 255])
      const encoded = base64UrlEncode(original.buffer)
      const decoded = base64UrlDecode(encoded)
      const result = new Uint8Array(decoded)

      expect(result).toEqual(original)
    })

    it('produces URL-safe output (no +, /, or = padding)', () => {
      // Use bytes that would produce +, /, and = in standard base64
      const data = new Uint8Array([255, 254, 253, 252, 251])
      const encoded = base64UrlEncode(data.buffer)

      expect(encoded).not.toContain('+')
      expect(encoded).not.toContain('/')
      expect(encoded).not.toContain('=')
      expect(encoded).toMatch(/^[A-Za-z0-9_-]+$/)
    })

    it('handles empty buffer', () => {
      const empty = new Uint8Array(0)
      const encoded = base64UrlEncode(empty.buffer)
      expect(encoded).toBe('')

      const decoded = base64UrlDecode(encoded)
      expect(new Uint8Array(decoded)).toEqual(empty)
    })
  })

  describe('constantTimeEqual', () => {
    it('returns true for identical strings', async () => {
      const result = await constantTimeEqual('hello-world', 'hello-world')
      expect(result).toBe(true)
    })

    it('returns false for different strings', async () => {
      const result = await constantTimeEqual('hello-world', 'hello-worlD')
      expect(result).toBe(false)
    })

    it('returns false for different lengths', async () => {
      const result = await constantTimeEqual('short', 'much-longer-string')
      expect(result).toBe(false)
    })

    it('returns true for empty strings', async () => {
      const result = await constantTimeEqual('', '')
      expect(result).toBe(true)
    })
  })
})
