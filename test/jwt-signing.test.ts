/**
 * JWT Signing Module Tests
 *
 * Comprehensive tests for RSA-2048 signing key generation,
 * serialization, JWKS export, JWT signing, and SigningKeyManager.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import {
  generateSigningKey,
  serializeSigningKey,
  deserializeSigningKey,
  exportPublicKeyToJWKS,
  exportKeysToJWKS,
  signJWT,
  SigningKeyManager,
} from '../src/jwt/signing'
import type { SigningKey, SerializedSigningKey, AccessTokenClaims, JWKS, JWKSPublicKey } from '../src/jwt/signing'

// ── Helpers ─────────────────────────────────────────────────────────────

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

  // Decode base64url signature back to ArrayBuffer
  let sigB64 = parts[2].replace(/-/g, '+').replace(/_/g, '/')
  while (sigB64.length % 4 !== 0) sigB64 += '='
  const sigBinary = atob(sigB64)
  const sigBytes = new Uint8Array(sigBinary.length)
  for (let i = 0; i < sigBinary.length; i++) sigBytes[i] = sigBinary.charCodeAt(i)

  return crypto.subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, publicKey, sigBytes.buffer, encoder.encode(data))
}

/** Create a mock storageOp for SigningKeyManager tests */
function createMockStorage() {
  const store = new Map<string, unknown>()
  const storageOp = vi.fn(async (op: { op: string; key?: string; value?: unknown }) => {
    switch (op.op) {
      case 'get':
        return { value: store.get(op.key!) }
      case 'put':
        store.set(op.key!, op.value)
        return {}
      case 'delete':
        store.delete(op.key!)
        return {}
      case 'list':
        return Object.fromEntries(store)
      default:
        return {}
    }
  })
  return { store, storageOp }
}

// ============================================================================
// generateSigningKey()
// ============================================================================

describe('generateSigningKey', () => {
  it('generates an RSA-2048 key pair', async () => {
    const key = await generateSigningKey()
    expect(key.privateKey).toBeInstanceOf(CryptoKey)
    expect(key.publicKey).toBeInstanceOf(CryptoKey)
  })

  it('sets alg to RS256', async () => {
    const key = await generateSigningKey()
    expect(key.alg).toBe('RS256')
  })

  it('sets a createdAt timestamp', async () => {
    const before = Date.now()
    const key = await generateSigningKey()
    const after = Date.now()
    expect(key.createdAt).toBeGreaterThanOrEqual(before)
    expect(key.createdAt).toBeLessThanOrEqual(after)
  })

  it('auto-generates kid from JWK thumbprint when not provided', async () => {
    const key = await generateSigningKey()
    expect(typeof key.kid).toBe('string')
    expect(key.kid.length).toBe(16)
  })

  it('auto-generated kid contains only base64url characters', async () => {
    const key = await generateSigningKey()
    expect(key.kid).toMatch(/^[A-Za-z0-9_-]+$/)
  })

  it('uses provided kid when given', async () => {
    const key = await generateSigningKey('my-custom-kid')
    expect(key.kid).toBe('my-custom-kid')
  })

  it('generates unique kids for different key pairs', async () => {
    const key1 = await generateSigningKey()
    const key2 = await generateSigningKey()
    expect(key1.kid).not.toBe(key2.kid)
  })

  it('generates keys that can sign and verify', async () => {
    const key = await generateSigningKey()
    const data = new TextEncoder().encode('test message')
    const signature = await crypto.subtle.sign({ name: 'RSASSA-PKCS1-v1_5' }, key.privateKey, data)
    const valid = await crypto.subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, key.publicKey, signature, data)
    expect(valid).toBe(true)
  })

  it('private key has sign usage', async () => {
    const key = await generateSigningKey()
    expect(key.privateKey.usages).toContain('sign')
  })

  it('public key has verify usage', async () => {
    const key = await generateSigningKey()
    expect(key.publicKey.usages).toContain('verify')
  })

  it('keys use RSASSA-PKCS1-v1_5 algorithm', async () => {
    const key = await generateSigningKey()
    expect((key.privateKey.algorithm as RsaHashedKeyAlgorithm).name).toBe('RSASSA-PKCS1-v1_5')
    expect((key.publicKey.algorithm as RsaHashedKeyAlgorithm).name).toBe('RSASSA-PKCS1-v1_5')
  })

  it('keys are extractable', async () => {
    const key = await generateSigningKey()
    expect(key.privateKey.extractable).toBe(true)
    expect(key.publicKey.extractable).toBe(true)
  })
})

// ============================================================================
// serializeSigningKey() / deserializeSigningKey()
// ============================================================================

describe('serializeSigningKey', () => {
  it('produces a serialized object with correct structure', async () => {
    const key = await generateSigningKey('test-kid')
    const serialized = await serializeSigningKey(key)

    expect(serialized.kid).toBe('test-kid')
    expect(serialized.alg).toBe('RS256')
    expect(serialized.createdAt).toBe(key.createdAt)
    expect(serialized.privateKeyJwk).toBeDefined()
    expect(serialized.publicKeyJwk).toBeDefined()
  })

  it('serialized private key JWK has RSA fields', async () => {
    const key = await generateSigningKey()
    const serialized = await serializeSigningKey(key)

    expect(serialized.privateKeyJwk.kty).toBe('RSA')
    expect(serialized.privateKeyJwk.n).toBeDefined()
    expect(serialized.privateKeyJwk.e).toBeDefined()
    expect(serialized.privateKeyJwk.d).toBeDefined() // private exponent
  })

  it('serialized public key JWK has RSA fields but no private exponent', async () => {
    const key = await generateSigningKey()
    const serialized = await serializeSigningKey(key)

    expect(serialized.publicKeyJwk.kty).toBe('RSA')
    expect(serialized.publicKeyJwk.n).toBeDefined()
    expect(serialized.publicKeyJwk.e).toBeDefined()
    expect(serialized.publicKeyJwk.d).toBeUndefined()
  })

  it('preserves kid through serialization', async () => {
    const key = await generateSigningKey('preserve-me')
    const serialized = await serializeSigningKey(key)
    expect(serialized.kid).toBe('preserve-me')
  })
})

describe('deserializeSigningKey', () => {
  it('round-trips correctly: serialize then deserialize produces equivalent key', async () => {
    const original = await generateSigningKey('round-trip')
    const serialized = await serializeSigningKey(original)
    const restored = await deserializeSigningKey(serialized)

    expect(restored.kid).toBe(original.kid)
    expect(restored.alg).toBe(original.alg)
    expect(restored.createdAt).toBe(original.createdAt)
  })

  it('deserialized key can sign and verify', async () => {
    const original = await generateSigningKey()
    const serialized = await serializeSigningKey(original)
    const restored = await deserializeSigningKey(serialized)

    const data = new TextEncoder().encode('verify after deserialize')
    const signature = await crypto.subtle.sign({ name: 'RSASSA-PKCS1-v1_5' }, restored.privateKey, data)
    const valid = await crypto.subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, restored.publicKey, signature, data)
    expect(valid).toBe(true)
  })

  it('deserialized key produces same signature as original', async () => {
    const original = await generateSigningKey()
    const serialized = await serializeSigningKey(original)
    const restored = await deserializeSigningKey(serialized)

    // Sign with original, verify with restored
    const data = new TextEncoder().encode('cross-verify')
    const signature = await crypto.subtle.sign({ name: 'RSASSA-PKCS1-v1_5' }, original.privateKey, data)
    const valid = await crypto.subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, restored.publicKey, signature, data)
    expect(valid).toBe(true)
  })

  it('deserialized private key has sign usage', async () => {
    const original = await generateSigningKey()
    const serialized = await serializeSigningKey(original)
    const restored = await deserializeSigningKey(serialized)
    expect(restored.privateKey.usages).toContain('sign')
  })

  it('deserialized public key has verify usage', async () => {
    const original = await generateSigningKey()
    const serialized = await serializeSigningKey(original)
    const restored = await deserializeSigningKey(serialized)
    expect(restored.publicKey.usages).toContain('verify')
  })
})

// ============================================================================
// exportPublicKeyToJWKS() / exportKeysToJWKS()
// ============================================================================

describe('exportPublicKeyToJWKS', () => {
  it('exports correct JWKS format fields', async () => {
    const key = await generateSigningKey('jwks-kid')
    const jwksKey = await exportPublicKeyToJWKS(key)

    expect(jwksKey.kty).toBe('RSA')
    expect(jwksKey.kid).toBe('jwks-kid')
    expect(jwksKey.use).toBe('sig')
    expect(jwksKey.alg).toBe('RS256')
  })

  it('includes n and e fields', async () => {
    const key = await generateSigningKey()
    const jwksKey = await exportPublicKeyToJWKS(key)

    expect(typeof jwksKey.n).toBe('string')
    expect(jwksKey.n.length).toBeGreaterThan(0)
    expect(typeof jwksKey.e).toBe('string')
    expect(jwksKey.e).toBe('AQAB') // standard RSA public exponent 65537
  })

  it('does not expose private key material', async () => {
    const key = await generateSigningKey()
    const jwksKey = await exportPublicKeyToJWKS(key)

    // Should only have the specified fields, no d, dp, dq, qi, p, q
    const keyObj = jwksKey as Record<string, unknown>
    expect(keyObj.d).toBeUndefined()
    expect(keyObj.dp).toBeUndefined()
    expect(keyObj.dq).toBeUndefined()
    expect(keyObj.qi).toBeUndefined()
    expect(keyObj.p).toBeUndefined()
    expect(keyObj.q).toBeUndefined()
  })

  it('preserves the kid from the signing key', async () => {
    const key = await generateSigningKey('specific-kid-value')
    const jwksKey = await exportPublicKeyToJWKS(key)
    expect(jwksKey.kid).toBe('specific-kid-value')
  })
})

describe('exportKeysToJWKS', () => {
  it('exports empty array when no keys provided', async () => {
    const jwks = await exportKeysToJWKS([])
    expect(jwks.keys).toEqual([])
  })

  it('exports single key correctly', async () => {
    const key = await generateSigningKey()
    const jwks = await exportKeysToJWKS([key])

    expect(jwks.keys).toHaveLength(1)
    expect(jwks.keys[0].kty).toBe('RSA')
    expect(jwks.keys[0].kid).toBe(key.kid)
  })

  it('exports multiple keys correctly', async () => {
    const key1 = await generateSigningKey('kid-1')
    const key2 = await generateSigningKey('kid-2')
    const key3 = await generateSigningKey('kid-3')

    const jwks = await exportKeysToJWKS([key1, key2, key3])

    expect(jwks.keys).toHaveLength(3)
    expect(jwks.keys.map((k) => k.kid)).toEqual(['kid-1', 'kid-2', 'kid-3'])
  })

  it('all exported keys have correct format', async () => {
    const keys = await Promise.all([generateSigningKey(), generateSigningKey()])
    const jwks = await exportKeysToJWKS(keys)

    for (const key of jwks.keys) {
      expect(key.kty).toBe('RSA')
      expect(key.use).toBe('sig')
      expect(key.alg).toBe('RS256')
      expect(key.n).toBeDefined()
      expect(key.e).toBeDefined()
      expect(key.kid).toBeDefined()
    }
  })

  it('returns object with keys property (standard JWKS structure)', async () => {
    const key = await generateSigningKey()
    const jwks = await exportKeysToJWKS([key])
    expect(jwks).toHaveProperty('keys')
    expect(Array.isArray(jwks.keys)).toBe(true)
  })
})

// ============================================================================
// signJWT()
// ============================================================================

describe('signJWT', () => {
  let signingKey: SigningKey

  beforeEach(async () => {
    signingKey = await generateSigningKey('jwt-test-kid')
  })

  it('produces a valid 3-part JWT (header.payload.signature)', async () => {
    const jwt = await signJWT(signingKey, { sub: 'user_1' }, { issuer: 'https://id.org.ai' })
    const parts = jwt.split('.')
    expect(parts).toHaveLength(3)
    expect(parts[0].length).toBeGreaterThan(0)
    expect(parts[1].length).toBeGreaterThan(0)
    expect(parts[2].length).toBeGreaterThan(0)
  })

  it('header contains alg: RS256', async () => {
    const jwt = await signJWT(signingKey, { sub: 'user_1' }, { issuer: 'https://id.org.ai' })
    const { header } = parseJWT(jwt)
    expect(header.alg).toBe('RS256')
  })

  it('header contains typ: JWT', async () => {
    const jwt = await signJWT(signingKey, { sub: 'user_1' }, { issuer: 'https://id.org.ai' })
    const { header } = parseJWT(jwt)
    expect(header.typ).toBe('JWT')
  })

  it('header contains the signing key kid', async () => {
    const jwt = await signJWT(signingKey, { sub: 'user_1' }, { issuer: 'https://id.org.ai' })
    const { header } = parseJWT(jwt)
    expect(header.kid).toBe('jwt-test-kid')
  })

  it('payload contains sub claim', async () => {
    const jwt = await signJWT(signingKey, { sub: 'user_123' }, { issuer: 'https://id.org.ai' })
    const { payload } = parseJWT(jwt)
    expect(payload.sub).toBe('user_123')
  })

  it('payload contains iss claim', async () => {
    const jwt = await signJWT(signingKey, { sub: 'user_1' }, { issuer: 'https://id.org.ai' })
    const { payload } = parseJWT(jwt)
    expect(payload.iss).toBe('https://id.org.ai')
  })

  it('payload contains iat claim (issued at)', async () => {
    const before = Math.floor(Date.now() / 1000)
    const jwt = await signJWT(signingKey, { sub: 'user_1' }, { issuer: 'https://id.org.ai' })
    const after = Math.floor(Date.now() / 1000)
    const { payload } = parseJWT(jwt)

    expect(payload.iat).toBeGreaterThanOrEqual(before)
    expect(payload.iat).toBeLessThanOrEqual(after)
  })

  it('payload contains exp claim (expiration)', async () => {
    const jwt = await signJWT(signingKey, { sub: 'user_1' }, { issuer: 'https://id.org.ai' })
    const { payload } = parseJWT(jwt)

    expect(payload.exp).toBeDefined()
    expect((payload.exp as number) - (payload.iat as number)).toBe(3600) // default 1 hour
  })

  it('respects expiresIn option', async () => {
    const jwt = await signJWT(signingKey, { sub: 'user_1' }, { issuer: 'https://id.org.ai', expiresIn: 7200 })
    const { payload } = parseJWT(jwt)
    expect((payload.exp as number) - (payload.iat as number)).toBe(7200)
  })

  it('uses default expiresIn of 3600 seconds when not specified', async () => {
    const jwt = await signJWT(signingKey, { sub: 'user_1' }, { issuer: 'https://id.org.ai' })
    const { payload } = parseJWT(jwt)
    expect((payload.exp as number) - (payload.iat as number)).toBe(3600)
  })

  it('includes audience when provided', async () => {
    const jwt = await signJWT(signingKey, { sub: 'user_1' }, { issuer: 'https://id.org.ai', audience: 'https://api.example.com' })
    const { payload } = parseJWT(jwt)
    expect(payload.aud).toBe('https://api.example.com')
  })

  it('omits audience when not provided', async () => {
    const jwt = await signJWT(signingKey, { sub: 'user_1' }, { issuer: 'https://id.org.ai' })
    const { payload } = parseJWT(jwt)
    expect(payload.aud).toBeUndefined()
  })

  it('includes email custom claim', async () => {
    const jwt = await signJWT(signingKey, { sub: 'user_1', email: 'alice@example.com' }, { issuer: 'https://id.org.ai' })
    const { payload } = parseJWT(jwt)
    expect(payload.email).toBe('alice@example.com')
  })

  it('includes name custom claim', async () => {
    const jwt = await signJWT(signingKey, { sub: 'user_1', name: 'Alice Smith' }, { issuer: 'https://id.org.ai' })
    const { payload } = parseJWT(jwt)
    expect(payload.name).toBe('Alice Smith')
  })

  it('includes org_id custom claim', async () => {
    const jwt = await signJWT(signingKey, { sub: 'user_1', org_id: 'org_abc' }, { issuer: 'https://id.org.ai' })
    const { payload } = parseJWT(jwt)
    expect(payload.org_id).toBe('org_abc')
  })

  it('includes roles custom claim', async () => {
    const jwt = await signJWT(signingKey, { sub: 'user_1', roles: ['admin', 'editor'] }, { issuer: 'https://id.org.ai' })
    const { payload } = parseJWT(jwt)
    expect(payload.roles).toEqual(['admin', 'editor'])
  })

  it('includes permissions custom claim', async () => {
    const jwt = await signJWT(signingKey, { sub: 'user_1', permissions: ['read', 'write', 'delete'] }, { issuer: 'https://id.org.ai' })
    const { payload } = parseJWT(jwt)
    expect(payload.permissions).toEqual(['read', 'write', 'delete'])
  })

  it('includes arbitrary custom claims via index signature', async () => {
    const jwt = await signJWT(signingKey, { sub: 'user_1', tenant: 'acme', tier: 'pro' }, { issuer: 'https://id.org.ai' })
    const { payload } = parseJWT(jwt)
    expect(payload.tenant).toBe('acme')
    expect(payload.tier).toBe('pro')
  })

  it('signature is verifiable with the public key', async () => {
    const jwt = await signJWT(signingKey, { sub: 'user_1' }, { issuer: 'https://id.org.ai' })
    const valid = await verifyJWTSignature(jwt, signingKey.publicKey)
    expect(valid).toBe(true)
  })

  it('signature fails verification with a different key', async () => {
    const otherKey = await generateSigningKey()
    const jwt = await signJWT(signingKey, { sub: 'user_1' }, { issuer: 'https://id.org.ai' })
    const valid = await verifyJWTSignature(jwt, otherKey.publicKey)
    expect(valid).toBe(false)
  })

  it('handles very short expiresIn', async () => {
    const jwt = await signJWT(signingKey, { sub: 'user_1' }, { issuer: 'https://id.org.ai', expiresIn: 1 })
    const { payload } = parseJWT(jwt)
    expect((payload.exp as number) - (payload.iat as number)).toBe(1)
  })

  it('handles very long expiresIn', async () => {
    const thirtyDays = 30 * 24 * 3600
    const jwt = await signJWT(signingKey, { sub: 'user_1' }, { issuer: 'https://id.org.ai', expiresIn: thirtyDays })
    const { payload } = parseJWT(jwt)
    expect((payload.exp as number) - (payload.iat as number)).toBe(thirtyDays)
  })

  it('JWT parts are valid base64url (no +, /, or = characters)', async () => {
    const jwt = await signJWT(
      signingKey,
      { sub: 'user_1', email: 'a@b.com', name: 'Test User', roles: ['admin'] },
      { issuer: 'https://id.org.ai', audience: 'https://api.test.com' },
    )
    const parts = jwt.split('.')
    for (const part of parts) {
      expect(part).not.toMatch(/[+/=]/)
    }
  })

  it('includes all standard and custom claims together', async () => {
    const claims: AccessTokenClaims = {
      sub: 'user_all',
      email: 'all@example.com',
      name: 'All Claims',
      image: 'https://example.com/avatar.png',
      org_id: 'org_full',
      roles: ['owner'],
      permissions: ['*'],
    }
    const jwt = await signJWT(signingKey, claims, { issuer: 'https://id.org.ai', audience: 'https://app.example.com', expiresIn: 1800 })
    const { payload } = parseJWT(jwt)

    expect(payload.sub).toBe('user_all')
    expect(payload.email).toBe('all@example.com')
    expect(payload.name).toBe('All Claims')
    expect(payload.image).toBe('https://example.com/avatar.png')
    expect(payload.org_id).toBe('org_full')
    expect(payload.roles).toEqual(['owner'])
    expect(payload.permissions).toEqual(['*'])
    expect(payload.iss).toBe('https://id.org.ai')
    expect(payload.aud).toBe('https://app.example.com')
    expect((payload.exp as number) - (payload.iat as number)).toBe(1800)
  })
})

// ============================================================================
// SigningKeyManager
// ============================================================================

describe('SigningKeyManager', () => {
  let mockStorage: ReturnType<typeof createMockStorage>
  let manager: SigningKeyManager

  beforeEach(() => {
    mockStorage = createMockStorage()
    manager = new SigningKeyManager(mockStorage.storageOp)
  })

  // ── getCurrentKey() ───────────────────────────────────────────────────

  describe('getCurrentKey', () => {
    it('generates a key on first call when storage is empty', async () => {
      const key = await manager.getCurrentKey()
      expect(key).toBeDefined()
      expect(key.kid).toBeDefined()
      expect(key.alg).toBe('RS256')
      expect(key.privateKey).toBeInstanceOf(CryptoKey)
      expect(key.publicKey).toBeInstanceOf(CryptoKey)
    })

    it('returns the same key on subsequent calls', async () => {
      const key1 = await manager.getCurrentKey()
      const key2 = await manager.getCurrentKey()
      expect(key1.kid).toBe(key2.kid)
      expect(key1.createdAt).toBe(key2.createdAt)
    })

    it('calls storageOp get on first access', async () => {
      await manager.getCurrentKey()
      expect(mockStorage.storageOp).toHaveBeenCalledWith(
        expect.objectContaining({ op: 'get', key: 'signing-keys' }),
      )
    })

    it('only loads from storage once (caches in memory)', async () => {
      await manager.getCurrentKey()
      await manager.getCurrentKey()
      await manager.getCurrentKey()

      const getCalls = mockStorage.storageOp.mock.calls.filter((c) => c[0].op === 'get')
      expect(getCalls).toHaveLength(1)
    })

    it('persists generated key to storage when storage is empty', async () => {
      await manager.getCurrentKey()

      const putCalls = mockStorage.storageOp.mock.calls.filter((c) => c[0].op === 'put')
      expect(putCalls).toHaveLength(1)
      expect(putCalls[0][0].key).toBe('signing-keys')

      const stored = putCalls[0][0].value as SerializedSigningKey[]
      expect(stored).toHaveLength(1)
      expect(stored[0].alg).toBe('RS256')
    })

    it('loads keys from storage on first access', async () => {
      // Pre-populate storage with a serialized key
      const preKey = await generateSigningKey('pre-loaded-kid')
      const serialized = await serializeSigningKey(preKey)
      mockStorage.store.set('signing-keys', [serialized])

      const key = await manager.getCurrentKey()
      expect(key.kid).toBe('pre-loaded-kid')
    })
  })

  // ── getJWKS() ─────────────────────────────────────────────────────────

  describe('getJWKS', () => {
    it('returns a valid JWKS document', async () => {
      const jwks = await manager.getJWKS()
      expect(jwks).toHaveProperty('keys')
      expect(Array.isArray(jwks.keys)).toBe(true)
    })

    it('contains at least one key when storage is empty (generates one)', async () => {
      const jwks = await manager.getJWKS()
      expect(jwks.keys.length).toBeGreaterThanOrEqual(1)
    })

    it('returned keys have correct JWKS format', async () => {
      const jwks = await manager.getJWKS()
      for (const key of jwks.keys) {
        expect(key.kty).toBe('RSA')
        expect(key.use).toBe('sig')
        expect(key.alg).toBe('RS256')
        expect(key.kid).toBeDefined()
        expect(key.n).toBeDefined()
        expect(key.e).toBeDefined()
      }
    })

    it('JWKS kid matches the current signing key kid', async () => {
      const currentKey = await manager.getCurrentKey()
      const jwks = await manager.getJWKS()
      const kids = jwks.keys.map((k) => k.kid)
      expect(kids).toContain(currentKey.kid)
    })
  })

  // ── sign() ────────────────────────────────────────────────────────────

  describe('sign', () => {
    it('produces a valid JWT string', async () => {
      const jwt = await manager.sign({ sub: 'user_1' }, { issuer: 'https://id.org.ai' })
      expect(jwt.split('.')).toHaveLength(3)
    })

    it('JWT is verifiable with the current key', async () => {
      const jwt = await manager.sign({ sub: 'user_1' }, { issuer: 'https://id.org.ai' })
      const currentKey = await manager.getCurrentKey()
      const valid = await verifyJWTSignature(jwt, currentKey.publicKey)
      expect(valid).toBe(true)
    })

    it('JWT contains the correct claims', async () => {
      const jwt = await manager.sign({ sub: 'user_mgr', email: 'mgr@test.com' }, { issuer: 'https://id.org.ai', audience: 'test-aud' })
      const { payload } = parseJWT(jwt)
      expect(payload.sub).toBe('user_mgr')
      expect(payload.email).toBe('mgr@test.com')
      expect(payload.iss).toBe('https://id.org.ai')
      expect(payload.aud).toBe('test-aud')
    })

    it('JWT header kid matches the current key kid', async () => {
      const jwt = await manager.sign({ sub: 'user_1' }, { issuer: 'https://id.org.ai' })
      const currentKey = await manager.getCurrentKey()
      const { header } = parseJWT(jwt)
      expect(header.kid).toBe(currentKey.kid)
    })

    it('passes expiresIn to signJWT', async () => {
      const jwt = await manager.sign({ sub: 'user_1' }, { issuer: 'https://id.org.ai', expiresIn: 300 })
      const { payload } = parseJWT(jwt)
      expect((payload.exp as number) - (payload.iat as number)).toBe(300)
    })
  })

  // ── rotateKey() ───────────────────────────────────────────────────────

  describe('rotateKey', () => {
    it('generates a new key', async () => {
      const originalKey = await manager.getCurrentKey()
      const newKey = await manager.rotateKey()
      expect(newKey.kid).not.toBe(originalKey.kid)
    })

    it('getCurrentKey returns the new key after rotation', async () => {
      await manager.getCurrentKey()
      const rotatedKey = await manager.rotateKey()
      const currentKey = await manager.getCurrentKey()
      expect(currentKey.kid).toBe(rotatedKey.kid)
    })

    it('JWKS contains both old and new keys after one rotation', async () => {
      const oldKey = await manager.getCurrentKey()
      const newKey = await manager.rotateKey()
      const jwks = await manager.getJWKS()

      expect(jwks.keys).toHaveLength(2)
      const kids = jwks.keys.map((k) => k.kid)
      expect(kids).toContain(oldKey.kid)
      expect(kids).toContain(newKey.kid)
    })

    it('keeps at most 2 keys after multiple rotations', async () => {
      await manager.getCurrentKey()
      await manager.rotateKey()
      await manager.rotateKey()
      await manager.rotateKey()

      const jwks = await manager.getJWKS()
      expect(jwks.keys).toHaveLength(2)
    })

    it('after 3 rotations, only the last 2 keys remain', async () => {
      const key0 = await manager.getCurrentKey()
      const key1 = await manager.rotateKey()
      const key2 = await manager.rotateKey()
      const key3 = await manager.rotateKey()

      const jwks = await manager.getJWKS()
      const kids = jwks.keys.map((k) => k.kid)

      expect(kids).not.toContain(key0.kid)
      expect(kids).not.toContain(key1.kid)
      expect(kids).toContain(key2.kid)
      expect(kids).toContain(key3.kid)
    })

    it('persists rotated keys to storage', async () => {
      await manager.getCurrentKey()
      mockStorage.storageOp.mockClear()

      await manager.rotateKey()

      const putCalls = mockStorage.storageOp.mock.calls.filter((c) => c[0].op === 'put')
      expect(putCalls).toHaveLength(1)
      expect(putCalls[0][0].key).toBe('signing-keys')

      const stored = putCalls[0][0].value as SerializedSigningKey[]
      expect(stored).toHaveLength(2) // old + new
    })

    it('JWTs signed before rotation are still verifiable via JWKS', async () => {
      const jwtBefore = await manager.sign({ sub: 'user_before' }, { issuer: 'https://id.org.ai' })
      const oldKey = await manager.getCurrentKey()

      await manager.rotateKey()

      // The old key is still in JWKS, so verifying should work
      const valid = await verifyJWTSignature(jwtBefore, oldKey.publicKey)
      expect(valid).toBe(true)

      // Confirm old key is still in JWKS
      const jwks = await manager.getJWKS()
      const kids = jwks.keys.map((k) => k.kid)
      expect(kids).toContain(oldKey.kid)
    })

    it('rotated key can sign valid JWTs', async () => {
      await manager.getCurrentKey()
      const newKey = await manager.rotateKey()

      const jwt = await manager.sign({ sub: 'user_after_rotate' }, { issuer: 'https://id.org.ai' })
      const valid = await verifyJWTSignature(jwt, newKey.publicKey)
      expect(valid).toBe(true)
    })
  })

  // ── Storage Interaction ───────────────────────────────────────────────

  describe('storage persistence', () => {
    it('new manager instance loads previously persisted keys', async () => {
      // First manager generates and persists a key
      const key1 = await manager.getCurrentKey()

      // Second manager with same storage should load the persisted key
      const manager2 = new SigningKeyManager(mockStorage.storageOp)
      const key2 = await manager2.getCurrentKey()

      expect(key2.kid).toBe(key1.kid)
    })

    it('generates new key if storage returns undefined', async () => {
      // Storage that always returns undefined
      const emptyStorageOp = vi.fn(async () => ({ value: undefined }))
      const emptyManager = new SigningKeyManager(emptyStorageOp)
      const key = await emptyManager.getCurrentKey()
      expect(key).toBeDefined()
      expect(key.kid).toBeDefined()
    })

    it('generates new key if storage returns empty array', async () => {
      mockStorage.store.set('signing-keys', [])
      const key = await manager.getCurrentKey()
      expect(key).toBeDefined()
      expect(key.kid.length).toBeGreaterThan(0)
    })

    it('persists keys after rotation in serialized form', async () => {
      await manager.getCurrentKey()
      await manager.rotateKey()

      const storedValue = mockStorage.store.get('signing-keys') as SerializedSigningKey[]
      expect(Array.isArray(storedValue)).toBe(true)
      expect(storedValue).toHaveLength(2)

      for (const serialized of storedValue) {
        expect(serialized.kid).toBeDefined()
        expect(serialized.alg).toBe('RS256')
        expect(serialized.privateKeyJwk).toBeDefined()
        expect(serialized.publicKeyJwk).toBeDefined()
        expect(serialized.createdAt).toBeDefined()
      }
    })
  })
})
