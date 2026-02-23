/**
 * JWT Signing Parity Tests
 *
 * Verifies that id.org.ai's jwt/signing module exposes the full
 * API surface from @dotdo/oauth's jwt-signing.ts:
 *
 * Functions: generateSigningKey, serializeSigningKey, deserializeSigningKey,
 *            exportPublicKeyToJWKS, exportKeysToJWKS, signJWT, signAccessToken,
 *            verifyJWTWithKeyManager
 *
 * Types: SigningKey, JWKSPublicKey, JWKS, SerializedSigningKey,
 *        AccessTokenClaims, VerifyJWTOptions
 *
 * Class: SigningKeyManager (getCurrentKey, getAllKeys, getJWKS, sign,
 *        signAccessToken, loadKeys, exportKeys, rotateKey)
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import {
  generateSigningKey,
  serializeSigningKey,
  deserializeSigningKey,
  exportPublicKeyToJWKS,
  exportKeysToJWKS,
  signJWT,
  signAccessToken,
  verifyJWTWithKeyManager,
  SigningKeyManager,
} from '../src/jwt/signing'
import type { SigningKey, SerializedSigningKey, AccessTokenClaims, JWKS, JWKSPublicKey, VerifyJWTOptions } from '../src/jwt/signing'

// ── Helpers ─────────────────────────────────────────────────────────────

function createMockStorage() {
  const store = new Map<string, unknown>()
  const storageOp = vi.fn(async (op: { op: string; key?: string; value?: unknown }) => {
    if (op.op === 'get') return { value: store.get(op.key!) }
    if (op.op === 'put') {
      store.set(op.key!, op.value)
      return {}
    }
    if (op.op === 'delete') {
      store.delete(op.key!)
      return {}
    }
    return {}
  })
  return { store, storageOp }
}

function base64UrlDecodeStr(str: string): string {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/')
  while (base64.length % 4 !== 0) base64 += '='
  return atob(base64)
}

function parseJWT(jwt: string) {
  const parts = jwt.split('.')
  return {
    header: JSON.parse(base64UrlDecodeStr(parts[0]!)),
    payload: JSON.parse(base64UrlDecodeStr(parts[1]!)),
    signature: parts[2],
  }
}

// ── Standalone Function Exports ─────────────────────────────────────────

describe('JWT Signing — standalone function exports', () => {
  it('exports generateSigningKey', () => {
    expect(typeof generateSigningKey).toBe('function')
  })

  it('exports serializeSigningKey', () => {
    expect(typeof serializeSigningKey).toBe('function')
  })

  it('exports deserializeSigningKey', () => {
    expect(typeof deserializeSigningKey).toBe('function')
  })

  it('exports exportPublicKeyToJWKS', () => {
    expect(typeof exportPublicKeyToJWKS).toBe('function')
  })

  it('exports exportKeysToJWKS', () => {
    expect(typeof exportKeysToJWKS).toBe('function')
  })

  it('exports signJWT', () => {
    expect(typeof signJWT).toBe('function')
  })

  it('exports signAccessToken as alias for signJWT', () => {
    expect(typeof signAccessToken).toBe('function')
    expect(signAccessToken).toBe(signJWT)
  })

  it('exports verifyJWTWithKeyManager', () => {
    expect(typeof verifyJWTWithKeyManager).toBe('function')
  })
})

// ── signAccessToken alias produces valid JWTs ───────────────────────────

describe('signAccessToken (alias)', () => {
  let key: SigningKey

  beforeEach(async () => {
    key = await generateSigningKey('test-key')
  })

  it('produces the same result as signJWT', async () => {
    // They are the same reference, so calling both with same args
    // at the same millisecond would produce identical tokens.
    // Instead we just verify signAccessToken produces a valid JWT.
    const token = await signAccessToken(key, { sub: 'user_1' }, { issuer: 'https://test.example.com' })
    expect(token.split('.')).toHaveLength(3)
    const { header, payload } = parseJWT(token)
    expect(header.alg).toBe('RS256')
    expect(header.kid).toBe('test-key')
    expect(payload.sub).toBe('user_1')
    expect(payload.iss).toBe('https://test.example.com')
  })
})

// ── verifyJWTWithKeyManager ─────────────────────────────────────────────

describe('verifyJWTWithKeyManager', () => {
  let manager: SigningKeyManager

  beforeEach(async () => {
    const { storageOp } = createMockStorage()
    manager = new SigningKeyManager(storageOp)
    // Force load
    await manager.getCurrentKey()
  })

  it('verifies a token signed by the manager', async () => {
    const token = await manager.sign({ sub: 'user_42' }, { issuer: 'https://id.org.ai' })
    const result = await verifyJWTWithKeyManager(token, manager, { issuer: 'https://id.org.ai' })
    expect(result).not.toBeNull()
    expect(result!.sub).toBe('user_42')
    expect(result!.iss).toBe('https://id.org.ai')
  })

  it('returns null for tampered tokens', async () => {
    const token = await manager.sign({ sub: 'user_1' }, { issuer: 'https://id.org.ai' })
    const tampered = token.slice(0, -5) + 'XXXXX'
    const result = await verifyJWTWithKeyManager(tampered, manager)
    expect(result).toBeNull()
  })

  it('returns null for wrong issuer', async () => {
    const token = await manager.sign({ sub: 'user_1' }, { issuer: 'https://id.org.ai' })
    const result = await verifyJWTWithKeyManager(token, manager, { issuer: 'https://wrong.example.com' })
    expect(result).toBeNull()
  })

  it('returns null for malformed input', async () => {
    expect(await verifyJWTWithKeyManager('not.a.jwt', manager)).toBeNull()
    expect(await verifyJWTWithKeyManager('', manager)).toBeNull()
    expect(await verifyJWTWithKeyManager('a.b', manager)).toBeNull()
  })

  it('validates audience when specified', async () => {
    const token = await manager.sign({ sub: 'user_1' }, { issuer: 'https://id.org.ai', audience: 'my-app' })
    const ok = await verifyJWTWithKeyManager(token, manager, { audience: 'my-app' })
    expect(ok).not.toBeNull()

    const fail = await verifyJWTWithKeyManager(token, manager, { audience: 'other-app' })
    expect(fail).toBeNull()
  })

  it('supports key rotation — verifies with old key', async () => {
    const token = await manager.sign({ sub: 'user_1' }, { issuer: 'https://id.org.ai' })
    await manager.rotateKey()
    // Should still verify since old key is kept
    const result = await verifyJWTWithKeyManager(token, manager, { issuer: 'https://id.org.ai' })
    expect(result).not.toBeNull()
    expect(result!.sub).toBe('user_1')
  })
})

// ── SigningKeyManager method parity ─────────────────────────────────────

describe('SigningKeyManager — method parity with @dotdo/oauth', () => {
  let manager: SigningKeyManager

  beforeEach(() => {
    const { storageOp } = createMockStorage()
    manager = new SigningKeyManager(storageOp)
  })

  it('has getCurrentKey()', async () => {
    const key = await manager.getCurrentKey()
    expect(key).toBeDefined()
    expect(key.kid).toBeDefined()
    expect(key.alg).toBe('RS256')
  })

  it('has getAllKeys() — returns copy of internal keys', async () => {
    await manager.getCurrentKey()
    const keys = manager.getAllKeys()
    expect(Array.isArray(keys)).toBe(true)
    expect(keys.length).toBeGreaterThanOrEqual(1)
    // Verify it returns a copy
    keys.push(null as unknown as SigningKey)
    expect(manager.getAllKeys().length).toBeLessThan(keys.length)
  })

  it('has getJWKS()', async () => {
    const jwks = await manager.getJWKS()
    expect(jwks.keys).toBeDefined()
    expect(jwks.keys.length).toBeGreaterThanOrEqual(1)
    expect(jwks.keys[0]!.kty).toBe('RSA')
    expect(jwks.keys[0]!.use).toBe('sig')
  })

  it('has sign()', async () => {
    const token = await manager.sign({ sub: 'test' }, { issuer: 'https://test.example.com' })
    expect(token.split('.')).toHaveLength(3)
  })

  it('has signAccessToken() as alias for sign()', async () => {
    const token = await manager.signAccessToken({ sub: 'test' }, { issuer: 'https://test.example.com' })
    expect(token.split('.')).toHaveLength(3)
    const { payload } = parseJWT(token)
    expect(payload.sub).toBe('test')
  })

  it('has loadKeys() — loads from serialized format', async () => {
    // Generate a key, serialize, and load into a new manager
    const key = await generateSigningKey('loaded-key')
    const serialized = await serializeSigningKey(key)

    const { storageOp: storageOp2 } = createMockStorage()
    const manager2 = new SigningKeyManager(storageOp2)
    await manager2.loadKeys([serialized])

    const keys = manager2.getAllKeys()
    expect(keys).toHaveLength(1)
    expect(keys[0]!.kid).toBe('loaded-key')
  })

  it('has exportKeys() — round-trips with loadKeys()', async () => {
    await manager.getCurrentKey() // force load
    const exported = await manager.exportKeys()
    expect(exported.length).toBeGreaterThanOrEqual(1)
    expect(exported[0]!.kid).toBeDefined()
    expect(exported[0]!.alg).toBe('RS256')
    expect(exported[0]!.privateKeyJwk).toBeDefined()
    expect(exported[0]!.publicKeyJwk).toBeDefined()

    // Load into a new manager and verify round-trip
    const { storageOp: storageOp2 } = createMockStorage()
    const manager2 = new SigningKeyManager(storageOp2)
    await manager2.loadKeys(exported)

    const keys = manager2.getAllKeys()
    expect(keys.length).toBe(exported.length)
    expect(keys[0]!.kid).toBe(exported[0]!.kid)
  })

  it('has rotateKey()', async () => {
    await manager.getCurrentKey()
    const initialKeys = manager.getAllKeys()
    expect(initialKeys).toHaveLength(1)

    await manager.rotateKey()
    const afterRotation = manager.getAllKeys()
    expect(afterRotation).toHaveLength(2)
    expect(afterRotation[1]!.kid).not.toBe(initialKeys[0]!.kid)
  })
})

// ── Type exports compile check ──────────────────────────────────────────

describe('Type exports', () => {
  it('SigningKey shape', async () => {
    const key: SigningKey = await generateSigningKey('type-check')
    expect(key.kid).toBe('type-check')
    expect(key.alg).toBe('RS256')
    expect(key.privateKey).toBeInstanceOf(CryptoKey)
    expect(key.publicKey).toBeInstanceOf(CryptoKey)
    expect(typeof key.createdAt).toBe('number')
  })

  it('SerializedSigningKey shape', async () => {
    const key = await generateSigningKey()
    const s: SerializedSigningKey = await serializeSigningKey(key)
    expect(s.kid).toBeDefined()
    expect(s.alg).toBe('RS256')
    expect(typeof s.privateKeyJwk).toBe('object')
    expect(typeof s.publicKeyJwk).toBe('object')
  })

  it('AccessTokenClaims allows extra fields', () => {
    const claims: AccessTokenClaims = { sub: 'user_1', custom_field: 'value' }
    expect(claims.sub).toBe('user_1')
    expect(claims.custom_field).toBe('value')
  })

  it('VerifyJWTOptions shape', () => {
    const opts: VerifyJWTOptions = { issuer: 'https://id.org.ai', audience: ['app1', 'app2'], clockTolerance: 30 }
    expect(opts.issuer).toBe('https://id.org.ai')
    expect(opts.audience).toEqual(['app1', 'app2'])
    expect(opts.clockTolerance).toBe(30)
  })

  it('JWKS and JWKSPublicKey shapes', async () => {
    const key = await generateSigningKey()
    const pk: JWKSPublicKey = await exportPublicKeyToJWKS(key)
    expect(pk.kty).toBe('RSA')
    expect(pk.use).toBe('sig')
    expect(pk.alg).toBe('RS256')

    const jwks: JWKS = await exportKeysToJWKS([key])
    expect(jwks.keys).toHaveLength(1)
  })
})
