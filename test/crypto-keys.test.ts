/**
 * Ed25519 Crypto Key Tests
 *
 * Tests for key generation, signing, verification, DID conversion,
 * PEM encoding/decoding, and base58/base64 utilities.
 */

import { describe, it, expect } from 'vitest'
import {
  base58Encode,
  base58Decode,
  base64Encode,
  base64Decode,
  publicKeyToDID,
  didToPublicKey,
  isValidDID,
  publicKeyToPEM,
  pemToPublicKey,
  generateKeypair,
  sign,
  verify,
  signMessage,
  verifyMessage,
  verifyFromDID,
} from '../src/crypto/keys'

// ── Base58 Tests ────────────────────────────────────────────────────────

describe('base58', () => {
  it('encodes and decodes empty data', () => {
    const data = new Uint8Array(0)
    const encoded = base58Encode(data)
    expect(encoded).toBe('')
    const decoded = base58Decode(encoded)
    expect(decoded).toEqual(data)
  })

  it('encodes and decodes single byte', () => {
    const data = new Uint8Array([1])
    const encoded = base58Encode(data)
    expect(encoded).toBe('2')
    const decoded = base58Decode(encoded)
    expect(decoded).toEqual(data)
  })

  it('encodes leading zeros', () => {
    const data = new Uint8Array([0, 0, 1])
    const encoded = base58Encode(data)
    expect(encoded.startsWith('11')).toBe(true)
    const decoded = base58Decode(encoded)
    expect(decoded).toEqual(data)
  })

  it('round-trips a 32-byte key', () => {
    const data = new Uint8Array(32)
    crypto.getRandomValues(data)
    const encoded = base58Encode(data)
    const decoded = base58Decode(encoded)
    expect(decoded).toEqual(data)
  })

  it('throws on invalid base58 characters', () => {
    expect(() => base58Decode('0OIl')).toThrow('Invalid base58 character')
  })
})

// ── Base64 Tests ────────────────────────────────────────────────────────

describe('base64', () => {
  it('encodes and decodes empty data', () => {
    const data = new Uint8Array(0)
    const encoded = base64Encode(data)
    const decoded = base64Decode(encoded)
    expect(decoded).toEqual(data)
  })

  it('round-trips arbitrary data', () => {
    const data = new Uint8Array([72, 101, 108, 108, 111]) // "Hello"
    const encoded = base64Encode(data)
    expect(encoded).toBe('SGVsbG8=')
    const decoded = base64Decode(encoded)
    expect(decoded).toEqual(data)
  })

  it('round-trips a 32-byte key', () => {
    const data = new Uint8Array(32)
    crypto.getRandomValues(data)
    const encoded = base64Encode(data)
    const decoded = base64Decode(encoded)
    expect(decoded).toEqual(data)
  })
})

// ── DID Conversion Tests ────────────────────────────────────────────────

describe('DID conversion', () => {
  it('converts a 32-byte public key to DID format', () => {
    const publicKey = new Uint8Array(32).fill(1)
    const did = publicKeyToDID(publicKey)
    expect(did).toMatch(/^did:agent:ed25519:.+$/)
  })

  it('round-trips public key to DID and back', () => {
    const publicKey = new Uint8Array(32)
    crypto.getRandomValues(publicKey)
    const did = publicKeyToDID(publicKey)
    const recovered = didToPublicKey(did)
    expect(recovered).toEqual(publicKey)
  })

  it('throws for invalid DID prefix', () => {
    expect(() => didToPublicKey('did:key:z123')).toThrow('Invalid DID format')
  })

  it('throws for empty DID public key part', () => {
    expect(() => didToPublicKey('did:agent:ed25519:')).toThrow('empty public key')
  })

  it('throws for wrong-length decoded key', () => {
    // Encode a 16-byte array as base58 to create a valid-looking but wrong-length DID
    const shortKey = new Uint8Array(16).fill(42)
    const encoded = base58Encode(shortKey)
    expect(() => didToPublicKey(`did:agent:ed25519:${encoded}`)).toThrow('32-byte')
  })
})

// ── DID Validation Tests ────────────────────────────────────────────────

describe('isValidDID', () => {
  it('validates correct DID format', () => {
    const publicKey = new Uint8Array(32)
    crypto.getRandomValues(publicKey)
    const did = publicKeyToDID(publicKey)
    expect(isValidDID(did)).toBe(true)
  })

  it('rejects DID with wrong prefix', () => {
    expect(isValidDID('did:key:z123')).toBe(false)
  })

  it('rejects DID with empty encoded part', () => {
    expect(isValidDID('did:agent:ed25519:')).toBe(false)
  })

  it('rejects DID with too-short encoded part', () => {
    expect(isValidDID('did:agent:ed25519:abc')).toBe(false)
  })

  it('rejects DID with invalid base58 characters', () => {
    expect(isValidDID('did:agent:ed25519:0OIl' + 'A'.repeat(40))).toBe(false)
  })
})

// ── PEM Encoding Tests ──────────────────────────────────────────────────

describe('PEM encoding', () => {
  it('encodes a 32-byte public key to PEM', () => {
    const publicKey = new Uint8Array(32).fill(0xAB)
    const pem = publicKeyToPEM(publicKey)
    expect(pem).toContain('-----BEGIN PUBLIC KEY-----')
    expect(pem).toContain('-----END PUBLIC KEY-----')
  })

  it('throws for non-32-byte public key', () => {
    const shortKey = new Uint8Array(16)
    expect(() => publicKeyToPEM(shortKey)).toThrow('32-byte')
  })

  it('round-trips public key through PEM', () => {
    const publicKey = new Uint8Array(32)
    crypto.getRandomValues(publicKey)
    const pem = publicKeyToPEM(publicKey)
    const recovered = pemToPublicKey(pem)
    expect(recovered).toEqual(publicKey)
  })

  it('decodes PEM with extra whitespace', () => {
    const publicKey = new Uint8Array(32).fill(0x42)
    const pem = publicKeyToPEM(publicKey)
    // Add extra whitespace
    const messyPem = pem.replace('\n', '\n\n  ')
    const recovered = pemToPublicKey(messyPem)
    expect(recovered).toEqual(publicKey)
  })

  it('throws for empty PEM', () => {
    expect(() => pemToPublicKey('-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----')).toThrow()
  })

  it('throws for non-Ed25519 PEM', () => {
    // Create a PEM with wrong OID prefix
    const fakeDer = new Uint8Array(44).fill(0xFF)
    const b64 = base64Encode(fakeDer)
    const fakePem = `-----BEGIN PUBLIC KEY-----\n${b64}\n-----END PUBLIC KEY-----`
    expect(() => pemToPublicKey(fakePem)).toThrow('SPKI prefix mismatch')
  })
})

// ── Ed25519 Key Generation Tests ────────────────────────────────────────

describe('generateKeypair', () => {
  it('generates a valid keypair', async () => {
    const keypair = await generateKeypair()

    expect(keypair.publicKey).toBeInstanceOf(Uint8Array)
    expect(keypair.publicKey.length).toBe(32)
    expect(keypair.privateKey).toBeInstanceOf(Uint8Array)
    expect(keypair.privateKey.length).toBe(32)
    expect(keypair.did).toMatch(/^did:agent:ed25519:.+$/)
  })

  it('generates unique keypairs', async () => {
    const kp1 = await generateKeypair()
    const kp2 = await generateKeypair()

    expect(kp1.did).not.toBe(kp2.did)
    expect(kp1.publicKey).not.toEqual(kp2.publicKey)
    expect(kp1.privateKey).not.toEqual(kp2.privateKey)
  })

  it('DID matches the public key', async () => {
    const keypair = await generateKeypair()
    const recoveredKey = didToPublicKey(keypair.did)
    expect(recoveredKey).toEqual(keypair.publicKey)
  })
})

// ── Ed25519 Sign / Verify Tests ─────────────────────────────────────────

describe('sign and verify', () => {
  it('signs and verifies a message', async () => {
    const keypair = await generateKeypair()
    const message = new TextEncoder().encode('Hello, agents!')

    const signature = await sign(message, keypair.privateKey)

    expect(signature).toBeInstanceOf(Uint8Array)
    expect(signature.length).toBe(64)

    const valid = await verify(message, signature, keypair.publicKey)
    expect(valid).toBe(true)
  })

  it('rejects tampered message', async () => {
    const keypair = await generateKeypair()
    const message = new TextEncoder().encode('Original message')
    const tampered = new TextEncoder().encode('Tampered message')

    const signature = await sign(message, keypair.privateKey)
    const valid = await verify(tampered, signature, keypair.publicKey)
    expect(valid).toBe(false)
  })

  it('rejects wrong public key', async () => {
    const kp1 = await generateKeypair()
    const kp2 = await generateKeypair()
    const message = new TextEncoder().encode('Signed by kp1')

    const signature = await sign(message, kp1.privateKey)
    const valid = await verify(message, signature, kp2.publicKey)
    expect(valid).toBe(false)
  })

  it('throws for wrong-length private key', async () => {
    const shortKey = new Uint8Array(16)
    const message = new TextEncoder().encode('test')
    await expect(sign(message, shortKey)).rejects.toThrow('32-byte')
  })

  it('throws for wrong-length public key', async () => {
    const shortKey = new Uint8Array(16)
    const message = new TextEncoder().encode('test')
    const sig = new Uint8Array(64)
    await expect(verify(message, sig, shortKey)).rejects.toThrow('32-byte')
  })

  it('throws for wrong-length signature', async () => {
    const keypair = await generateKeypair()
    const message = new TextEncoder().encode('test')
    const shortSig = new Uint8Array(32)
    await expect(verify(message, shortSig, keypair.publicKey)).rejects.toThrow('64-byte')
  })
})

// ── String Sign / Verify Tests ──────────────────────────────────────────

describe('signMessage and verifyMessage', () => {
  it('signs and verifies a string message', async () => {
    const keypair = await generateKeypair()
    const message = 'A message for signing'

    const signatureB64 = await signMessage(message, keypair.privateKey)
    expect(typeof signatureB64).toBe('string')

    const valid = await verifyMessage(message, signatureB64, keypair.publicKey)
    expect(valid).toBe(true)
  })

  it('rejects tampered string message', async () => {
    const keypair = await generateKeypair()
    const signatureB64 = await signMessage('original', keypair.privateKey)

    const valid = await verifyMessage('tampered', signatureB64, keypair.publicKey)
    expect(valid).toBe(false)
  })

  it('returns false for invalid base64 signature', async () => {
    const keypair = await generateKeypair()
    const valid = await verifyMessage('test', '!!!invalid-base64!!!', keypair.publicKey)
    expect(valid).toBe(false)
  })
})

// ── DID-based Verification Tests ────────────────────────────────────────

describe('verifyFromDID', () => {
  it('verifies a signature using DID', async () => {
    const keypair = await generateKeypair()
    const message = 'Verify me via DID'
    const signatureB64 = await signMessage(message, keypair.privateKey)

    const valid = await verifyFromDID(keypair.did, message, signatureB64)
    expect(valid).toBe(true)
  })

  it('rejects invalid DID format', async () => {
    const valid = await verifyFromDID('did:invalid:format', 'test', 'dGVzdA==')
    expect(valid).toBe(false)
  })

  it('rejects wrong DID', async () => {
    const kp1 = await generateKeypair()
    const kp2 = await generateKeypair()
    const message = 'Signed by kp1'
    const signatureB64 = await signMessage(message, kp1.privateKey)

    const valid = await verifyFromDID(kp2.did, message, signatureB64)
    expect(valid).toBe(false)
  })
})
