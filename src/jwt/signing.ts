/**
 * JWT Signing Key Management for id.org.ai
 *
 * Manages RSA-2048 signing keys for JWT token issuance.
 * Keys are persisted in Durable Object storage and cached in memory.
 *
 * Ported from @dotdo/oauth jwt-signing.ts — adapted for DO storage.
 */

// ============================================================================
// Types
// ============================================================================

export interface SigningKey {
  kid: string
  alg: 'RS256'
  privateKey: CryptoKey
  publicKey: CryptoKey
  createdAt: number
}

export interface JWKSPublicKey {
  kty: 'RSA'
  kid: string
  use: 'sig'
  alg: 'RS256'
  n: string
  e: string
}

export interface JWKS {
  keys: JWKSPublicKey[]
}

export interface SerializedSigningKey {
  kid: string
  alg: 'RS256'
  privateKeyJwk: JsonWebKey
  publicKeyJwk: JsonWebKey
  createdAt: number
}

export interface AccessTokenClaims {
  sub: string
  email?: string
  name?: string
  image?: string
  org_id?: string
  roles?: string[]
  permissions?: string[]
  [key: string]: unknown
}

// ============================================================================
// Base64URL Utilities
// ============================================================================

function base64UrlEncode(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer)
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

// ============================================================================
// Key Generation & Serialization
// ============================================================================

export async function generateSigningKey(kid?: string): Promise<SigningKey> {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify'],
  ) as CryptoKeyPair

  if (!kid) {
    const jwk = (await crypto.subtle.exportKey('jwk', keyPair.publicKey)) as JsonWebKey
    const thumbprintInput = JSON.stringify({ e: jwk.e, kty: jwk.kty, n: jwk.n })
    const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(thumbprintInput))
    kid = base64UrlEncode(hash).slice(0, 16)
  }

  return {
    kid,
    alg: 'RS256',
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
    createdAt: Date.now(),
  }
}

export async function serializeSigningKey(key: SigningKey): Promise<SerializedSigningKey> {
  const [privateKeyJwk, publicKeyJwk] = await Promise.all([
    crypto.subtle.exportKey('jwk', key.privateKey) as Promise<JsonWebKey>,
    crypto.subtle.exportKey('jwk', key.publicKey) as Promise<JsonWebKey>,
  ])

  return {
    kid: key.kid,
    alg: key.alg,
    privateKeyJwk,
    publicKeyJwk,
    createdAt: key.createdAt,
  }
}

export async function deserializeSigningKey(serialized: SerializedSigningKey): Promise<SigningKey> {
  const [privateKey, publicKey] = await Promise.all([
    crypto.subtle.importKey('jwk', serialized.privateKeyJwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, true, ['sign']),
    crypto.subtle.importKey('jwk', serialized.publicKeyJwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, true, ['verify']),
  ])

  return {
    kid: serialized.kid,
    alg: serialized.alg,
    privateKey,
    publicKey,
    createdAt: serialized.createdAt,
  }
}

export async function exportPublicKeyToJWKS(key: SigningKey): Promise<JWKSPublicKey> {
  const jwk = (await crypto.subtle.exportKey('jwk', key.publicKey)) as JsonWebKey
  return {
    kty: 'RSA',
    kid: key.kid,
    use: 'sig',
    alg: 'RS256',
    n: jwk.n!,
    e: jwk.e!,
  }
}

export async function exportKeysToJWKS(keys: SigningKey[]): Promise<JWKS> {
  const publicKeys = await Promise.all(keys.map(exportPublicKeyToJWKS))
  return { keys: publicKeys }
}

// ============================================================================
// JWT Signing
// ============================================================================

export async function signJWT(
  key: SigningKey,
  claims: AccessTokenClaims,
  options: {
    issuer: string
    audience?: string
    expiresIn?: number // seconds, default 3600 (1 hour)
  },
): Promise<string> {
  const { issuer, audience, expiresIn = 3600 } = options
  const now = Math.floor(Date.now() / 1000)

  const header = { alg: 'RS256' as const, typ: 'JWT' as const, kid: key.kid }
  const payload = {
    ...claims,
    iss: issuer,
    ...(audience && { aud: audience }),
    iat: now,
    exp: now + expiresIn,
  }

  const encoder = new TextEncoder()
  const headerB64 = base64UrlEncode(encoder.encode(JSON.stringify(header)).buffer as ArrayBuffer)
  const payloadB64 = base64UrlEncode(encoder.encode(JSON.stringify(payload)).buffer as ArrayBuffer)
  const data = `${headerB64}.${payloadB64}`

  const signature = await crypto.subtle.sign({ name: 'RSASSA-PKCS1-v1_5' }, key.privateKey, encoder.encode(data))
  const signatureB64 = base64UrlEncode(signature)

  return `${data}.${signatureB64}`
}

// ============================================================================
// SigningKeyManager — DO-backed key storage with in-memory cache
// ============================================================================

type StorageOp = (op: {
  op: 'get' | 'put' | 'delete' | 'list'
  key?: string
  value?: unknown
  options?: { expirationTtl?: number; prefix?: string; limit?: number }
}) => Promise<Record<string, unknown>>

const SIGNING_KEYS_STORAGE_KEY = 'signing-keys'

/**
 * Manages signing keys with DO storage persistence.
 *
 * Usage:
 *   const manager = new SigningKeyManager(oauthStub.oauthStorageOp)
 *   const jwks = await manager.getJWKS()
 *   const jwt = await manager.sign(claims, { issuer: 'https://id.org.ai' })
 */
export class SigningKeyManager {
  private keys: SigningKey[] = []
  private loaded = false

  constructor(private storageOp: StorageOp) {}

  private async ensureLoaded(): Promise<void> {
    if (this.loaded) return

    const result = await this.storageOp({ op: 'get', key: SIGNING_KEYS_STORAGE_KEY })
    const serialized = result.value as SerializedSigningKey[] | undefined

    if (serialized && serialized.length > 0) {
      this.keys = await Promise.all(serialized.map(deserializeSigningKey))
    } else {
      // Generate initial key
      const key = await generateSigningKey()
      this.keys = [key]
      await this.persistKeys()
    }

    this.loaded = true
  }

  private async persistKeys(): Promise<void> {
    const serialized = await Promise.all(this.keys.map(serializeSigningKey))
    await this.storageOp({ op: 'put', key: SIGNING_KEYS_STORAGE_KEY, value: serialized })
  }

  async getCurrentKey(): Promise<SigningKey> {
    await this.ensureLoaded()
    return this.keys[this.keys.length - 1]!
  }

  async getJWKS(): Promise<JWKS> {
    await this.ensureLoaded()
    return exportKeysToJWKS(this.keys)
  }

  async sign(
    claims: AccessTokenClaims,
    options: { issuer: string; audience?: string; expiresIn?: number },
  ): Promise<string> {
    const key = await this.getCurrentKey()
    return signJWT(key, claims, options)
  }

  async rotateKey(): Promise<SigningKey> {
    await this.ensureLoaded()
    const newKey = await generateSigningKey()
    this.keys.push(newKey)

    // Keep at most 2 keys (current + previous for rotation grace period)
    while (this.keys.length > 2) this.keys.shift()

    await this.persistKeys()
    return newKey
  }
}
