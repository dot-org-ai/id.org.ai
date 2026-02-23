/**
 * JWT Verification for id.org.ai
 *
 * Server-side JWT token validation with JWKS support.
 * Validates standard JWT claims (exp, iat, iss, aud) and
 * fetches public keys from JWKS endpoints.
 *
 * Ported from @dotdo/oauth core/src/jwt.ts
 */

import { base64UrlDecode } from './pkce'

// ═══════════════════════════════════════════════════════════════════════════
// Type Guards (inlined from @dotdo/oauth guards.ts)
// ═══════════════════════════════════════════════════════════════════════════

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function isString(value: unknown): value is string {
  return typeof value === 'string'
}

function isNumber(value: unknown): value is number {
  return typeof value === 'number' && !Number.isNaN(value)
}

function isJWTHeader(data: unknown): data is JWTHeader {
  if (!isObject(data)) return false
  if (!isString(data['alg'])) return false
  if (data['typ'] !== undefined && !isString(data['typ'])) return false
  if (data['kid'] !== undefined && !isString(data['kid'])) return false
  return true
}

function isJWTPayload(data: unknown): data is JWTPayload {
  if (!isObject(data)) return false
  if (data['iss'] !== undefined && !isString(data['iss'])) return false
  if (data['sub'] !== undefined && !isString(data['sub'])) return false
  if (data['exp'] !== undefined && !isNumber(data['exp'])) return false
  if (data['nbf'] !== undefined && !isNumber(data['nbf'])) return false
  if (data['iat'] !== undefined && !isNumber(data['iat'])) return false
  if (data['jti'] !== undefined && !isString(data['jti'])) return false
  if (data['aud'] !== undefined) {
    if (!isString(data['aud']) && !Array.isArray(data['aud'])) return false
    if (Array.isArray(data['aud']) && !(data['aud'] as unknown[]).every((a: unknown) => isString(a))) return false
  }
  return true
}

// ═══════════════════════════════════════════════════════════════════════════
// Public Types
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Result of JWT verification - discriminated union based on validity
 */
export type JWTVerifyResult =
  | { valid: true; payload: JWTPayload; header: JWTHeader; error?: undefined }
  | { valid: false; error: string; payload?: undefined; header?: undefined }
  | { valid: false; error: string; payload: JWTPayload; header: JWTHeader }

/**
 * JWT Header
 */
export interface JWTHeader {
  /** Algorithm used for signing */
  alg: string
  /** Token type (typically 'JWT') */
  typ?: string
  /** Key ID for JWKS lookup */
  kid?: string
}

/**
 * Standard JWT Payload claims
 */
export interface JWTPayload {
  /** Issuer */
  iss?: string
  /** Subject */
  sub?: string
  /** Audience (can be string or array) */
  aud?: string | string[]
  /** Expiration time (Unix timestamp) */
  exp?: number
  /** Not before (Unix timestamp) */
  nbf?: number
  /** Issued at (Unix timestamp) */
  iat?: number
  /** JWT ID */
  jti?: string
  /** Additional claims */
  [key: string]: unknown
}

/**
 * Options for JWT verification
 */
export interface JWTVerifyOptions {
  /** JWKS URL for fetching public keys */
  jwksUrl?: string
  /** Expected issuer */
  issuer?: string
  /** Expected audience (can be string or array) */
  audience?: string | string[]
  /** Pre-loaded public key (alternative to jwksUrl) */
  publicKey?: CryptoKey
  /** Clock tolerance in seconds for exp/nbf/iat checks (default: 60) */
  clockTolerance?: number
  /** Skip expiration check */
  ignoreExpiration?: boolean
}

// ═══════════════════════════════════════════════════════════════════════════
// Internal Types
// ═══════════════════════════════════════════════════════════════════════════

interface JWKS {
  keys: JWK[]
}

interface JWK {
  kty: string
  kid?: string
  use?: string
  alg?: string
  n?: string
  e?: string
  x?: string
  y?: string
  crv?: string
}

// Cache for JWKS to avoid repeated fetches
const jwksCache = new Map<string, { keys: Map<string, CryptoKey>; expiresAt: number }>()
const JWKS_CACHE_TTL = 5 * 60 * 1000 // 5 minutes

// ═══════════════════════════════════════════════════════════════════════════
// Public API
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Verify a JWT token
 *
 * @param token - The JWT token to verify
 * @param options - Verification options
 * @returns Verification result with payload if valid
 *
 * @example With JWKS URL
 * ```typescript
 * const result = await verifyJWT(token, {
 *   jwksUrl: 'https://issuer.com/.well-known/jwks.json',
 *   issuer: 'https://issuer.com',
 *   audience: 'my-api'
 * })
 *
 * if (result.valid) {
 *   console.log('User ID:', result.payload?.sub)
 * } else {
 *   console.error('Invalid token:', result.error)
 * }
 * ```
 *
 * @example With pre-loaded public key
 * ```typescript
 * const result = await verifyJWT(token, {
 *   publicKey: await crypto.subtle.importKey(...),
 *   issuer: 'https://issuer.com'
 * })
 * ```
 */
export async function verifyJWT(token: string, options: JWTVerifyOptions = {}): Promise<JWTVerifyResult> {
  const { jwksUrl, issuer, audience, publicKey, clockTolerance = 60, ignoreExpiration = false } = options

  try {
    // Parse the JWT
    const parts = token.split('.')
    if (parts.length !== 3) {
      return { valid: false, error: 'Invalid JWT format: expected 3 parts' }
    }

    const [headerB64, payloadB64, signatureB64] = parts

    // Decode header
    let header: JWTHeader
    try {
      header = JSON.parse(decodeBase64Url(headerB64!))
    } catch {
      return { valid: false, error: 'Invalid JWT header: failed to decode' }
    }

    // Decode payload
    let payload: JWTPayload
    try {
      payload = JSON.parse(decodeBase64Url(payloadB64!))
    } catch {
      return { valid: false, error: 'Invalid JWT payload: failed to decode' }
    }

    // Validate algorithm
    if (!isSupportedAlgorithm(header.alg)) {
      return { valid: false, error: `Unsupported algorithm: ${header.alg}`, header, payload }
    }

    // Get the public key
    let key: CryptoKey
    if (publicKey) {
      key = publicKey
    } else if (jwksUrl) {
      const fetchedKey = await getKeyFromJWKS(jwksUrl, header.kid, header.alg)
      if (!fetchedKey) {
        return { valid: false, error: 'No matching key found in JWKS', header, payload }
      }
      key = fetchedKey
    } else {
      return { valid: false, error: 'Either jwksUrl or publicKey must be provided', header, payload }
    }

    // Verify signature
    const signatureValid = await verifySignature(`${headerB64}.${payloadB64}`, signatureB64!, key, header.alg)

    if (!signatureValid) {
      return { valid: false, error: 'Invalid signature', header, payload }
    }

    // Validate claims
    const now = Math.floor(Date.now() / 1000)

    // Check expiration
    if (!ignoreExpiration && payload.exp !== undefined) {
      if (now > payload.exp + clockTolerance) {
        return { valid: false, error: 'Token has expired', header, payload }
      }
    }

    // Check not before
    if (payload.nbf !== undefined) {
      if (now < payload.nbf - clockTolerance) {
        return { valid: false, error: 'Token not yet valid (nbf)', header, payload }
      }
    }

    // Check issued at (prevent tokens issued in the future)
    if (payload.iat !== undefined) {
      if (payload.iat > now + clockTolerance) {
        return { valid: false, error: 'Token issued in the future (iat)', header, payload }
      }
    }

    // Check issuer
    if (issuer !== undefined) {
      if (payload.iss !== issuer) {
        return { valid: false, error: `Invalid issuer: expected ${issuer}, got ${payload.iss}`, header, payload }
      }
    }

    // Check audience
    if (audience !== undefined) {
      const tokenAud = Array.isArray(payload.aud) ? payload.aud : payload.aud ? [payload.aud] : []
      const expectedAud = Array.isArray(audience) ? audience : [audience]

      const hasValidAudience = expectedAud.some((aud) => tokenAud.includes(aud))
      if (!hasValidAudience) {
        return {
          valid: false,
          error: `Invalid audience: expected one of ${expectedAud.join(', ')}, got ${tokenAud.join(', ')}`,
          header,
          payload,
        }
      }
    }

    return { valid: true, payload, header }
  } catch (err) {
    return {
      valid: false,
      error: err instanceof Error ? err.message : 'Unknown error during verification',
    }
  }
}

/**
 * Decode a JWT without verifying the signature
 * Useful for inspecting tokens before verification
 *
 * @param token - The JWT token to decode
 * @returns Decoded header and payload, or null if invalid format
 */
export function decodeJWT(token: string): { header: JWTHeader; payload: JWTPayload } | null {
  try {
    const parts = token.split('.')
    if (parts.length !== 3) {
      return null
    }

    const headerData = JSON.parse(decodeBase64Url(parts[0]!))
    const payloadData = JSON.parse(decodeBase64Url(parts[1]!))
    if (!isJWTHeader(headerData) || !isJWTPayload(payloadData)) {
      return null
    }

    return { header: headerData, payload: payloadData }
  } catch {
    return null
  }
}

/**
 * Check if a JWT is expired (without full verification)
 *
 * @param token - The JWT token to check
 * @param clockTolerance - Tolerance in seconds (default: 0)
 * @returns true if expired, false if valid or no exp claim
 */
export function isJWTExpired(token: string, clockTolerance: number = 0): boolean {
  const decoded = decodeJWT(token)
  if (!decoded || decoded.payload.exp === undefined) {
    return false
  }

  const now = Math.floor(Date.now() / 1000)
  return now > decoded.payload.exp + clockTolerance
}

/**
 * Clear the JWKS cache (useful for testing)
 */
export function clearJWKSCache(): void {
  jwksCache.clear()
}

// ═══════════════════════════════════════════════════════════════════════════
// Internal Helper Functions
// ═══════════════════════════════════════════════════════════════════════════

function decodeBase64Url(str: string): string {
  const buffer = base64UrlDecode(str)
  return new TextDecoder().decode(buffer)
}

function isSupportedAlgorithm(alg: string): boolean {
  return ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'].includes(alg)
}

type AlgorithmParams = { name: 'RSASSA-PKCS1-v1_5'; hash: string } | { name: 'ECDSA'; hash: string; namedCurve: string }

function getAlgorithmParams(alg: string): AlgorithmParams {
  switch (alg) {
    case 'RS256':
      return { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }
    case 'RS384':
      return { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' }
    case 'RS512':
      return { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' }
    case 'ES256':
      return { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' }
    case 'ES384':
      return { name: 'ECDSA', hash: 'SHA-384', namedCurve: 'P-384' }
    case 'ES512':
      return { name: 'ECDSA', hash: 'SHA-512', namedCurve: 'P-521' }
    default:
      throw new Error(`Unsupported algorithm: ${alg}`)
  }
}

async function verifySignature(data: string, signature: string, key: CryptoKey, alg: string): Promise<boolean> {
  const encoder = new TextEncoder()
  const dataBytes = encoder.encode(data)
  let signatureBytes = new Uint8Array(base64UrlDecode(signature))

  const params = getAlgorithmParams(alg)

  if (params.name === 'ECDSA') {
    signatureBytes = convertJWTSignatureToWebCrypto(signatureBytes, alg)
  }

  const algorithm = params.name === 'ECDSA' ? { name: 'ECDSA', hash: params.hash } : { name: params.name }

  return crypto.subtle.verify(algorithm, key, signatureBytes, dataBytes)
}

function convertJWTSignatureToWebCrypto(signature: Uint8Array<ArrayBuffer>, alg: string): Uint8Array<ArrayBuffer> {
  const expectedLength = alg === 'ES256' ? 64 : alg === 'ES384' ? 96 : 132
  if (signature.length !== expectedLength) {
    // If signature is DER encoded, we might need to convert it
    // For now, return as-is and let verification fail if format is wrong
  }
  return signature
}

async function getKeyFromJWKS(jwksUrl: string, kid: string | undefined, alg: string): Promise<CryptoKey | null> {
  // Check cache
  const cached = jwksCache.get(jwksUrl)
  if (cached && cached.expiresAt > Date.now()) {
    if (kid && cached.keys.has(kid)) {
      return cached.keys.get(kid)!
    }
    if (!kid) {
      for (const key of cached.keys.values()) {
        return key
      }
    }
  }

  // Fetch JWKS
  const response = await fetch(jwksUrl)
  if (!response.ok) {
    throw new Error(`Failed to fetch JWKS: ${response.status} ${response.statusText}`)
  }

  const jwks: JWKS = await response.json()
  const keys = new Map<string, CryptoKey>()

  for (const jwk of jwks.keys) {
    try {
      const cryptoKey = await importJWK(jwk, alg)
      if (cryptoKey) {
        const keyId = jwk.kid || `${jwk.kty}-${jwk.alg || alg}`
        keys.set(keyId, cryptoKey)
      }
    } catch {
      continue
    }
  }

  jwksCache.set(jwksUrl, {
    keys,
    expiresAt: Date.now() + JWKS_CACHE_TTL,
  })

  if (kid && keys.has(kid)) {
    return keys.get(kid)!
  }

  if (!kid && keys.size > 0) {
    return keys.values().next().value ?? null
  }

  return null
}

async function importJWK(jwk: JWK, expectedAlg: string): Promise<CryptoKey | null> {
  const params = getAlgorithmParams(expectedAlg)

  if (jwk.kty === 'RSA' && params.name.startsWith('RSA')) {
    if (!jwk.n || !jwk.e) {
      return null
    }

    return crypto.subtle.importKey(
      'jwk',
      { kty: 'RSA', n: jwk.n, e: jwk.e, alg: expectedAlg, use: 'sig' },
      { name: params.name, hash: params.hash! },
      false,
      ['verify'],
    )
  }

  if (jwk.kty === 'EC' && params.name === 'ECDSA') {
    if (!jwk.x || !jwk.y || !jwk.crv) {
      return null
    }

    return crypto.subtle.importKey(
      'jwk',
      { kty: 'EC', x: jwk.x, y: jwk.y, crv: jwk.crv, use: 'sig' },
      { name: 'ECDSA', namedCurve: jwk.crv },
      false,
      ['verify'],
    )
  }

  return null
}
