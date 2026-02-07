/**
 * Ed25519 Agent Keypairs
 *
 * Agents authenticate via Ed25519 keypair signatures.
 * Public keys stored in git as .headless.ly/agents/*.pub
 * DID format: did:agent:ed25519:{base58pubkey}
 *
 * Uses the Web Crypto API (available in Cloudflare Workers runtime)
 * for Ed25519 key generation, signing, and verification.
 *
 * Key formats:
 *   - Raw: 32-byte Uint8Array (public key) / 32-byte seed (private key)
 *   - DID: did:agent:ed25519:{base58-encoded-public-key}
 *   - PEM: PKCS#8 (private) / SPKI (public) base64-wrapped
 *   - Base64: standard base64 encoding for transport
 */

// ============================================================================
// Base58 Encoding (Bitcoin alphabet)
// ============================================================================

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

/**
 * Encode a Uint8Array to base58 string (Bitcoin alphabet).
 */
export function base58Encode(data: Uint8Array): string {
  if (data.length === 0) return ''

  // Count leading zeros
  let zeros = 0
  while (zeros < data.length && data[zeros] === 0) {
    zeros++
  }

  // Convert to big integer representation
  // Allocate enough space in base58 representation
  const size = Math.ceil(data.length * 138 / 100) + 1
  const b58 = new Uint8Array(size)

  let length = 0
  for (let i = zeros; i < data.length; i++) {
    let carry = data[i]
    let j = 0

    for (let k = size - 1; (carry !== 0 || j < length) && k >= 0; k--, j++) {
      carry += 256 * b58[k]
      b58[k] = carry % 58
      carry = Math.floor(carry / 58)
    }

    length = j
  }

  // Skip leading zeros in base58 result
  let it = size - length
  while (it < size && b58[it] === 0) {
    it++
  }

  // Build the result string
  let result = BASE58_ALPHABET[0].repeat(zeros)
  for (; it < size; it++) {
    result += BASE58_ALPHABET[b58[it]]
  }

  return result
}

/**
 * Decode a base58 string to Uint8Array.
 */
export function base58Decode(str: string): Uint8Array {
  if (str.length === 0) return new Uint8Array(0)

  // Build reverse lookup
  const alphabetMap = new Map<string, number>()
  for (let i = 0; i < BASE58_ALPHABET.length; i++) {
    alphabetMap.set(BASE58_ALPHABET[i], i)
  }

  // Count leading '1's (zeros in base58)
  let zeros = 0
  while (zeros < str.length && str[zeros] === '1') {
    zeros++
  }

  // Allocate enough space
  const size = Math.ceil(str.length * 733 / 1000) + 1
  const b256 = new Uint8Array(size)

  let length = 0
  for (let i = zeros; i < str.length; i++) {
    const value = alphabetMap.get(str[i])
    if (value === undefined) {
      throw new Error(`Invalid base58 character: ${str[i]}`)
    }

    let carry = value
    let j = 0

    for (let k = size - 1; (carry !== 0 || j < length) && k >= 0; k--, j++) {
      carry += 58 * b256[k]
      b256[k] = carry % 256
      carry = Math.floor(carry / 256)
    }

    length = j
  }

  // Skip leading zeros in result
  let it = size - length
  while (it < size && b256[it] === 0) {
    it++
  }

  // Build output with leading zeros
  const result = new Uint8Array(zeros + (size - it))
  // Leading zeros are already 0 in the Uint8Array
  result.set(b256.subarray(it), zeros)

  return result
}

// ============================================================================
// Base64 Helpers
// ============================================================================

/**
 * Encode Uint8Array to standard base64 string.
 */
export function base64Encode(data: Uint8Array): string {
  let binary = ''
  for (let i = 0; i < data.length; i++) {
    binary += String.fromCharCode(data[i])
  }
  return btoa(binary)
}

/**
 * Decode base64 string to Uint8Array.
 */
export function base64Decode(str: string): Uint8Array {
  const binary = atob(str)
  const data = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    data[i] = binary.charCodeAt(i)
  }
  return data
}

// ============================================================================
// DID <-> Public Key Conversion
// ============================================================================

const DID_PREFIX = 'did:agent:ed25519:'

/**
 * Convert a raw Ed25519 public key to a DID string.
 *
 * Format: did:agent:ed25519:{base58-encoded-32-byte-public-key}
 */
export function publicKeyToDID(publicKey: Uint8Array): string {
  return `${DID_PREFIX}${base58Encode(publicKey)}`
}

/**
 * Convert a DID string to a raw Ed25519 public key.
 *
 * @throws Error if the DID format is invalid
 */
export function didToPublicKey(did: string): Uint8Array {
  if (!did.startsWith(DID_PREFIX)) {
    throw new Error(`Invalid DID format: expected prefix "${DID_PREFIX}", got "${did.slice(0, 30)}"`)
  }

  const encoded = did.slice(DID_PREFIX.length)
  if (!encoded) {
    throw new Error('Invalid DID: empty public key')
  }

  const publicKey = base58Decode(encoded)
  if (publicKey.length !== 32) {
    throw new Error(`Invalid DID: expected 32-byte public key, got ${publicKey.length} bytes`)
  }

  return publicKey
}

/**
 * Validate a DID string format without decoding.
 */
export function isValidDID(did: string): boolean {
  if (!did.startsWith(DID_PREFIX)) return false
  const encoded = did.slice(DID_PREFIX.length)
  if (!encoded || encoded.length < 32 || encoded.length > 50) return false

  // Check all characters are valid base58
  for (const ch of encoded) {
    if (!BASE58_ALPHABET.includes(ch)) return false
  }

  return true
}

// ============================================================================
// PEM Encoding / Decoding
// ============================================================================

// OID for Ed25519: 1.3.101.112 -> DER: 06 03 2b 65 70
// SPKI wrapper for Ed25519 public key (32 bytes):
//   SEQUENCE { SEQUENCE { OID(ed25519) }, BIT STRING { 0x00, <32 bytes> } }
const SPKI_PREFIX = new Uint8Array([
  0x30, 0x2a, // SEQUENCE, 42 bytes
  0x30, 0x05, // SEQUENCE, 5 bytes
  0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (ed25519)
  0x03, 0x21, // BIT STRING, 33 bytes
  0x00, // no unused bits
])

/**
 * Convert a raw 32-byte Ed25519 public key to SPKI-format PEM.
 *
 * Produces a standard PEM file suitable for .pub files:
 * ```
 * -----BEGIN PUBLIC KEY-----
 * MCowBQYDK2VwAyEA<base64-encoded-key>
 * -----END PUBLIC KEY-----
 * ```
 */
export function publicKeyToPEM(publicKey: Uint8Array): string {
  if (publicKey.length !== 32) {
    throw new Error(`Expected 32-byte public key, got ${publicKey.length} bytes`)
  }

  // Build SPKI structure
  const spki = new Uint8Array(SPKI_PREFIX.length + 32)
  spki.set(SPKI_PREFIX, 0)
  spki.set(publicKey, SPKI_PREFIX.length)

  const b64 = base64Encode(spki)

  // Wrap at 64 characters per line
  const lines: string[] = []
  for (let i = 0; i < b64.length; i += 64) {
    lines.push(b64.slice(i, i + 64))
  }

  return `-----BEGIN PUBLIC KEY-----\n${lines.join('\n')}\n-----END PUBLIC KEY-----\n`
}

/**
 * Extract a raw 32-byte Ed25519 public key from a SPKI-format PEM string.
 *
 * @throws Error if the PEM is malformed or not an Ed25519 key
 */
export function pemToPublicKey(pem: string): Uint8Array {
  // Strip PEM headers and whitespace
  const b64 = pem
    .replace(/-----BEGIN PUBLIC KEY-----/, '')
    .replace(/-----END PUBLIC KEY-----/, '')
    .replace(/\s/g, '')

  if (!b64) {
    throw new Error('Empty PEM data')
  }

  const der = base64Decode(b64)

  // Validate SPKI structure
  if (der.length !== SPKI_PREFIX.length + 32) {
    throw new Error(`Invalid SPKI length: expected ${SPKI_PREFIX.length + 32}, got ${der.length}`)
  }

  // Verify the SPKI prefix matches Ed25519
  for (let i = 0; i < SPKI_PREFIX.length; i++) {
    if (der[i] !== SPKI_PREFIX[i]) {
      throw new Error('PEM does not contain an Ed25519 public key (SPKI prefix mismatch)')
    }
  }

  return der.slice(SPKI_PREFIX.length)
}

// ============================================================================
// Ed25519 Key Generation, Signing, Verification
// ============================================================================

/**
 * Generate a new Ed25519 keypair.
 *
 * Returns raw public/private key bytes and the DID identifier.
 * Uses the Web Crypto API (crypto.subtle) available in Cloudflare Workers.
 */
export async function generateKeypair(): Promise<{
  publicKey: Uint8Array
  privateKey: Uint8Array
  did: string
}> {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'Ed25519' },
    true, // extractable
    ['sign', 'verify'],
  ) as CryptoKeyPair

  // Export raw public key (32 bytes)
  const publicKeyBuffer = await crypto.subtle.exportKey('raw', keyPair.publicKey)
  const publicKey = new Uint8Array(publicKeyBuffer)

  // Export private key as PKCS#8, then extract the 32-byte seed
  const pkcs8Buffer = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey)
  const pkcs8 = new Uint8Array(pkcs8Buffer)

  // PKCS#8 for Ed25519 is:
  //   SEQUENCE { INTEGER(0), SEQUENCE { OID(ed25519) }, OCTET STRING { OCTET STRING { 32-byte-seed } } }
  // The 32-byte seed is at the end, wrapped in two OCTET STRING headers.
  // Total PKCS#8 length is 48 bytes: 16 bytes header + 32 bytes seed
  // The seed starts at offset 16 in the standard encoding.
  const privateKey = pkcs8.slice(pkcs8.length - 32)

  const did = publicKeyToDID(publicKey)

  return { publicKey, privateKey, did }
}

/**
 * Import an Ed25519 private key (32-byte seed) as a CryptoKey for signing.
 */
async function importPrivateKey(privateKey: Uint8Array): Promise<CryptoKey> {
  // Build PKCS#8 wrapper for the 32-byte seed
  const pkcs8 = new Uint8Array([
    0x30, 0x2e, // SEQUENCE, 46 bytes
    0x02, 0x01, 0x00, // INTEGER 0 (version)
    0x30, 0x05, // SEQUENCE, 5 bytes
    0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (ed25519)
    0x04, 0x22, // OCTET STRING, 34 bytes
    0x04, 0x20, // OCTET STRING, 32 bytes (the actual seed)
    ...privateKey,
  ])

  return crypto.subtle.importKey(
    'pkcs8',
    pkcs8,
    { name: 'Ed25519' },
    false,
    ['sign'],
  )
}

/**
 * Import an Ed25519 public key (32 bytes raw) as a CryptoKey for verification.
 */
async function importPublicKey(publicKey: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    publicKey,
    { name: 'Ed25519' },
    false,
    ['verify'],
  )
}

/**
 * Sign a message with an Ed25519 private key.
 *
 * @param message - The message bytes to sign
 * @param privateKey - The 32-byte Ed25519 private key (seed)
 * @returns The 64-byte Ed25519 signature
 */
export async function sign(message: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array> {
  if (privateKey.length !== 32) {
    throw new Error(`Expected 32-byte private key, got ${privateKey.length} bytes`)
  }

  const cryptoKey = await importPrivateKey(privateKey)
  const signature = await crypto.subtle.sign(
    { name: 'Ed25519' },
    cryptoKey,
    message,
  )

  return new Uint8Array(signature)
}

/**
 * Verify an Ed25519 signature.
 *
 * @param message - The original message bytes
 * @param signature - The 64-byte Ed25519 signature
 * @param publicKey - The 32-byte Ed25519 public key
 * @returns true if the signature is valid
 */
export async function verify(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array,
): Promise<boolean> {
  if (publicKey.length !== 32) {
    throw new Error(`Expected 32-byte public key, got ${publicKey.length} bytes`)
  }

  if (signature.length !== 64) {
    throw new Error(`Expected 64-byte signature, got ${signature.length} bytes`)
  }

  try {
    const cryptoKey = await importPublicKey(publicKey)
    return await crypto.subtle.verify(
      { name: 'Ed25519' },
      cryptoKey,
      signature,
      message,
    )
  } catch {
    return false
  }
}

// ============================================================================
// Request Signing / Verification Helpers
// ============================================================================

/**
 * Create a signed request payload.
 *
 * Signs the message string with the private key and returns a base64-encoded
 * signature suitable for HTTP headers or JSON payloads.
 *
 * @param message - The message string to sign (typically a request body or canonical request)
 * @param privateKey - The 32-byte Ed25519 private key
 * @returns Base64-encoded signature string
 */
export async function signMessage(message: string, privateKey: Uint8Array): Promise<string> {
  const messageBytes = new TextEncoder().encode(message)
  const signature = await sign(messageBytes, privateKey)
  return base64Encode(signature)
}

/**
 * Verify a signed request payload.
 *
 * @param message - The original message string
 * @param signatureBase64 - The base64-encoded signature
 * @param publicKey - The 32-byte Ed25519 public key
 * @returns true if the signature is valid
 */
export async function verifyMessage(
  message: string,
  signatureBase64: string,
  publicKey: Uint8Array,
): Promise<boolean> {
  try {
    const messageBytes = new TextEncoder().encode(message)
    const signature = base64Decode(signatureBase64)
    return await verify(messageBytes, signature, publicKey)
  } catch {
    return false
  }
}

/**
 * Verify a signed request using a DID.
 *
 * Combines DID resolution with signature verification.
 *
 * @param did - The DID of the signer (did:agent:ed25519:...)
 * @param message - The original message string
 * @param signatureBase64 - The base64-encoded signature
 * @returns true if the DID is valid and the signature verifies
 */
export async function verifyFromDID(
  did: string,
  message: string,
  signatureBase64: string,
): Promise<boolean> {
  try {
    const publicKey = didToPublicKey(did)
    return await verifyMessage(message, signatureBase64, publicKey)
  } catch {
    return false
  }
}
