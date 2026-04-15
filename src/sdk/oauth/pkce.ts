/**
 * @dotdo/oauth - PKCE (Proof Key for Code Exchange) utilities
 *
 * OAuth 2.1 requires PKCE for all authorization code flows.
 * Only S256 is supported (plain is deprecated in OAuth 2.1).
 */

/**
 * Generate a cryptographically random code verifier
 *
 * Per RFC 7636, the verifier must be:
 * - Between 43 and 128 characters long
 * - Using only unreserved URI characters [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
 *
 * @param length - Length of the verifier (default: 64)
 * @returns Random code verifier string
 */
export function generateCodeVerifier(length: number = 64): string {
  if (length < 43 || length > 128) {
    throw new Error('Code verifier length must be between 43 and 128 characters')
  }

  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~'
  // Use rejection sampling to avoid modulo bias
  // For 66 chars, maxValid = 256 - (256 % 66) = 256 - 58 = 198
  const maxValid = 256 - (256 % chars.length)

  let verifier = ''
  for (let i = 0; i < length; i++) {
    let value: number
    do {
      value = crypto.getRandomValues(new Uint8Array(1))[0]!
    } while (value >= maxValid)
    verifier += chars[value % chars.length]
  }

  return verifier
}

/**
 * Generate a code challenge from a code verifier using S256 method
 *
 * S256: BASE64URL(SHA256(code_verifier))
 *
 * @param verifier - The code verifier
 * @returns Base64URL-encoded SHA-256 hash of the verifier
 */
export async function generateCodeChallenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder()
  const data = encoder.encode(verifier)
  const hashBuffer = await crypto.subtle.digest('SHA-256', data)
  return base64UrlEncode(hashBuffer)
}

/**
 * Verify a code verifier against a code challenge
 *
 * @param verifier - The code verifier from the token request
 * @param challenge - The code challenge from the authorization request
 * @param method - The challenge method (must be 'S256' for OAuth 2.1)
 * @returns True if the verifier matches the challenge
 */
export async function verifyCodeChallenge(
  verifier: string,
  challenge: string,
  method: string = 'S256'
): Promise<boolean> {
  if (method !== 'S256') {
    // OAuth 2.1 only supports S256
    return false
  }

  const expectedChallenge = await generateCodeChallenge(verifier)
  return await constantTimeEqual(expectedChallenge, challenge)
}

/**
 * Generate a PKCE pair (verifier and challenge)
 *
 * @param length - Length of the verifier (default: 64)
 * @returns Object with verifier and challenge
 */
export async function generatePkce(length: number = 64): Promise<{ verifier: string; challenge: string }> {
  const verifier = generateCodeVerifier(length)
  const challenge = await generateCodeChallenge(verifier)
  return { verifier, challenge }
}

/**
 * Base64URL encode an ArrayBuffer
 *
 * @param buffer - The buffer to encode
 * @returns Base64URL-encoded string (no padding)
 */
export function base64UrlEncode(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer)
  let binary = ''
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]!)
  }
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
}

/**
 * Base64URL decode a string to ArrayBuffer
 *
 * @param str - Base64URL-encoded string
 * @returns Decoded ArrayBuffer
 */
export function base64UrlDecode(str: string): ArrayBuffer {
  // Add padding if needed
  const padded = str + '='.repeat((4 - (str.length % 4)) % 4)
  // Convert from base64url to base64
  const base64 = padded.replace(/-/g, '+').replace(/_/g, '/')
  const binary = atob(base64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes.buffer
}

/**
 * Constant-time string comparison to prevent timing attacks
 *
 * Uses hash-based comparison to ensure constant-time behavior regardless of
 * string lengths. Both strings are hashed with SHA-256 before comparison,
 * which produces fixed-length outputs and prevents length-based timing leaks.
 *
 * @param a - First string
 * @param b - Second string
 * @returns True if strings are equal
 */
export async function constantTimeEqual(a: string, b: string): Promise<boolean> {
  const encoder = new TextEncoder()

  // Hash both strings to get fixed-length byte arrays
  // This prevents any timing information from leaking based on string length
  const [hashA, hashB] = await Promise.all([
    crypto.subtle.digest('SHA-256', encoder.encode(a)),
    crypto.subtle.digest('SHA-256', encoder.encode(b))
  ])

  const bytesA = new Uint8Array(hashA)
  const bytesB = new Uint8Array(hashB)

  // Both arrays are always 32 bytes (SHA-256 output)
  // Compare all bytes using XOR - result is 0 only if all bytes match
  let result = 0
  for (let i = 0; i < 32; i++) {
    result |= bytesA[i]! ^ bytesB[i]!
  }

  return result === 0
}

/** Alphanumeric characters for token/state generation */
const ALPHANUMERIC_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'

/**
 * Generate a cryptographically random string from a given charset
 * Uses rejection sampling to avoid modulo bias.
 *
 * @param length - Length of the string
 * @param charset - Characters to use for generation
 * @returns Random string
 */
function generateRandomString(length: number, charset: string): string {
  // Use rejection sampling to avoid modulo bias
  const maxValid = 256 - (256 % charset.length)

  let result = ''
  for (let i = 0; i < length; i++) {
    let value: number
    do {
      value = crypto.getRandomValues(new Uint8Array(1))[0]!
    } while (value >= maxValid)
    result += charset[value % charset.length]
  }

  return result
}

/**
 * Generate a random state parameter for CSRF protection
 *
 * @param length - Length of the state (default: 32)
 * @returns Random state string
 */
export function generateState(length: number = 32): string {
  return generateRandomString(length, ALPHANUMERIC_CHARS)
}

/**
 * Generate a random token (for access tokens, refresh tokens, etc.)
 *
 * @param length - Length of the token (default: 32)
 * @returns Random token string
 */
export function generateToken(length: number = 32): string {
  return generateRandomString(length, ALPHANUMERIC_CHARS)
}

/**
 * Generate a unique authorization code
 *
 * @returns Random authorization code
 */
export function generateAuthorizationCode(): string {
  return generateToken(48)
}

/**
 * Hash a client secret for storage
 *
 * @param secret - The client secret to hash
 * @returns SHA-256 hash of the secret
 */
export async function hashClientSecret(secret: string): Promise<string> {
  const encoder = new TextEncoder()
  const data = encoder.encode(secret)
  const hashBuffer = await crypto.subtle.digest('SHA-256', data)
  return base64UrlEncode(hashBuffer)
}

/**
 * Verify a client secret against a hash
 *
 * @param secret - The client secret to verify
 * @param hash - The stored hash
 * @returns True if the secret matches the hash
 */
export async function verifyClientSecret(secret: string, hash: string): Promise<boolean> {
  const expectedHash = await hashClientSecret(secret)
  return await constantTimeEqual(expectedHash, hash)
}
