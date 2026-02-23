/**
 * CSRF Protection for id.org.ai
 *
 * Implements the double-submit cookie pattern for protecting OAuth flows
 * and other state-mutating endpoints against cross-site request forgery.
 *
 * Pattern:
 *   1. Server generates a random CSRF token
 *   2. Token is set as a cookie AND embedded in the form/state parameter
 *   3. On submission, server verifies cookie value === form/query value
 *   4. Attacker cannot read the cookie (SameSite + HttpOnly), so cannot forge the match
 *
 * For OAuth flows, the CSRF token is embedded in the `state` parameter:
 *   state = base64url({ csrf: token, originalState: clientState })
 *
 * Tokens are stored in DO storage with a TTL (default 30 minutes).
 */

// ============================================================================
// Types
// ============================================================================

export interface CSRFToken {
  token: string
  createdAt: number
  expiresAt: number
}

export interface CSRFValidationResult {
  valid: boolean
  error?: string
}

// ============================================================================
// Constants
// ============================================================================

/** Default CSRF token TTL: 30 minutes */
const CSRF_TOKEN_TTL_MS = 30 * 60 * 1000

/** Cookie name for the CSRF token */
export const CSRF_COOKIE_NAME = '__csrf'

/** Maximum age for the CSRF cookie in seconds */
const CSRF_COOKIE_MAX_AGE = 1800 // 30 minutes

// ============================================================================
// Allowed Origins
// ============================================================================

/** Origins allowed for CORS and CSRF validation */
export const ALLOWED_ORIGIN_PATTERNS = [
  /^https?:\/\/([a-z0-9-]+\.)*headless\.ly$/,
  /^https?:\/\/([a-z0-9-]+\.)*org\.ai$/,
  /^https?:\/\/([a-z0-9-]+\.)*[a-z0-9-]+\.do$/,
  /^https?:\/\/localhost(:\d+)?$/,
  /^https?:\/\/127\.0\.0\.1(:\d+)?$/,
]

/**
 * Check if an origin is in the allowlist.
 */
export function isAllowedOrigin(origin: string): boolean {
  if (!origin) return false
  return ALLOWED_ORIGIN_PATTERNS.some((pattern) => pattern.test(origin))
}

/**
 * Check if a redirect URL is safe (prevents open redirect attacks).
 * Allows: relative paths (starting with `/`, not `//`) and absolute URLs on allowed origins.
 * Rejects: absolute URLs to unknown domains, protocol-relative URLs, javascript: URIs, data: URIs.
 */
export function isSafeRedirectUrl(url: string): boolean {
  if (!url) return false
  // Relative paths are safe (but reject protocol-relative `//evil.com`)
  if (url.startsWith('/') && !url.startsWith('//')) return true
  // Absolute URLs must be on an allowed origin
  try {
    const parsed = new URL(url)
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return false
    return isAllowedOrigin(parsed.origin)
  } catch {
    return false
  }
}

/**
 * Get the CORS origin to return for a request.
 * Returns the origin if allowed, or null if not.
 */
export function getCorsOrigin(request: Request): string | null {
  const origin = request.headers.get('origin')
  if (!origin) return null
  return isAllowedOrigin(origin) ? origin : null
}

// ============================================================================
// CSRF Token Generation & Validation
// ============================================================================

/**
 * Generate a cryptographically random CSRF token.
 */
export function generateCSRFToken(): string {
  const bytes = new Uint8Array(32)
  crypto.getRandomValues(bytes)
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

/**
 * Encode the CSRF token into an OAuth state parameter.
 * Preserves any original state the client sent.
 */
export function encodeStateWithCSRF(csrfToken: string, originalState?: string): string {
  const stateObj = {
    csrf: csrfToken,
    ...(originalState ? { s: originalState } : {}),
  }
  // Base64url encode the JSON
  const json = JSON.stringify(stateObj)
  return btoa(json).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

/**
 * Decode the CSRF token from an OAuth state parameter.
 * Returns the CSRF token and the original client state.
 */
export function decodeStateWithCSRF(state: string): { csrf: string; originalState?: string } | null {
  try {
    // Restore base64 padding
    const padded = state.replace(/-/g, '+').replace(/_/g, '/')
    const json = atob(padded)
    const obj = JSON.parse(json) as { csrf?: string; s?: string }
    if (!obj.csrf || typeof obj.csrf !== 'string') return null
    return {
      csrf: obj.csrf,
      originalState: obj.s,
    }
  } catch {
    return null
  }
}

/**
 * Build the Set-Cookie header for the CSRF token.
 */
export function buildCSRFCookie(token: string, secure = true): string {
  const parts = [
    `${CSRF_COOKIE_NAME}=${token}`,
    `Path=/`,
    `Max-Age=${CSRF_COOKIE_MAX_AGE}`,
    `SameSite=Lax`,
    `HttpOnly`,
  ]
  if (secure) {
    parts.push('Secure')
  }
  return parts.join('; ')
}

/**
 * Extract the CSRF token from the cookie header.
 */
export function extractCSRFFromCookie(request: Request): string | null {
  const cookieHeader = request.headers.get('cookie')
  if (!cookieHeader) return null

  const cookies = cookieHeader.split(';').map((c) => c.trim())
  for (const cookie of cookies) {
    const [name, ...rest] = cookie.split('=')
    if (name.trim() === CSRF_COOKIE_NAME) {
      return rest.join('=').trim()
    }
  }
  return null
}

// ============================================================================
// CSRF Validator (uses DO storage for server-side validation)
// ============================================================================

/**
 * CSRFProtection provides server-side CSRF token management.
 *
 * Usage:
 *   const csrf = new CSRFProtection(ctx.storage)
 *   const token = await csrf.generate()
 *   // ... set cookie and embed in form ...
 *   const result = csrf.validate(cookieToken, formToken)
 */
export class CSRFProtection {
  private storage: DurableObjectStorage

  constructor(storage: DurableObjectStorage) {
    this.storage = storage
  }

  /**
   * Generate a new CSRF token and store it in DO storage.
   * Returns the token string.
   */
  async generate(): Promise<string> {
    const token = generateCSRFToken()
    const now = Date.now()

    const data: CSRFToken = {
      token,
      createdAt: now,
      expiresAt: now + CSRF_TOKEN_TTL_MS,
    }

    await this.storage.put(`csrf:${token}`, data)
    return token
  }

  /**
   * Validate a CSRF token using the double-submit cookie pattern.
   *
   * Both the cookie value and the form/state value must:
   *   1. Be present and non-empty
   *   2. Match each other exactly
   *   3. Exist in server-side storage (not expired)
   *
   * The token is consumed (deleted) on successful validation to prevent replay.
   */
  async validate(cookieToken: string | null, formToken: string | null): Promise<CSRFValidationResult> {
    // Both must be present
    if (!cookieToken || !formToken) {
      return { valid: false, error: 'Missing CSRF token' }
    }

    // Must match (constant-time comparison)
    if (!timingSafeEqual(cookieToken, formToken)) {
      return { valid: false, error: 'CSRF token mismatch' }
    }

    // Check server-side storage
    const stored = await this.storage.get<CSRFToken>(`csrf:${cookieToken}`)
    if (!stored) {
      return { valid: false, error: 'Unknown CSRF token' }
    }

    // Check expiration
    if (Date.now() > stored.expiresAt) {
      await this.storage.delete(`csrf:${cookieToken}`)
      return { valid: false, error: 'CSRF token expired' }
    }

    // Consume the token (one-time use)
    await this.storage.delete(`csrf:${cookieToken}`)

    return { valid: true }
  }

  /**
   * Clean up expired CSRF tokens.
   * Call periodically (e.g. via alarm) to prevent storage bloat.
   */
  async cleanup(): Promise<number> {
    const entries = await this.storage.list<CSRFToken>({ prefix: 'csrf:' })
    const now = Date.now()
    const expired: string[] = []

    for (const [key, value] of entries) {
      if (value && value.expiresAt < now) {
        expired.push(key)
      }
    }

    if (expired.length > 0) {
      await this.storage.delete(expired)
    }

    return expired.length
  }
}

// ============================================================================
// Origin Validation Middleware
// ============================================================================

/**
 * Validate that POST/PUT/DELETE requests include a valid Origin header.
 * Returns an error response if the origin is not allowed, or null if OK.
 */
export function validateOrigin(request: Request): Response | null {
  const method = request.method.toUpperCase()

  // Only validate mutating methods
  if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') {
    return null
  }

  const origin = request.headers.get('origin')

  // Allow requests with no Origin header (same-origin, non-browser, curl, etc.)
  // The Referer header could also be checked but Origin is sufficient per OWASP
  if (!origin) {
    return null
  }

  if (!isAllowedOrigin(origin)) {
    return new Response(JSON.stringify({
      error: 'forbidden',
      message: 'Origin not allowed',
    }), {
      status: 403,
      headers: { 'Content-Type': 'application/json' },
    })
  }

  return null
}

// ============================================================================
// Timing-safe string comparison
// ============================================================================

/**
 * Constant-time string comparison to prevent timing attacks on CSRF tokens.
 */
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  let mismatch = 0
  for (let i = 0; i < a.length; i++) {
    mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i)
  }
  return mismatch === 0
}
