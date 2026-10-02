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
  /^https?:\/\/([a-z0-9-]+\.)*auto\.dev$/,
  /^https?:\/\/localhost(:\d+)?$/,
  /^https?:\/\/127\.0\.0\.1(:\d+)?$/,
]

// ============================================================================
// Hostname canonicalisation
// ============================================================================

/**
 * The canonical spelling of a hostname for trust and redirect decisions:
 * lowercase, with any trailing dot removed. `id.org.ai.` (the fully-qualified
 * spelling) and `ID.org.AI` name the same host as `id.org.ai`, and Cloudflare
 * routes public traffic on the trailing-dot name to this worker with the dot
 * still in `request.url`. Every comparison of a host against a list must go
 * through this, so no spelling of a name is treated differently from another.
 */
export function canonicalHostname(hostname: string): string {
  return hostname.toLowerCase().replace(/\.+$/, '')
}

/**
 * The canonical origin (`scheme://host[:port]`) of a URL or origin string,
 * with the host through `canonicalHostname`; null when it does not parse or
 * has no host.
 */
export function canonicalOrigin(urlOrOrigin: string): string | null {
  let u: URL
  try {
    u = new URL(urlOrOrigin)
  } catch {
    return null
  }
  if (!u.hostname) return null
  const host = canonicalHostname(u.hostname)
  if (!host) return null
  return `${u.protocol}//${host}${u.port ? `:${u.port}` : ''}`
}

/**
 * The canonical origin of the request being served: what trust and redirect
 * decisions (login state, cross-origin bounce, continue policy, audiences,
 * advertised issuers) use in place of `new URL(request.url).origin`, which
 * keeps a trailing dot.
 */
export function requestOriginOf(requestUrl: string): string {
  return canonicalOrigin(requestUrl) ?? new URL(requestUrl).origin
}

/**
 * Check if an origin is in the allowlist. The origin is compared in its
 * canonical spelling (lowercase host, no trailing dot).
 */
export function isAllowedOrigin(origin: string): boolean {
  // An Origin is scheme://host[:port] and nothing else: no path, query,
  // fragment or userinfo may ride along into the comparison.
  if (!origin || !/^[a-z][a-z0-9+.-]*:\/\/[^/?#@\s\\]+$/i.test(origin)) return false
  const canonical = canonicalOrigin(origin)
  if (!canonical) return false
  return ALLOWED_ORIGIN_PATTERNS.some((pattern) => pattern.test(canonical))
}

/**
 * Syntactic redirect check (prevents script injection via redirects).
 * Allows: relative paths and absolute http(s) URLs.
 * Rejects: protocol-relative URLs (//evil.com, /\evil.com), javascript: and
 * data: URIs, and anything carrying tab/CR/LF.
 *
 * This is NOT an allowlist: it does not stop an open redirect to an arbitrary
 * https: host. `/login?continue=` goes through the destination policy in
 * worker/utils/relying-parties.ts (`resolveContinue`) on top of this check.
 */
export function isSafeRedirectUrl(url: string): boolean {
  if (!url) return false
  // Browsers strip tab/CR/LF from URLs, so `/\t/evil.com` would become `//evil.com`.
  if (/[\t\n\r]/.test(url)) return false
  // Relative paths are safe, but not protocol-relative `//evil.com` or
  // `/\evil.com` (which browsers normalise to `//evil.com`).
  if (url.startsWith('/')) return url[1] !== '/' && url[1] !== '\\'
  // Absolute URLs: only allow http(s)
  try {
    const parsed = new URL(url)
    return parsed.protocol === 'https:' || parsed.protocol === 'http:'
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

import type { StorageAdapter } from '../storage'
import { constantTimeEqual } from '../oauth/pkce'

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
  private storage: StorageAdapter

  constructor(storage: StorageAdapter) {
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
    if (!(await constantTimeEqual(cookieToken, formToken))) {
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
      await Promise.all(expired.map(key => this.storage.delete(key)))
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

  // Pages served with Referrer-Policy: no-referrer (every auth page,
  // security.md) make the browser send `Origin: null` on their own form posts.
  // Sec-Fetch-Site is set by the browser alone (no page can), so null is
  // accepted only when it says the post came from this site.
  if (origin === 'null' && request.headers.get('sec-fetch-site') === 'same-origin') {
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

