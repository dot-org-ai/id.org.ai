/**
 * Cookie utility functions for auth cookie parsing, building, and domain detection.
 * Supports chunked cookies for JWTs that exceed per-cookie size limits.
 */

// ── Cookie Parsing ──────────────────────────────────────────────────────
// Simple cookie parser for extracting auth tokens from cookie headers.
// Supports chunked cookies: if `auth` is not found, tries `auth.0` + `auth.1` + ...
// Used by authenticate() when called with a raw cookie header string.

export function parseCookieValue(cookieHeader: string, name: string): string | null {
  // Try single cookie first
  const match = cookieHeader.match(new RegExp(`(?:^|;\\s*)${name}=([^;]*)`))
  if (match) return decodeURIComponent(match[1])

  // Try chunked cookies (name.0, name.1, ...)
  let result = ''
  for (let i = 0; ; i++) {
    const chunk = cookieHeader.match(new RegExp(`(?:^|;\\s*)${name}\\.${i}=([^;]*)`))
    if (!chunk) break
    result += decodeURIComponent(chunk[1])
  }
  return result || null
}

/** Max bytes per cookie value (leave room for name + flags, ~200 bytes overhead) */
const COOKIE_CHUNK_SIZE = 3800

/**
 * Build Set-Cookie headers for a JWT value. If the JWT exceeds COOKIE_CHUNK_SIZE,
 * splits into chunked cookies (auth.0, auth.1, ...) with a auth.count marker.
 * Otherwise sets a single `auth` cookie.
 */
export function buildAuthCookieHeaders(jwt: string, opts: { secure: boolean; domain: string | null; maxAge: number }): string[] {
  const flags = [
    'HttpOnly',
    'Path=/',
    'SameSite=Lax',
    `Max-Age=${opts.maxAge}`,
    ...(opts.secure ? ['Secure'] : []),
    ...(opts.domain ? [`Domain=${opts.domain}`] : []),
  ]
  const flagStr = flags.join('; ')

  if (jwt.length <= COOKIE_CHUNK_SIZE) {
    return [`auth=${jwt}; ${flagStr}`]
  }

  // Split into chunks
  const cookies: string[] = []
  const chunks = Math.ceil(jwt.length / COOKIE_CHUNK_SIZE)
  for (let i = 0; i < chunks; i++) {
    const chunk = jwt.slice(i * COOKIE_CHUNK_SIZE, (i + 1) * COOKIE_CHUNK_SIZE)
    cookies.push(`auth.${i}=${chunk}; ${flagStr}`)
  }
  // Marker so readers know how many chunks to expect
  cookies.push(`auth.count=${chunks}; ${flagStr}`)
  return cookies
}

/**
 * Build Set-Cookie headers to clear auth cookies (single + chunked).
 */
export function buildClearAuthCookieHeaders(opts: { secure: boolean; domain: string | null }): string[] {
  const flags = ['HttpOnly', 'Path=/', 'SameSite=Lax', 'Max-Age=0', ...(opts.secure ? ['Secure'] : []), ...(opts.domain ? [`Domain=${opts.domain}`] : [])]
  const flagStr = flags.join('; ')
  // Clear both the single cookie and up to 10 potential chunks
  const cookies = [`auth=; ${flagStr}`]
  for (let i = 0; i < 10; i++) {
    cookies.push(`auth.${i}=; ${flagStr}`)
  }
  cookies.push(`auth.count=; ${flagStr}`)
  return cookies
}

// ── Cookie Domain Detection ──────────────────────────────────────────────
// When running on a subdomain (e.g. id.headless.ly), set Domain=.headless.ly
// so the auth cookie is shared across all subdomains. On root domains or
// localhost, omit Domain to use the default (exact host).

export function getRootDomain(hostname: string): string | null {
  // Known public suffixes that should not be used as cookie domains
  const publicSuffixes = ['org.ai', 'co.uk', 'com.au', 'co.jp']
  const parts = hostname.split('.')
  if (parts.length < 2) return null // localhost or single-part hostname
  const lastTwo = parts.slice(-2).join('.')
  // Check if the last two parts form a public suffix (e.g. org.ai)
  if (publicSuffixes.includes(lastTwo)) {
    if (parts.length <= 3) return null // id.org.ai is already the root — can't set domain on public suffix
    return '.' + parts.slice(-3).join('.') // sub.id.org.ai → .id.org.ai
  }
  // For regular two-part domains (headless.ly), set Domain so subdomains share the cookie.
  // For three+ part domains (dashboard.headless.ly), extract the root.
  return '.' + lastTwo // headless.ly → .headless.ly, dashboard.headless.ly → .headless.ly
}

// ── Login nonce cookie (browser binding for the login ceremony) ─────────
// Set by /login on the host that served it, required by /callback on that same
// host. `__Host-` makes it host-only (no Domain, Path=/, Secure), so a sibling
// subdomain cannot plant or read it. Plain-http dev hosts cannot use the
// `__Host-` prefix, so they fall back to an unprefixed host-only cookie.

export const LOGIN_NONCE_COOKIE = '__Host-auth_nonce'
const LOGIN_NONCE_COOKIE_INSECURE = 'auth_nonce'

function loginNonceCookieName(secure: boolean): string {
  return secure ? LOGIN_NONCE_COOKIE : LOGIN_NONCE_COOKIE_INSECURE
}

export function buildLoginNonceCookie(nonce: string, opts: { secure: boolean; maxAge: number }): string {
  return `${loginNonceCookieName(opts.secure)}=${nonce}; HttpOnly; Path=/; SameSite=Lax; Max-Age=${opts.maxAge}${opts.secure ? '; Secure' : ''}`
}

export function buildClearLoginNonceCookie(opts: { secure: boolean }): string {
  return buildLoginNonceCookie('', { secure: opts.secure, maxAge: 0 })
}

export function readLoginNonce(cookieHeader: string, secure: boolean): string | null {
  const match = cookieHeader.match(new RegExp(`(?:^|;\\s*)${loginNonceCookieName(secure)}=([^;]*)`))
  return match && match[1] ? decodeURIComponent(match[1]) : null
}
