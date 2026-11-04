/**
 * Cookie utility functions for auth cookie parsing, building, and domain detection.
 * Supports chunked cookies for JWTs that exceed per-cookie size limits.
 */
import { canonicalHostname } from '../../src/sdk/csrf'
import { sharedZones } from './shared-zones'

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
// On an estate apex's sibling (auth.headless.ly, auth.startups.new) the
// cookie is set on the apex (Domain=.headless.ly) so the app there receives
// it. On a zone whose subdomains belong to different owners (the builder base
// zones, workers.do, workers.dev: worker/utils/shared-zones.ts) it never is:
// those are treated as public suffixes (security review H4). On localhost or
// an IP, Domain is omitted (exact host).

export function getRootDomain(rawHostname: string, extraSharedZones?: string | null): string | null {
  // Canonical spelling: `id.org.ai.` must not become Domain=.ai.
  const hostname = canonicalHostname(rawHostname)
  // An IP address (127.0.0.1 in local development, [::1]) has no parent domain.
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) || hostname.includes(':') || hostname.startsWith('[')) return null
  const parts = hostname.split('.')
  if (parts.length < 2) return null // localhost or single-part hostname
  const suffixes = sharedZones(extraSharedZones)
  if (suffixes.has(hostname)) return null // the shared zone itself (api.sb, svc.st)
  // The longest listed suffix wins: acme.hq.com.ai is under hq.com.ai, not com.ai.
  for (let i = 1; i < parts.length; i++) {
    if (!suffixes.has(parts.slice(i).join('.'))) continue
    // The host is the registrable domain itself (id.org.ai, acme.svc.st): host-only.
    if (i === 1) return null
    return '.' + parts.slice(i - 1).join('.') // sub.id.org.ai → .id.org.ai, auth.acme.svc.st → .acme.svc.st
  }
  // An unlisted parent: share with its subdomains, as before.
  return '.' + parts.slice(-2).join('.') // headless.ly → .headless.ly, auth.headless.ly → .headless.ly
}

/**
 * The Domain the cookie was set on before H4 (last two labels, `org.ai`-style
 * suffixes aside). Used only to clear a cookie a browser may still hold there.
 */
function legacyRootDomain(rawHostname: string): string | null {
  const hostname = canonicalHostname(rawHostname)
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) || hostname.includes(':') || hostname.startsWith('[')) return null
  const parts = hostname.split('.')
  if (parts.length < 2) return null
  const lastTwo = parts.slice(-2).join('.')
  if (['org.ai', 'co.uk', 'com.au', 'co.jp'].includes(lastTwo)) {
    if (parts.length <= 3) return null
    return '.' + parts.slice(-3).join('.')
  }
  return '.' + lastTwo
}

/**
 * Set-Cookie headers that put the session JWT on the request's host (see
 * getRootDomain), clearing first any copy an earlier release left on a wider
 * parent domain, which would otherwise shadow or outlive it.
 */
export function sessionCookieHeaders(requestUrl: string, jwt: string, opts: { maxAge: number; sharedZones?: string | null }): string[] {
  const url = new URL(requestUrl)
  const secure = url.protocol === 'https:'
  const domain = getRootDomain(url.hostname, opts.sharedZones)
  const legacy = legacyRootDomain(url.hostname)
  return [
    ...(legacy && legacy !== domain ? buildClearAuthCookieHeaders({ secure, domain: legacy }) : []),
    ...buildAuthCookieHeaders(jwt, { secure, domain, maxAge: opts.maxAge }),
  ]
}

/** Set-Cookie headers that clear the session cookie on the request's host, and on the pre-H4 parent domain. */
export function clearSessionCookieHeaders(requestUrl: string, opts: { sharedZones?: string | null } = {}): string[] {
  const url = new URL(requestUrl)
  const secure = url.protocol === 'https:'
  const domain = getRootDomain(url.hostname, opts.sharedZones)
  const legacy = legacyRootDomain(url.hostname)
  return [
    ...buildClearAuthCookieHeaders({ secure, domain }),
    ...(legacy && legacy !== domain ? buildClearAuthCookieHeaders({ secure, domain: legacy }) : []),
  ]
}
