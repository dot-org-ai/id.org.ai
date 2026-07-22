/**
 * SSRF guard for outbound, caller-influenced fetches.
 *
 * The AAP host+jwt / ID-JAG / SET verifiers may fetch a JWKS from a URL the
 * caller advertises (a host's `jwks_uri`, an assertion's `iss`-derived JWKS).
 * A caller-controlled fetch target is an SSRF vector: it must be an absolute
 * https URL on a publicly-routable host — never http, never a private /
 * loopback / link-local / carrier-NAT / cloud-metadata address. The fetch is
 * additionally bounded (timeout + max body) and refuses redirects, so a public
 * URL cannot 30x-bounce onto a private host after the check.
 *
 * This mirrors the same posture api.qa applies to metadata-derived probes
 * (isPubliclyRoutableSameOrigin): the hostile URL is refused BEFORE any socket
 * is opened.
 */

/** True when `host` is a private / loopback / link-local / metadata address. */
export function isPrivateHost(host: string): boolean {
  const h = host.toLowerCase().replace(/^\[/, '').replace(/\]$/, '')
  if (h.length === 0) return true

  // Names that never resolve to a public host.
  if (h === 'localhost' || h.endsWith('.localhost')) return true
  if (h.endsWith('.local') || h.endsWith('.internal') || h.endsWith('.home.arpa')) return true

  // IPv6 loopback / unspecified / link-local (fe80::/10) / unique-local (fc00::/7).
  if (h === '::1' || h === '::') return true
  if (/^fe[89ab][0-9a-f]:/i.test(h)) return true
  if (/^f[cd][0-9a-f]{2}:/i.test(h)) return true
  // IPv4-mapped IPv6 (::ffff:a.b.c.d) — evaluate the embedded v4 below.
  const mapped = h.match(/^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i)
  const v4 = mapped ? mapped[1]! : h

  const m = v4.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/)
  if (m) {
    const a = Number(m[1])
    const b = Number(m[2])
    if ([a, b, Number(m[3]), Number(m[4])].some((o) => o > 255)) return true
    if (a === 0) return true // 0.0.0.0/8 "this host"
    if (a === 10) return true // private
    if (a === 127) return true // loopback
    if (a === 169 && b === 254) return true // link-local incl. 169.254.169.254 metadata
    if (a === 172 && b >= 16 && b <= 31) return true // private
    if (a === 192 && b === 168) return true // private
    if (a === 100 && b >= 64 && b <= 127) return true // carrier-grade NAT (RFC 6598)
    if (a >= 224) return true // multicast / reserved / broadcast
  }
  return false
}

/**
 * Validate a caller-supplied fetch target. Throws (fail-closed) unless it is an
 * absolute https URL on a publicly-routable host. Returns the parsed URL.
 */
export function assertPublicHttpsUrl(raw: unknown): URL {
  if (typeof raw !== 'string' || raw.trim().length === 0) {
    throw new Error('URL is missing or not a string')
  }
  let url: URL
  try {
    url = new URL(raw)
  } catch {
    throw new Error('URL is not a valid absolute URL')
  }
  if (url.protocol !== 'https:') {
    throw new Error('Only https URLs may be fetched (SSRF guard)')
  }
  if (isPrivateHost(url.hostname)) {
    throw new Error('Refusing to fetch a private/loopback/link-local/metadata host (SSRF guard)')
  }
  return url
}

export interface SafeFetchJsonOptions {
  /** Abort the fetch after this many ms (default 3000). */
  timeoutMs?: number
  /** Reject bodies larger than this many bytes (default 256 KiB). */
  maxBytes?: number
}

/**
 * SSRF-safe JSON GET: validates the URL is public https, bounds the request
 * with a timeout + max-body cap, and refuses redirects (so a public URL cannot
 * bounce onto a private host). Throws on any failure — callers fail closed.
 */
export async function safeFetchJson(raw: unknown, opts: SafeFetchJsonOptions = {}): Promise<unknown> {
  const url = assertPublicHttpsUrl(raw)
  const { timeoutMs = 3000, maxBytes = 256 * 1024 } = opts
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  try {
    const res = await fetch(url.toString(), {
      method: 'GET',
      // `manual` returns the 3xx response verbatim instead of following it, so a
      // public URL cannot 30x-bounce onto a private host. workerd does not
      // implement `redirect: 'error'`, so we reject the redirect explicitly.
      redirect: 'manual',
      signal: controller.signal,
      headers: { accept: 'application/json' },
    })
    if (res.status >= 300 && res.status < 400) {
      throw new Error(`refusing to follow a redirect (HTTP ${res.status}) — SSRF guard`)
    }
    if (!res.ok) throw new Error(`fetch failed: HTTP ${res.status}`)
    const text = await res.text()
    if (text.length > maxBytes) throw new Error('response body exceeds size cap')
    return JSON.parse(text)
  } finally {
    clearTimeout(timer)
  }
}
