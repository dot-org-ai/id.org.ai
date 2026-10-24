/**
 * Where a sign-in with a known email goes (OIDC `login_hint`): the one way that
 * address can sign in without a choice to make.
 *
 *   google     gmail.com / googlemail.com, or a domain whose mail is Google
 *              Workspace's (MX on google.com / googlemail.com): straight to
 *              Google, which preselects that account.
 *   microsoft  outlook.com / hotmail.com / live.com / msn.com, or a domain
 *              whose mail is Microsoft 365's (MX on
 *              mail.protection.outlook.com).
 *   email      anything else, or when the lookup fails: a 6-digit code to
 *              that address.
 *
 * Routing by the address rather than sending everyone to Google keeps the
 * account the person signs in with on that address: a relying party that
 * binds an invite to the invited email (pitch.startups.studio) refuses a
 * Google account under another address.
 *
 * The MX lookup is one DNS-over-HTTPS query, held in Cloudflare's cache and in
 * the isolate for an hour, and given up after 1.5 seconds.
 */

export type SignInRoute = 'google' | 'microsoft' | 'email'

type Fetch = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>

const GOOGLE_DOMAINS = new Set(['gmail.com', 'googlemail.com'])
const MICROSOFT_DOMAINS = new Set(['outlook.com', 'hotmail.com', 'live.com', 'msn.com'])
const DOH = 'https://cloudflare-dns.com/dns-query'
const CACHE_SECONDS = 3600
const LOOKUP_TIMEOUT_MS = 1500
const MAX_CACHED = 1000

const cache = new Map<string, { route: SignInRoute; until: number }>()

/** The route for an MX host set: Google's or Microsoft's mail, else none. */
export function routeForMx(hosts: string[]): SignInRoute | null {
  const names = hosts.map((h) => h.trim().toLowerCase().replace(/\.$/, ''))
  const on = (suffix: string) => names.some((h) => h === suffix || h.endsWith(`.${suffix}`))
  if (on('google.com') || on('googlemail.com')) return 'google'
  if (on('mail.protection.outlook.com')) return 'microsoft'
  return null
}

/** The MX hosts of a domain from a DoH JSON answer (`"10 aspmx.l.google.com."`). */
async function lookupMx(domain: string, fetcher: Fetch): Promise<string[]> {
  const url = `${DOH}?name=${encodeURIComponent(domain)}&type=MX`
  const res = await fetcher(url, {
    headers: { accept: 'application/dns-json' },
    signal: AbortSignal.timeout(LOOKUP_TIMEOUT_MS),
    // Cloudflare's cache: one lookup per domain per hour across isolates
    cf: { cacheTtl: CACHE_SECONDS, cacheEverything: true },
  } as RequestInit)
  if (!res.ok) return []
  const body = (await res.json()) as { Answer?: Array<{ type?: number; data?: string }> }
  return (body.Answer ?? []).filter((a) => a.type === 15 && typeof a.data === 'string').map((a) => a.data!.trim().split(/\s+/).pop() ?? '')
}

/** The sign-in route for an email address (see the module comment). */
export async function signInRouteFor(email: string, opts: { fetch?: Fetch; now?: number } = {}): Promise<SignInRoute> {
  const domain = email.trim().toLowerCase().split('@').pop() ?? ''
  if (!domain || !domain.includes('.')) return 'email'
  if (GOOGLE_DOMAINS.has(domain)) return 'google'
  if (MICROSOFT_DOMAINS.has(domain)) return 'microsoft'
  const now = opts.now ?? Date.now()
  const hit = cache.get(domain)
  if (hit && hit.until > now) return hit.route
  let route: SignInRoute = 'email'
  try {
    route = routeForMx(await lookupMx(domain, opts.fetch ?? ((i, o) => fetch(i, o)))) ?? 'email'
  } catch {
    // unreachable or slow DNS: the email code works for every address
    return 'email'
  }
  if (cache.size >= MAX_CACHED) cache.clear()
  cache.set(domain, { route, until: now + CACHE_SECONDS * 1000 })
  return route
}
