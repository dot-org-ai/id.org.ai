/**
 * Delegated authority for resource servers: RFC 8707 resource indicators and
 * the api.sb scopes.
 *
 * A token id.org.ai issues says who it is for (`resource`, the audience) and
 * what it lets the holder do there (`scope`). This module holds the rules both
 * the authorization endpoint and the token endpoint apply:
 *
 *   - `parseResourceIndicators` — RFC 8707 §2: a `resource` value is an
 *     absolute URI with no fragment. https only, except loopback http for
 *     local development. One distinct value per request (a token has one
 *     audience here).
 *   - `SB_SCOPES` — `sb:read` and `sb:do` (coined here). They delegate a
 *     Person's authority on api.sb to a client, so:
 *       · they are only ever granted for an api.sb resource (a request with
 *         no `resource` is bound to `https://api.sb`), so a token carrying
 *         them always says it is for api.sb;
 *       · they need a Person: never through client_credentials;
 *       · they are always shown on the consent screen, even to a first-party
 *         (trusted) client, and never through the device flow (its approval
 *         page shows no scopes).
 *
 * Nothing here changes the OIDC scopes (`openid profile email
 * offline_access`) or a request that carries neither a `resource` nor an sb
 * scope.
 */

/** The OIDC scopes every client may request (unchanged). */
export const OIDC_SCOPES = ['openid', 'profile', 'email', 'offline_access'] as const

/** Read api.sb as the Person: search and fetch. */
export const SB_SCOPE_READ = 'sb:read'
/** Act on api.sb as the Person: run Verbs that change their Startups. A step-up over `sb:read`. */
export const SB_SCOPE_DO = 'sb:do'
export const SB_SCOPES = [SB_SCOPE_READ, SB_SCOPE_DO] as const

/** Every scope the authorization server advertises in its metadata. */
export const SCOPES_SUPPORTED: string[] = [...OIDC_SCOPES, ...SB_SCOPES]

/** What the consent screen says each scope delegates. */
export const SCOPE_DESCRIPTIONS: Record<string, string> = {
  openid: 'Verify your identity',
  profile: 'View your name and profile picture',
  email: 'View your email address',
  offline_access: 'Access your data while you are offline',
  [SB_SCOPE_READ]: 'Read your Startups on api.sb (search and fetch)',
  [SB_SCOPE_DO]: 'Act for you on api.sb: run Verbs that change your Startups',
}

/** The api.sb resources (RFC 8707 audiences) the sb scopes may be granted for. */
export const SB_RESOURCES = ['https://api.sb', 'https://api.sb/mcp'] as const
/** The audience an sb-scoped request with no `resource` is bound to. */
export const DEFAULT_SB_RESOURCE = 'https://api.sb'

export function isSbScope(scope: string): boolean {
  return (SB_SCOPES as readonly string[]).includes(scope)
}

/** `sb:` at the start of a token or after a non-alphanumeric (so `usb:read` is not caught). */
const SB_LOOKALIKE = /(^|[^a-z0-9])sb:/i

/** RFC 6749 §3.3: scope-token = 1*( %x21 / %x23-5B / %x5D-7E ). */
const SCOPE_TOKEN = /^[\x21\x23-\x5B\x5D-\x7E]+$/

/**
 * Why a list of scope tokens is not acceptable, or null. Each token must fit
 * the RFC 6749 grammar (no tabs, newlines, quotes or backslashes), and any
 * token that mentions `sb:` in any case must be exactly `sb:read` or `sb:do`:
 * the sb names are reserved, so `SB:DO`, `sb:do,sb:read` or `x,sb:do` cannot
 * slip past a check for the exact scope and be read as it by a lax parser.
 */
export function scopeProblem(tokens: string[]): string | null {
  for (const t of tokens) {
    if (!SCOPE_TOKEN.test(t)) return `invalid scope token: ${JSON.stringify(t)}`
    if (SB_LOOKALIKE.test(t) && !isSbScope(t)) return `reserved scope name: ${t} (the sb scopes are exactly sb:read and sb:do)`
  }
  return null
}

/** True when a raw scope string asks for (or imitates) an sb scope. */
export function mentionsSbScope(scope: string | null | undefined): boolean {
  return typeof scope === 'string' && /sb:/i.test(scope)
}

/** Split a space-delimited scope string, dropping empty entries. */
export function splitScopes(scope: string): string[] {
  return scope.split(' ').filter(Boolean)
}

/**
 * Canonical spelling of a resource URI for comparison: lowercase scheme and
 * host, no trailing dot on the host, a single trailing slash trimmed from a
 * non-root path. Path case is kept (paths can be case-sensitive). Mirrors
 * worker/utils/mcp-resource.ts `canonicalizeResourceUri`.
 */
export function canonicalResource(uri: string): string {
  try {
    const u = new URL(uri)
    const path = u.pathname.length > 1 ? u.pathname.replace(/\/$/, '') : ''
    const host = u.hostname.toLowerCase().replace(/\.+$/, '') + (u.port ? `:${u.port}` : '')
    return `${u.protocol.toLowerCase()}//${host}${path}${u.search}`
  } catch {
    return uri.replace(/\/$/, '')
  }
}

export function sameResource(a: string, b: string): boolean {
  return canonicalResource(a) === canonicalResource(b)
}

export function isSbResource(resource: string): boolean {
  const c = canonicalResource(resource)
  return SB_RESOURCES.some((r) => canonicalResource(r) === c)
}

const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]'])

export type ResourceParse = { ok: true; resource?: string } | { ok: false; description: string }

/**
 * Validate the `resource` parameter(s) of an authorization or token request
 * (RFC 8707 §2). Returns the single resource (as sent), none, or why not.
 */
export function parseResourceIndicators(values: Array<string | null | undefined>): ResourceParse {
  const given = values.filter((v): v is string => typeof v === 'string' && v !== '')
  if (given.length === 0) return { ok: true }
  const distinct = new Map<string, string>()
  for (const v of given) {
    let u: URL
    try {
      u = new URL(v)
    } catch {
      return { ok: false, description: `resource is not an absolute URI: ${v}` }
    }
    if (u.hash || v.includes('#')) return { ok: false, description: 'resource must not contain a fragment' }
    if (u.username || u.password) return { ok: false, description: 'resource must not contain credentials' }
    if (u.protocol !== 'https:' && !(u.protocol === 'http:' && LOOPBACK.has(u.hostname))) {
      return { ok: false, description: 'resource must use https' }
    }
    distinct.set(canonicalResource(v), v)
  }
  if (distinct.size > 1) return { ok: false, description: 'only one resource per request is supported' }
  // An api.sb resource is stored (and reported as `aud`) exactly as listed in
  // SB_RESOURCES, so api.sb's exact `aud` check sees one spelling. Any other
  // resource is kept as the client sent it (as before), since a third-party
  // resource server may match its own spelling.
  const [canonical, asSent] = [...distinct.entries()][0]!
  const sb = SB_RESOURCES.find((r) => canonicalResource(r) === canonical)
  return { ok: true, resource: sb ?? asSent }
}

export type DelegationCheck =
  | { ok: true; scopes: string[]; resource?: string }
  | { ok: false; error: 'invalid_scope' | 'invalid_target'; description: string }

/**
 * Apply the sb-scope rules to an authorization request's scopes and resource:
 * an sb scope needs an api.sb resource, and an sb-scoped request with no
 * resource is bound to DEFAULT_SB_RESOURCE.
 */
export function bindSbScopes(scopes: string[], resource: string | undefined): DelegationCheck {
  if (!scopes.some(isSbScope)) return { ok: true, scopes, ...(resource !== undefined && { resource }) }
  if (resource === undefined) return { ok: true, scopes, resource: DEFAULT_SB_RESOURCE }
  if (!isSbResource(resource)) {
    return { ok: false, error: 'invalid_target', description: `sb scopes are only granted for api.sb (${SB_RESOURCES.join(' or ')}), not ${resource}` }
  }
  return { ok: true, scopes, resource }
}
