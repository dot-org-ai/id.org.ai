/**
 * Relying-party helpers: where a sign-in may send the browser afterwards, and
 * who is calling.
 *
 * `/login?continue=` (and POST /api/magic-link's `continue`) used to accept any
 * http(s) URL: an open redirect on the estate's identity provider. The policy
 * here accepts only
 *
 *   1. a relative path on the host that served the request;
 *   2. id.org.ai's own origins, and the origin that served the request;
 *   3. the trusted-account domains (ADR-0007, TRUSTED_ACCOUNT_DOMAINS) and the
 *      hosts named by LOGIN_CONTINUE_HOSTS (config; `*.` suffix entries);
 *   4. the origin of a registered OAuth client's redirect_uri.
 *
 * Anything else is refused and the caller falls back to a safe default.
 *
 * Every host is compared in its canonical spelling (lowercase, no trailing
 * dot; canonicalHostname): Cloudflare serves public traffic on `id.org.ai.`
 * as well as `id.org.ai`, with the dot kept in request.url, so no decision
 * here may treat one spelling of a name differently from another. No trust is
 * ever inferred from the host a request arrived on: callers inside the
 * account use the AuthService RPC entrypoint (worker/index.ts), which a public
 * request cannot reach.
 *
 * Registration (RFC 7591) is open, so (4) is only as strong as registration:
 * whoever registers a client can already have /oauth/authorize redirect to its
 * redirect_uri (error redirects need no consent). This policy adds no target an
 * OAuth client could not already reach; it removes every target nobody
 * registered.
 */
import type { Env } from '../types'
import { getStubForIdentity } from '../middleware/tenant'
import { isSafeRedirectUrl, canonicalHostname, canonicalOrigin, requestOriginOf } from '../../src/sdk/csrf'
import { parseTrustedAccountDomains } from '../routes/oauth'
import { withHashedSecret } from '../../src/sdk/oauth/client-secret'

/** The public origins this worker serves (worker/wrangler.jsonc routes + workers.dev). */
export const OWN_ORIGINS: readonly string[] = [
  'https://id.org.ai',
  'https://auth.org.ai',
  'https://oauth.do',
  'https://auth.headless.ly',
  'https://oauth.dotdo.workers.dev',
]

export { canonicalHostname, canonicalOrigin, requestOriginOf }

type StorageOp = (op: {
  op: 'get' | 'put' | 'delete' | 'list'
  key?: string
  value?: unknown
  options?: { prefix?: string; limit?: number }
}) => Promise<Record<string, unknown>>

function oauthStorage(env: Env): StorageOp {
  const stub = getStubForIdentity(env, 'oauth')
  return (op) => stub.oauthStorageOp(op)
}

const ORIGIN_INDEX_PREFIX = 'rp-origin:'
const ORIGIN_INDEX_MARKER = 'rp-origin-index:v1'
const MAX_CLIENTS_PER_ORIGIN = 20

function originOf(url: string): string | null {
  try {
    const u = new URL(url)
    if (u.protocol !== 'https:' && u.protocol !== 'http:') return null
    return canonicalOrigin(u.href)
  } catch {
    return null
  }
}

/** Record the origins of a client's redirect_uris so `/login?continue=` can accept them. */
export async function indexClientOrigins(env: Env, clientId: string, redirectUris: readonly string[]): Promise<void> {
  const storage = oauthStorage(env)
  const origins = new Set(redirectUris.map(originOf).filter((o): o is string => !!o))
  for (const origin of origins) {
    const key = `${ORIGIN_INDEX_PREFIX}${origin}`
    const existing = (await storage({ op: 'get', key })).value as { clientIds?: string[] } | undefined
    const clientIds = existing?.clientIds ?? []
    if (clientIds.includes(clientId)) continue
    await storage({
      op: 'put',
      key,
      value: { clientIds: [...clientIds, clientId].slice(-MAX_CLIENTS_PER_ORIGIN), updatedAt: Date.now() },
    })
  }
}

/**
 * One-time backfill of the origin index from every stored client, for clients
 * registered before the index existed. Runs at most once (guarded by a marker),
 * so a stream of refused continues cannot turn into repeated full scans.
 */
async function backfillOriginIndex(env: Env): Promise<void> {
  const storage = oauthStorage(env)
  const marker = (await storage({ op: 'get', key: ORIGIN_INDEX_MARKER })).value
  if (marker) return
  await storage({ op: 'put', key: ORIGIN_INDEX_MARKER, value: { startedAt: Date.now() } })
  const listed = (await storage({ op: 'list', options: { prefix: 'client:' } })).entries as Array<[string, unknown]> | undefined
  const byOrigin = new Map<string, string[]>()
  for (const [, value] of listed ?? []) {
    const client = value as { id?: string; redirectUris?: string[] } | undefined
    if (!client?.id || !Array.isArray(client.redirectUris)) continue
    for (const uri of client.redirectUris) {
      const origin = originOf(uri)
      if (!origin) continue
      const ids = byOrigin.get(origin) ?? []
      if (!ids.includes(client.id)) ids.push(client.id)
      byOrigin.set(origin, ids)
    }
  }
  for (const [origin, ids] of byOrigin) {
    const key = `${ORIGIN_INDEX_PREFIX}${origin}`
    const existing = (await storage({ op: 'get', key })).value as { clientIds?: string[] } | undefined
    const merged = Array.from(new Set([...(existing?.clientIds ?? []), ...ids])).slice(-MAX_CLIENTS_PER_ORIGIN)
    await storage({ op: 'put', key, value: { clientIds: merged, updatedAt: Date.now() } })
  }
  await storage({ op: 'put', key: ORIGIN_INDEX_MARKER, value: { completedAt: Date.now(), origins: byOrigin.size } })
}

/** Is `origin` the origin of some registered client's redirect_uri? */
export async function isRegisteredClientOrigin(env: Env, origin: string): Promise<boolean> {
  const storage = oauthStorage(env)
  const key = `${ORIGIN_INDEX_PREFIX}${origin}`
  if ((await storage({ op: 'get', key })).value) return true
  await backfillOriginIndex(env)
  return !!(await storage({ op: 'get', key })).value
}

/**
 * Parse LOGIN_CONTINUE_HOSTS: bare hostnames, or `*.suffix` for any subdomain
 * of `suffix` (never `suffix` itself, and never a bare `*`). Entries with a
 * scheme, port, path or space are dropped rather than widening the policy.
 */
export function parseContinueHosts(value: string | undefined): { exact: Set<string>; suffixes: string[] } {
  const exact = new Set<string>()
  const suffixes: string[] = []
  for (const raw of (value ?? '').split(',')) {
    const entry = canonicalHostname(raw.trim())
    if (!entry || /[/:\s@]/.test(entry)) continue
    if (entry.startsWith('*.')) {
      const suffix = entry.slice(2)
      // A suffix must itself be a multi-label name: `*.dev` or `*.` would open a TLD.
      if (suffix.split('.').filter(Boolean).length >= 2 && !suffix.includes('*')) suffixes.push(`.${suffix}`)
      continue
    }
    if (!entry.includes('*')) exact.add(entry)
  }
  return { exact, suffixes }
}

/** Is `hostname` named by LOGIN_CONTINUE_HOSTS? */
export function isListedContinueHost(env: Env, hostname: string): boolean {
  const { exact, suffixes } = parseContinueHosts(env.LOGIN_CONTINUE_HOSTS)
  const host = canonicalHostname(hostname)
  return exact.has(host) || suffixes.some((s) => host.endsWith(s))
}

/** `report` only when explicitly configured; anything else enforces. */
export function continuePolicy(env: Env): 'enforce' | 'report' {
  return (env.LOGIN_CONTINUE_POLICY ?? '').trim().toLowerCase() === 'report' ? 'report' : 'enforce'
}

/**
 * The policy for a browser-facing redirect parameter (`/login?continue=`,
 * `/logout?return_url=`): `resolveContinue`, then, under
 * LOGIN_CONTINUE_POLICY=report, a target the policy refused but which passes
 * the syntactic check is still followed and reported as `unlisted`. The
 * caller logs `host` (never the full URL) under its own event name.
 */
export async function resolveBrowserRedirect(
  env: Env,
  raw: string | null | undefined,
  opts: { requestOrigin: string; clientId?: string },
): Promise<{ url: string | null; outcome: 'none' | 'accepted' | 'unlisted' | 'refused'; host?: string }> {
  if (!raw) return { url: null, outcome: 'none' }
  const accepted = await resolveContinue(env, raw, opts)
  if (accepted) return { url: accepted, outcome: 'accepted' }
  const host = hostForLog(raw)
  if (continuePolicy(env) === 'report' && raw.length <= 4096 && isSafeRedirectUrl(raw)) {
    return { url: raw, outcome: 'unlisted', host }
  }
  return { url: null, outcome: 'refused', host }
}

/** The host of a redirect target, for logs (never the full URL). */
export function hostForLog(url: string): string {
  try {
    return new URL(url, 'https://id.org.ai').host
  } catch {
    return 'unparseable'
  }
}

/** A registered client's record, or null. */
export async function getRegisteredClient(
  env: Env,
  clientId: string,
): Promise<{ id: string; secret?: string; secretHash?: string; redirectUris: string[]; tokenEndpointAuthMethod?: string; name?: string } | null> {
  if (!clientId) return null
  const value = (await oauthStorage(env)({ op: 'get', key: `client:${clientId}` })).value as
    | { id: string; secret?: string; secretHash?: string; redirectUris?: string[]; tokenEndpointAuthMethod?: string; name?: string }
    | undefined
  if (!value?.id) return null
  return { ...value, redirectUris: Array.isArray(value.redirectUris) ? value.redirectUris : [] }
}

/** Rewrite a client record's legacy plaintext secret as its hash (B13.5). */
export async function rehashLegacyClientSecret(env: Env, clientId: string): Promise<void> {
  const store = oauthStorage(env)
  const value = (await store({ op: 'get', key: `client:${clientId}` })).value as { secret?: string } | undefined
  if (value?.secret) await store({ op: 'put', key: `client:${clientId}`, value: await withHashedSecret(value) })
}

/**
 * Resolve where a finished sign-in may send the browser.
 *
 * Returns the accepted target (a relative path stays relative; an absolute URL
 * comes back normalised), or `null` when the target is not allowed, in which
 * case the caller uses its safe default.
 *
 * @param requestOrigin  origin of the request being served (the flow's own host)
 * @param clientId       when the caller names a client, its redirect_uri
 *                       origins are accepted without the index lookup
 */
export async function resolveContinue(
  env: Env,
  raw: string | null | undefined,
  opts: { requestOrigin: string; clientId?: string },
): Promise<string | null> {
  if (!raw || raw.length > 4096 || !isSafeRedirectUrl(raw)) return null
  const requestOrigin = canonicalOrigin(opts.requestOrigin)
  if (!requestOrigin) return null
  let resolved: URL
  try {
    resolved = new URL(raw, requestOrigin)
  } catch {
    return null
  }

  // 1. Relative path on this host.
  if (raw.startsWith('/')) {
    return resolved.origin === requestOrigin ? raw : null
  }

  if (resolved.protocol !== 'https:' && resolved.protocol !== 'http:') return null
  // Credentials in a redirect target are never legitimate.
  if (resolved.username || resolved.password) return null
  // Decide on, and return, the canonical spelling of the host.
  const host = canonicalHostname(resolved.hostname)
  if (!host) return null
  if (host !== resolved.hostname) resolved.hostname = host
  const origin = resolved.origin

  // 2. id.org.ai's own origins, and the origin that served this request.
  if (OWN_ORIGINS.includes(origin) || origin === requestOrigin) return resolved.href

  // 3. Trusted-account domains (ADR-0007): same Cloudflare account.
  if (resolved.protocol === 'https:' && parseTrustedAccountDomains(env.TRUSTED_ACCOUNT_DOMAINS).has(resolved.hostname)) {
    return resolved.href
  }
  //    ...and the estate hosts named in config (LOGIN_CONTINUE_HOSTS).
  if (resolved.protocol === 'https:' && isListedContinueHost(env, resolved.hostname)) return resolved.href

  // 4. A registered client's redirect_uri origin.
  if (opts.clientId) {
    const client = await getRegisteredClient(env, opts.clientId)
    if (client?.redirectUris.some((u) => originOf(u) === origin)) return resolved.href
  }
  if (await isRegisteredClientOrigin(env, origin)) return resolved.href

  return null
}
