/**
 * Relying-party helpers: where a sign-in may send the browser afterwards, and
 * who is calling.
 *
 * `/login?continue=` (and POST /api/magic-link's `continue`) used to accept any
 * http(s) URL: an open redirect on the estate's identity provider. The policy
 * here accepts only
 *
 *   1. a relative path on the host that served the request;
 *   2. id.org.ai's own origins (and the request's own origin, which for a
 *      service binding is the calling worker's host);
 *   3. the trusted-account domains (ADR-0007, TRUSTED_ACCOUNT_DOMAINS);
 *   4. the origin of a registered OAuth client's redirect_uri.
 *
 * Anything else is refused and the caller falls back to a safe default.
 *
 * Registration (RFC 7591) is open, so (4) is only as strong as registration:
 * whoever registers a client can already have /oauth/authorize redirect to its
 * redirect_uri (error redirects need no consent). This policy adds no target an
 * OAuth client could not already reach; it removes every target nobody
 * registered.
 */
import type { Env } from '../types'
import { getStubForIdentity } from '../middleware/tenant'
import { isSafeRedirectUrl } from '../../src/sdk/csrf'
import { parseTrustedAccountDomains } from '../routes/oauth'

/** The public origins this worker serves (worker/wrangler.jsonc routes + workers.dev). */
export const OWN_ORIGINS: readonly string[] = [
  'https://id.org.ai',
  'https://auth.org.ai',
  'https://oauth.do',
  'https://auth.headless.ly',
  'https://oauth.dotdo.workers.dev',
]

const PUBLIC_HOSTS = new Set(OWN_ORIGINS.map((o) => new URL(o).hostname))

/**
 * True when the request came through a Cloudflare service binding rather than
 * the public internet. Public traffic reaches this worker only on its routes'
 * hostnames (id.org.ai, auth.org.ai, oauth.do, auth.headless.ly, *.workers.dev);
 * a service-binding caller builds the request URL itself, on its own host.
 * Unlike the X-Issuer header, the host of a public request cannot be chosen by
 * the client, so this cannot be spoofed from outside the account.
 */
export function isServiceBindingRequest(request: Request): boolean {
  let host: string
  try {
    host = new URL(request.url).hostname
  } catch {
    return false
  }
  if (PUBLIC_HOSTS.has(host)) return false
  if (host.endsWith('.workers.dev')) return false
  if (host === 'localhost' || host === '127.0.0.1' || host === '[::1]') return false
  return true
}

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
    return u.origin
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

/** A registered client's record, or null. */
export async function getRegisteredClient(
  env: Env,
  clientId: string,
): Promise<{ id: string; secret?: string; redirectUris: string[]; tokenEndpointAuthMethod?: string; name?: string } | null> {
  if (!clientId) return null
  const value = (await oauthStorage(env)({ op: 'get', key: `client:${clientId}` })).value as
    | { id: string; secret?: string; redirectUris?: string[]; tokenEndpointAuthMethod?: string; name?: string }
    | undefined
  if (!value?.id) return null
  return { ...value, redirectUris: Array.isArray(value.redirectUris) ? value.redirectUris : [] }
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
  let resolved: URL
  try {
    resolved = new URL(raw, opts.requestOrigin)
  } catch {
    return null
  }

  // 1. Relative path on this host.
  if (raw.startsWith('/')) {
    return resolved.origin === new URL(opts.requestOrigin).origin ? raw : null
  }

  if (resolved.protocol !== 'https:' && resolved.protocol !== 'http:') return null
  // Credentials in a redirect target are never legitimate.
  if (resolved.username || resolved.password) return null
  const origin = resolved.origin

  // 2. id.org.ai's own origins, and the origin that served this request.
  if (OWN_ORIGINS.includes(origin) || origin === new URL(opts.requestOrigin).origin) return resolved.href

  // 3. Trusted-account domains (ADR-0007): same Cloudflare account.
  if (resolved.protocol === 'https:' && parseTrustedAccountDomains(env.TRUSTED_ACCOUNT_DOMAINS).has(resolved.hostname)) {
    return resolved.href
  }

  // 4. A registered client's redirect_uri origin.
  if (opts.clientId) {
    const client = await getRegisteredClient(env, opts.clientId)
    if (client?.redirectUris.some((u) => originOf(u) === origin)) return resolved.href
  }
  if (await isRegisteredClientOrigin(env, origin)) return resolved.href

  return null
}
