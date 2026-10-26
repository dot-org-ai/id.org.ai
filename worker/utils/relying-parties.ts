/**
 * Relying-party helpers: where a sign-in may send the browser afterwards, and
 * who is calling.
 *
 * `/login?continue=`, `/logout?return_url=` and POST /api/magic-link's
 * `continue` accept only
 *
 *   1. a relative path on the host that served the request;
 *   2. id.org.ai's own origins, and the origin that served the request;
 *   3. an explicit first-party allowlist: the trusted-account domains
 *      (ADR-0007, TRUSTED_ACCOUNT_DOMAINS) and the hosts named by
 *      LOGIN_CONTINUE_HOSTS (config; `*.` suffix entries);
 *   4. a redirect_uri of the client in the flow, by exact match, and only when
 *      the caller has established that client (`clientRedirectUris`): an
 *      operator-seeded trusted client on the browser routes
 *      (flowClientRedirectUris), an authenticated, listed client on
 *      /api/magic-link.
 *
 * Anything else is refused and the caller falls back to a safe default.
 *
 * Never trusted (H3): the origin of whatever client happens to be registered.
 * Registration (RFC 7591) is open, so "some registered client's redirect
 * origin" is any origin an attacker cares to register, and a client_id in a
 * browser query string is whatever the attacker wrote there. The rp-origin:*
 * index that once backed that rule is no longer read.
 *
 * Every host is compared in its canonical spelling (lowercase, no trailing
 * dot; canonicalHostname): Cloudflare serves public traffic on `id.org.ai.`
 * as well as `id.org.ai`, with the dot kept in request.url, so no decision
 * here may treat one spelling of a name differently from another. No trust is
 * ever inferred from the host a request arrived on: callers inside the
 * account use the AuthService RPC entrypoint (worker/index.ts), which a public
 * request cannot reach.
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

export interface ContinueOptions {
  /** Origin of the request being served (the flow's own host). */
  requestOrigin: string
  /**
   * Redirect URIs of the client in the flow, already established by the
   * caller (an authenticated client, or flowClientRedirectUris). Matched
   * exactly; never a registered client's whole origin.
   */
  clientRedirectUris?: readonly string[]
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

/** The canonical href of an http(s) URL (host in its canonical spelling), or null. */
function canonicalHref(url: string): string | null {
  try {
    const u = new URL(url)
    if (u.protocol !== 'https:' && u.protocol !== 'http:') return null
    const host = canonicalHostname(u.hostname)
    if (!host) return null
    if (host !== u.hostname) u.hostname = host
    return u.href
  } catch {
    return null
  }
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

/**
 * `enforce` unless LOGIN_CONTINUE_POLICY is explicitly `report` (production
 * config enforces since H3). `report` is a break-glass for an estate caller
 * found broken after a deploy: it re-opens the redirect to any https URL, so
 * list the caller's host in LOGIN_CONTINUE_HOSTS instead wherever possible.
 */
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
  opts: ContinueOptions,
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

/**
 * resolveBrowserRedirect for the redesigned screens (spec/security.md#redirects):
 * always enforce, whatever LOGIN_CONTINUE_POLICY says, so a new route never
 * follows an unlisted target even if the `report` break-glass is switched on
 * for the legacy routes.
 */
export async function resolveBrowserRedirectStrict(
  env: Env,
  raw: string | null | undefined,
  opts: ContinueOptions,
): Promise<{ url: string | null; outcome: 'none' | 'accepted' | 'refused'; host?: string }> {
  if (!raw) return { url: null, outcome: 'none' }
  const accepted = await resolveContinue(env, raw, opts)
  return accepted ? { url: accepted, outcome: 'accepted' } : { url: null, outcome: 'refused', host: hostForLog(raw) }
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
): Promise<{ id: string; secret?: string; secretHash?: string; redirectUris: string[]; tokenEndpointAuthMethod?: string; name?: string; trusted?: boolean } | null> {
  if (!clientId) return null
  const value = (await oauthStorage(env)({ op: 'get', key: `client:${clientId}` })).value as
    | { id: string; secret?: string; secretHash?: string; redirectUris?: string[]; tokenEndpointAuthMethod?: string; name?: string; trusted?: boolean }
    | undefined
  if (!value?.id) return null
  return { ...value, redirectUris: Array.isArray(value.redirectUris) ? value.redirectUris : [] }
}

/**
 * The redirect URIs a browser route (`/login?client_id=`) may honour for the
 * client it names: those of an operator-seeded trusted client
 * (src/sdk/oauth/clients.ts), none for a self-registered one. The client_id
 * in a browser query is unauthenticated and registration is open, so a
 * self-registered client's redirect_uri is never a continue target (H3).
 */
export async function flowClientRedirectUris(env: Env, clientId: string | null | undefined): Promise<string[] | undefined> {
  if (!clientId) return undefined
  const client = await getRegisteredClient(env, clientId)
  return client?.trusted === true ? client.redirectUris : undefined
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
 * @param requestOrigin       origin of the request being served (the flow's own host)
 * @param clientRedirectUris  redirect URIs of the client in the flow, which the
 *                            caller has established (authenticated, or trusted);
 *                            a target equal to one of them is accepted
 */
export async function resolveContinue(
  env: Env,
  raw: string | null | undefined,
  opts: ContinueOptions,
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

  // 4. A redirect_uri of the client in the flow, by exact match.
  if (opts.clientRedirectUris?.some((u) => canonicalHref(u) === resolved.href)) return resolved.href

  return null
}
