/**
 * OAuth Client ID Metadata Documents (CIMD, draft-ietf-oauth-client-id-
 * metadata-document; the MCP 2025-11-25+ recommended registration).
 *
 * A client whose `client_id` is an https URL publishes its metadata at that
 * URL. id.org.ai fetches the document (worker/utils/client-metadata.ts: SSRF
 * guards, size and time limits, no redirects, cached) and validates it here:
 *
 *   - the client_id URL: https, a path, no fragment, no credentials, no dot
 *     segments, no query;
 *   - the document: a JSON object whose `client_id` equals the URL exactly,
 *     with https (or loopback http) `redirect_uris`, no shared secret, and an
 *     auth method id.org.ai can treat as a public client (`none`, or
 *     `private_key_jwt` for a client that also lists `none`). Every CIMD
 *     client is public here: PKCE is mandatory and no secret is accepted.
 *
 * A CIMD client is never trusted (the Person always sees the consent screen),
 * cannot use client_credentials or the device flow, and is named on the
 * consent screen by its URL's host: the document's `client_name` is the
 * client's own claim.
 *
 * DCR keeps working unchanged (OpenCode and Cursor need it); a DCR client_id
 * (`cid_…`) or a seeded id is never an https URL, so the two cannot collide.
 */

import type { OAuthProviderClient } from './provider'

/** Documents larger than this are refused. */
export const CIMD_MAX_BYTES = 10 * 1024
/** Fetch timeout. */
export const CIMD_TIMEOUT_MS = 5000
/** Cache bounds for a fetched document (Cache-Control max-age is clamped into this range). */
export const CIMD_MIN_TTL_S = 300
export const CIMD_MAX_TTL_S = 24 * 3600
export const CIMD_DEFAULT_TTL_S = 3600
/** How long a failed fetch is remembered, so one client_id cannot make id.org.ai fetch in a loop. */
export const CIMD_NEGATIVE_TTL_S = 60

const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]'])

/** True when `clientId` is shaped like a CIMD client_id (an https URL). */
export function looksLikeCimdClientId(clientId: string): boolean {
  return typeof clientId === 'string' && clientId.startsWith('https://')
}

/** Why a client_id URL is not acceptable as a CIMD client_id, or null. */
export function cimdClientIdProblem(clientId: string): string | null {
  if (!looksLikeCimdClientId(clientId)) return 'client_id is not an https URL'
  if (clientId.length > 2048) return 'client_id URL is too long'
  let u: URL
  try {
    u = new URL(clientId)
  } catch {
    return 'client_id is not a valid URL'
  }
  if (u.protocol !== 'https:') return 'client_id must use https'
  if (u.username || u.password) return 'client_id must not contain credentials'
  if (clientId.includes('#')) return 'client_id must not contain a fragment'
  if (u.search || clientId.includes('?')) return 'client_id must not contain a query'
  if (u.pathname === '/' || u.pathname === '') return 'client_id must contain a path'
  // The URL as sent must be the URL as parsed: no dot segments, no case or
  // encoding tricks the parser would normalise away.
  if (u.href !== clientId) return 'client_id is not in canonical form'
  const raw = clientId.slice(clientId.indexOf('/', 'https://'.length))
  if (raw.split('/').some((seg) => seg === '.' || seg === '..' || /^%2e(%2e)?$/i.test(seg) || /^\.%2e$|^%2e\.$/i.test(seg))) {
    return 'client_id must not contain dot segments'
  }
  return null
}

function isHttpsOrLoopback(uri: string): boolean {
  try {
    const u = new URL(uri)
    if (u.hash || uri.includes('#')) return false
    if (u.username || u.password) return false
    if (u.protocol === 'https:') return true
    return u.protocol === 'http:' && LOOPBACK_HOSTS.has(u.hostname)
  } catch {
    return false
  }
}

export type CimdParse = { ok: true; client: OAuthProviderClient } | { ok: false; description: string }

/** Validate a fetched metadata document for `clientId` and build the client record. */
export function parseClientMetadataDocument(clientId: string, doc: unknown): CimdParse {
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) return { ok: false, description: 'client metadata is not a JSON object' }
  const d = doc as Record<string, unknown>
  if (d.client_id !== clientId) return { ok: false, description: 'client metadata client_id does not match the URL it was fetched from' }
  if ('client_secret' in d || 'client_secret_expires_at' in d) return { ok: false, description: 'client metadata must not contain a client secret' }

  const method = d.token_endpoint_auth_method ?? 'none'
  const supported = Array.isArray(d.token_endpoint_auth_methods_supported) ? d.token_endpoint_auth_methods_supported : []
  const publicOk = method === 'none' || (method === 'private_key_jwt' && supported.includes('none'))
  if (!publicOk) {
    return { ok: false, description: `token_endpoint_auth_method ${String(method)} is not supported for client metadata documents (use none)` }
  }

  const redirectUris = d.redirect_uris
  if (!Array.isArray(redirectUris) || redirectUris.length === 0 || !redirectUris.every((r) => typeof r === 'string')) {
    return { ok: false, description: 'client metadata needs redirect_uris' }
  }
  if (redirectUris.length > 20) return { ok: false, description: 'client metadata lists too many redirect_uris' }
  for (const r of redirectUris as string[]) {
    if (!isHttpsOrLoopback(r)) return { ok: false, description: `redirect_uri must use https (or http on loopback): ${r}` }
  }

  const grantTypes = Array.isArray(d.grant_types) ? (d.grant_types as unknown[]).filter((g): g is string => typeof g === 'string') : ['authorization_code']
  if (!grantTypes.includes('authorization_code')) return { ok: false, description: 'client metadata must allow authorization_code' }
  // Only the browser grants: no client_credentials (no secret), no device flow.
  const allowed = grantTypes.filter((g) => g === 'authorization_code' || g === 'refresh_token')

  const str = (v: unknown, max = 256) => (typeof v === 'string' && v.length > 0 ? v.slice(0, max) : undefined)
  const host = new URL(clientId).host
  const logo = str(d.logo_uri, 2048)
  const website = str(d.client_uri, 2048)
  return {
    ok: true,
    client: {
      id: clientId,
      name: str(d.client_name) ?? host,
      redirectUris: redirectUris as string[],
      grantTypes: allowed,
      responseTypes: ['code'],
      // No registered scopes: a CIMD client may ask for the OIDC scopes and
      // the sb scopes (both by the Person's consent), nothing else.
      scopes: [],
      trusted: false,
      tokenEndpointAuthMethod: 'none',
      ...(logo && logo.startsWith('https://') && { logo }),
      ...(website && website.startsWith('https://') && { website }),
      createdAt: 0,
    },
  }
}

/**
 * Does `requested` match one of a CIMD client's `registered` redirect_uris?
 * Exact string match, except that a loopback (`http://localhost`,
 * `http://127.0.0.1`, `http://[::1]`) redirect_uri matches on any port (RFC
 * 8252 §7.3: native apps listen on an ephemeral port; Claude Code registers
 * `http://localhost/callback`). Scheme, host, path and query must still match
 * exactly.
 */
export function cimdRedirectMatches(registered: string[], requested: string): boolean {
  if (registered.includes(requested)) return true
  let req: URL
  try {
    req = new URL(requested)
  } catch {
    return false
  }
  if (req.protocol !== 'http:' || !LOOPBACK_HOSTS.has(req.hostname) || req.hash || req.username || req.password) return false
  return registered.some((r) => {
    try {
      const reg = new URL(r)
      return (
        reg.protocol === 'http:' &&
        reg.hostname === req.hostname &&
        reg.pathname === req.pathname &&
        reg.search === req.search &&
        // The requested URI with its port removed is the registered URI with its port removed.
        stripPort(r) === stripPort(requested)
      )
    } catch {
      return false
    }
  })
}

function stripPort(uri: string): string {
  const u = new URL(uri)
  u.port = ''
  return u.href
}

/** Clamp a Cache-Control header's max-age into the CIMD cache bounds. */
export function cimdTtlSeconds(cacheControl: string | null): number {
  if (!cacheControl) return CIMD_DEFAULT_TTL_S
  if (/\bno-store\b|\bno-cache\b/i.test(cacheControl)) return CIMD_MIN_TTL_S
  const m = cacheControl.match(/\bmax-age\s*=\s*(\d+)/i)
  if (!m) return CIMD_DEFAULT_TTL_S
  return Math.min(CIMD_MAX_TTL_S, Math.max(CIMD_MIN_TTL_S, Number(m[1])))
}
