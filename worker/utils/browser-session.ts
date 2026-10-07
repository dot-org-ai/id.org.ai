/**
 * Did this request authenticate as a person in their own browser? Tenant
 * resolution takes an API key (header, X-API-Key, ?api_key=) or a session
 * token before the `auth` cookie, so any of those present means the identity
 * did not come from the browser session. Used where only a person may act:
 * delegating api.sb authority on consent, and approving a device (phase 6
 * re-review SF-2: an anonymous sandbox session must not approve one).
 */
import { parseCookieValue } from './cookies'
import { extractApiKey, extractSessionToken } from './extract'

export function isBrowserSession(request: Request): boolean {
  const authCookie = parseCookieValue(request.headers.get('cookie') ?? '', 'auth')
  return (
    !extractApiKey(request) &&
    !extractSessionToken(request) &&
    !request.headers.get('authorization') &&
    !!authCookie &&
    isSessionCookieJwt(authCookie)
  )
}

/**
 * Is the `auth` cookie shaped like an id.org.ai browser-session JWT (what
 * /api/callback and magic link sign), rather than some other
 * id.org.ai-signed JWT placed there? Tenant resolution has already verified
 * its signature and issuer; this looks at its shape. A session JWT carries no
 * `aud`, `nonce` or `at_hash`; an id_token (issued to a relying party) always
 * carries `aud` and `at_hash`; an access token is typ at+jwt. So an RP that
 * holds a Person's id_token cannot pose as that Person's browser to grant
 * sb scopes.
 */
export function isSessionCookieJwt(jwt: string): boolean {
  const parts = jwt.split('.')
  if (parts.length !== 3) return false
  try {
    const dec = (s: string) => JSON.parse(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4)))
    const header = dec(parts[0]!) as Record<string, unknown>
    const payload = dec(parts[1]!) as Record<string, unknown>
    if (typeof header.typ === 'string' && header.typ.toLowerCase().replace(/^application\//, '') !== 'jwt') return false
    if ('crit' in header) return false
    return !('aud' in payload) && !('nonce' in payload) && !('at_hash' in payload)
  } catch {
    return false
  }
}
