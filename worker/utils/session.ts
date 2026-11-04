/**
 * The browser session behind the `auth` cookie (security review H4).
 *
 * The session JWT /api/callback signs used to be a bare 30-day bearer: no
 * `sid`, no `aud`, `platformRole: superadmin` baked in, and logout only
 * cleared the cookie. Now:
 *
 *   - every session JWT carries a `sid` and `aud: SESSION_AUDIENCE`, and the
 *     `sid` names a record in the Person's own IdentityDO (`human:<sub>`);
 *   - logout revokes that record, freezing the identity revokes them all, and
 *     every verification (here, AuthService, /auth/verify) checks it;
 *   - privileged claims (`platformRole`, an `admin`/`owner` role) are re-read
 *     from WorkOS at verification, never trusted from the token.
 *
 * A session JWT minted before this change has no `sid` and no `aud`. It stays
 * valid until it expires, so nobody is signed out by the deploy, but it is
 * checked too: logout revokes it by hash, freeze by its `iat`, and its
 * privileged claims are re-read the same way.
 *
 * Other id.org.ai-signed JWTs (id_tokens, `at+jwt` access tokens: they carry
 * a different `aud`) are not sessions; this module leaves them as they were.
 */
import * as jose from 'jose'
import type { Env } from '../types'
import type { AccessTokenClaims } from '../../src/sdk/jwt/signing'
import { getStubForIdentity, getSigningKeyManager, verifySessionJwt as verifySessionClassJwt } from '../middleware/tenant'
import { ID_ORG_AI_SESSION_AUDIENCE, isSessionAudience } from '../../src/sdk/auth/token-class'
import { parseCookieValue } from './cookies'
import { invalidateCachedToken } from './cache'
import { listUserOrgMemberships } from '../../src/sdk/workos/upstream'

export const SESSION_ISSUER = 'https://id.org.ai'
/** The `aud` of a browser-session JWT. A URN, so no resource server can be registered under it. */
export const SESSION_AUDIENCE = ID_ORG_AI_SESSION_AUDIENCE
/** The JWT's lifetime. Privilege inside it is re-read at every verification. */
export const SESSION_TTL_SECONDS = 30 * 24 * 3600
/** How long AuthService may cache an unprivileged session verification. Privileged ones are never cached. */
export const SESSION_CACHE_TTL_SECONDS = 30

/** WorkOS org roles that grant more than membership; re-read, never trusted from the token. */
const PRIVILEGED_ROLES: ReadonlySet<string> = new Set(['admin', 'owner'])

/** The IdentityDO a session JWT's record lives in. */
export function sessionIdentityId(sub: string): string {
  return `human:${sub}`
}

function newSid(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(24))
  return 'bs_' + Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('')
}

/**
 * Sign a session JWT for `claims.sub`, backed by a session record. Pass `sid`
 * to re-sign an existing session (an org switch); otherwise a new one starts.
 */
export async function mintSessionJwt(env: Env, claims: AccessTokenClaims, opts: { sid?: string } = {}): Promise<string> {
  const sid = opts.sid ?? newSid()
  const expiresAt = (Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS) * 1000
  await getStubForIdentity(env, sessionIdentityId(claims.sub)).putBrowserSession({ identityId: sessionIdentityId(claims.sub), sid, expiresAt })
  return getSigningKeyManager(env).sign({ ...claims, sid }, { issuer: SESSION_ISSUER, audience: SESSION_AUDIENCE, expiresIn: SESSION_TTL_SECONDS })
}

/** Is this verified id.org.ai payload a browser session (ours, or one minted before `aud` existed)? */
export function isSessionPayload(payload: jose.JWTPayload): boolean {
  return isSessionAudience(payload.aud)
}

/**
 * Is the session still good: not logged out, not frozen, not expired? Answers
 * true for id.org.ai JWTs that are not sessions. Fails closed when the record
 * can't be read.
 */
export async function checkSessionState(env: Env, payload: jose.JWTPayload, token: string): Promise<boolean> {
  if (!isSessionPayload(payload)) return true
  if (typeof payload.sub !== 'string' || !payload.sub) return false
  const sid = typeof payload.sid === 'string' && payload.sid ? payload.sid : undefined
  // We never sign the session audience without a sid.
  if (!sid && payload.aud !== undefined) return false
  try {
    const identityId = sessionIdentityId(payload.sub)
    const result = await getStubForIdentity(env, identityId).checkBrowserSession({
      identityId,
      sid,
      iat: typeof payload.iat === 'number' ? payload.iat : undefined,
      ...(sid ? {} : { tokenHash: await sha256Hex(token) }),
    })
    return result.valid
  } catch (err) {
    console.error('[session] record check failed:', err instanceof Error ? err.message : err)
    return false
  }
}

/**
 * Signature, issuer and expiry, and the session class (security review H2):
 * an id_token or access token placed in the cookie is never a session.
 */
async function verifySignature(env: Env, token: string): Promise<jose.JWTPayload | null> {
  try {
    return await verifySessionClassJwt(token, env)
  } catch {
    return null
  }
}

/**
 * Verify an id.org.ai browser-session JWT (signature, issuer, expiry, session
 * class) and its session record. Null when any check fails.
 */
export async function verifyLiveSessionJwt(env: Env, token: string): Promise<jose.JWTPayload | null> {
  const payload = await verifySignature(env, token)
  if (!payload) return null
  return (await checkSessionState(env, payload, token)) ? payload : null
}

const cookieVerdicts = new WeakMap<Request, Promise<jose.JWTPayload | null>>()

/**
 * The verified payload of the request's `auth` cookie, or null. Memoized per
 * Request, so tenant resolution and the routes after it check the record once.
 */
export function verifySessionCookie(request: Request, env: Env): Promise<jose.JWTPayload | null> {
  let verdict = cookieVerdicts.get(request)
  if (!verdict) {
    const cookie = request.headers.get('cookie')
    const jwt = cookie ? parseCookieValue(cookie, 'auth') : null
    verdict = jwt ? verifyLiveSessionJwt(env, jwt) : Promise.resolve(null)
    cookieVerdicts.set(request, verdict)
  }
  return verdict
}

/**
 * Revoke the session a JWT belongs to (logout). A no-op for anything that is
 * not a validly signed id.org.ai session. Never throws: logout still clears
 * the cookie when the record can't be reached.
 */
export async function revokeSessionJwt(env: Env, token: string): Promise<void> {
  try {
    const payload = await verifySignature(env, token)
    if (!payload || !isSessionPayload(payload) || typeof payload.sub !== 'string' || !payload.sub) return
    const identityId = sessionIdentityId(payload.sub)
    const sid = typeof payload.sid === 'string' && payload.sid ? payload.sid : undefined
    await getStubForIdentity(env, identityId).revokeBrowserSession(
      sid
        ? { identityId, sid }
        : { identityId, tokenHash: await sha256Hex(token), expiresAt: typeof payload.exp === 'number' ? payload.exp * 1000 : undefined },
    )
  } catch (err) {
    console.error('[session] revoke failed:', err instanceof Error ? err.message : err)
  } finally {
    // This colo's AuthService cache; others age out within SESSION_CACHE_TTL_SECONDS.
    await invalidateCachedToken(token)
  }
}

/** Revoke the session in the request's `auth` cookie, if any. */
export async function revokeSessionCookie(request: Request, env: Env): Promise<void> {
  const cookie = request.headers.get('cookie')
  const jwt = cookie ? parseCookieValue(cookie, 'auth') : null
  if (jwt) await revokeSessionJwt(env, jwt)
}

function stringArray(value: unknown): string[] | undefined {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : undefined
}

/** Does the token claim anything beyond plain membership? */
export function claimsPrivilege(payload: jose.JWTPayload): boolean {
  if (payload.platformRole === 'superadmin') return true
  return (stringArray(payload.roles) ?? []).some((r) => PRIVILEGED_ROLES.has(r))
}

export interface SessionPrivilege {
  platformRole?: 'superadmin'
  roles?: string[]
  permissions?: string[]
}

/**
 * The privilege a verified token's holder has *now*. Unprivileged claims pass
 * through untouched (no WorkOS call). A token claiming `platformRole` or an
 * `admin`/`owner` role is re-read against the person's live WorkOS
 * memberships: superadmin needs an active membership in PLATFORM_ORG_ID (and
 * is never granted to a token that didn't claim it), and the org role is the
 * membership's current role in the token's org. Fails closed: no WorkOS key,
 * or a WorkOS error, drops the privilege.
 */
export async function rereadPrivilege(env: Env, payload: jose.JWTPayload): Promise<SessionPrivilege> {
  const roles = stringArray(payload.roles)
  const permissions = stringArray(payload.permissions)
  if (!claimsPrivilege(payload)) return { roles, permissions }

  const sub = typeof payload.sub === 'string' ? payload.sub : ''
  const memberships = sub && env.WORKOS_API_KEY ? await listUserOrgMemberships(env.WORKOS_API_KEY, sub) : []
  const active = memberships.filter((m) => m.status === 'active')

  const platformRole =
    payload.platformRole === 'superadmin' && env.PLATFORM_ORG_ID && active.some((m) => m.organization_id === env.PLATFORM_ORG_ID)
      ? ('superadmin' as const)
      : undefined

  const org = payload.org as { id?: unknown } | undefined
  const orgId = typeof org?.id === 'string' ? org.id : typeof payload.org_id === 'string' ? payload.org_id : undefined
  const membership = orgId ? active.find((m) => m.organization_id === orgId) : undefined
  if (!membership) return { platformRole, roles: [], permissions: [] }
  const slug = membership.role?.slug
  const currentRoles = slug ? [slug] : []
  // The token's permissions belong to the role it was signed with; a changed
  // role gets none until the next sign-in (as an org switch does).
  const sameRole = !!slug && (roles ?? []).includes(slug)
  return { platformRole, roles: currentRoles, permissions: sameRole ? (permissions ?? []) : [] }
}
