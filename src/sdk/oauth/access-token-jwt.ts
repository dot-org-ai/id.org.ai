/**
 * JWT access tokens (RFC 9068) for resource servers that verify tokens
 * themselves (api.sb), signed with id.org.ai's signing key and published in
 * its JWKS (/.well-known/jwks.json).
 *
 * Header:  { alg: RS256, typ: "at+jwt", kid, crit: ["aud_bound"], aud_bound: true }
 * Claims:  iss, sub (the Person), aud (the resource), client_id, scope, iat,
 *          exp, jti; `act` when a token exchange made one (RFC 8693 §4.1,
 *          nested for chains).
 *
 * Why `crit`: the same key signs id.org.ai's id_tokens and session JWTs, and
 * several verifiers in the estate accept any id.org.ai-signed JWT as a
 * Person's credential without checking `typ` or `aud` (the `auth` worker,
 * AuthService, the `auth` cookie). An access token minted for api.sb must not
 * become a credential anywhere else. RFC 7515 §4.1.11: a recipient that does
 * not understand a `crit` extension MUST reject the JWS. jose (every JOSE
 * verifier in the estate) and id.org.ai's own verifiers do. A resource server
 * built for these tokens opts in, e.g. with jose:
 *
 *   jwtVerify(token, JWKS, { issuer: 'https://id.org.ai', audience: 'https://api.sb/mcp',
 *                            typ: 'at+jwt', crit: { aud_bound: true } })
 *
 * `aud_bound` (coined here) says: the token is bound to its `aud`; accept it
 * only where you check that `aud` is you.
 */

import type { SigningKey } from '../jwt/signing'

/** The JWS `typ` of an RFC 9068 access token. */
export const ACCESS_TOKEN_TYP = 'at+jwt'
/** The critical header parameter every access token carries (coined). */
export const AUD_BOUND_HEADER = 'aud_bound'
/** Access-token JWT lifetime. Short: a resource server verifying locally sees a revocation only at expiry. */
export const ACCESS_TOKEN_JWT_TTL = 900 // 15 minutes

/** RFC 8693 §4.1 actor claim: the current actor, with prior actors nested. */
export interface ActorClaim {
  sub: string
  act?: ActorClaim
}

export interface AccessTokenJwtClaims {
  iss: string
  sub: string
  aud: string
  client_id: string
  scope: string
  iat: number
  exp: number
  jti: string
  act?: ActorClaim
}

function b64url(bytes: Uint8Array): string {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

function b64urlJson(value: unknown): string {
  return b64url(new TextEncoder().encode(JSON.stringify(value)))
}

function fromB64url(s: string): string {
  const b = s.replace(/-/g, '+').replace(/_/g, '/')
  return atob(b + '='.repeat((4 - (b.length % 4)) % 4))
}

/** Sign an RFC 9068 access token. */
export async function signAccessTokenJwt(key: SigningKey, claims: AccessTokenJwtClaims): Promise<string> {
  const header = { alg: 'RS256', typ: ACCESS_TOKEN_TYP, kid: key.kid, crit: [AUD_BOUND_HEADER], [AUD_BOUND_HEADER]: true }
  const data = `${b64urlJson(header)}.${b64urlJson(claims)}`
  const sig = await crypto.subtle.sign({ name: 'RSASSA-PKCS1-v1_5' }, key.privateKey, new TextEncoder().encode(data))
  return `${data}.${b64url(new Uint8Array(sig))}`
}

/** The decoded header of a compact JWS, or null. Does not verify anything. */
export function peekJwtHeader(token: string): Record<string, unknown> | null {
  if (typeof token !== 'string') return null
  const parts = token.split('.')
  if (parts.length !== 3 || !parts[0]) return null
  try {
    const h = JSON.parse(fromB64url(parts[0]))
    return h && typeof h === 'object' && !Array.isArray(h) ? (h as Record<string, unknown>) : null
  } catch {
    return null
  }
}

/**
 * True when `token` presents itself as an access token (typ at+jwt, per RFC
 * 9068 §2.1 compared case-insensitively with or without "application/", or
 * carrying the aud_bound extension). A cheap pre-check for verifiers of
 * identity JWTs (id_token, session cookie) that must never accept one.
 */
export function isAccessTokenJwt(token: string): boolean {
  const h = peekJwtHeader(token)
  if (!h) return false
  const typ = typeof h.typ === 'string' ? h.typ.toLowerCase().replace(/^application\//, '') : ''
  if (typ === ACCESS_TOKEN_TYP) return true
  return Array.isArray(h.crit) && h.crit.includes(AUD_BOUND_HEADER)
}

/**
 * RFC 7515 §4.1.11 for id.org.ai's hand-rolled verifiers: the `crit` entries
 * of a header that `understood` does not list. A JWS with any is rejected.
 * A malformed `crit` (not a non-empty array of strings) counts as not
 * understood.
 */
export function unrecognizedCrit(header: Record<string, unknown>, understood: readonly string[] = []): string[] {
  if (!('crit' in header)) return []
  const crit = header.crit
  if (!Array.isArray(crit) || crit.length === 0 || !crit.every((c) => typeof c === 'string')) return ['(malformed crit)']
  return (crit as string[]).filter((c) => !understood.includes(c) || !(c in header))
}
