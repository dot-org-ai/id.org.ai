/**
 * What kind of id.org.ai-signed JWT a verified token is.
 *
 * id.org.ai signs three kinds of JWT with one published key set (the
 * signature alone cannot tell them apart):
 *
 *   - the sign-in session JWT (the `auth` cookie): `typ: JWT`, NO `aud`.
 *     It is the Person's own credential.
 *   - the OIDC id_token: `typ: JWT`, `aud` = the OAuth client it was issued to.
 *     It tells THAT client who signed in; it is never a credential anywhere
 *     else. Registration is open, so any third-party client a Person signs into
 *     holds one.
 *   - the RFC 9068 access token: `typ: at+jwt`, `crit: ["aud_bound"]`, `aud` =
 *     the resource it is for. Only that resource accepts it.
 *
 * A verifier that takes "a valid id.org.ai JWT" as the Person must accept only
 * the session class. A token with an audience is accepted only by a verifier
 * that names that audience (it is the audience).
 */

export type IdOrgAiTokenClass = 'session' | 'id_token' | 'access_token' | 'other'

/** Classify a VERIFIED token from its protected header and payload. */
export function idOrgAiTokenClass(header: { typ?: unknown; crit?: unknown }, payload: { aud?: unknown }): IdOrgAiTokenClass {
  const typ = typeof header.typ === 'string' ? header.typ.toLowerCase() : undefined
  if (typ === 'at+jwt' || typ === 'application/at+jwt') return 'access_token'
  // Any critical extension (the access token's aud_bound, or one not yet
  // defined) is not a session.
  if (header.crit !== undefined) return 'other'
  if (typ !== undefined && typ !== 'jwt') return 'other'
  // Any `aud` at all (even an empty one) names an audience: not a session.
  if (payload.aud !== undefined && payload.aud !== null) return 'id_token'
  return 'session'
}

/** True when a verified id.org.ai JWT is the Person's sign-in session token. */
export function isIdOrgAiSessionToken(header: { typ?: unknown; crit?: unknown }, payload: { aud?: unknown }): boolean {
  return idOrgAiTokenClass(header, payload) === 'session'
}
