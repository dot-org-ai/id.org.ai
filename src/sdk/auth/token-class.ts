/**
 * What kind of id.org.ai-signed JWT a verified token is.
 *
 * id.org.ai signs three kinds of JWT with one published key set (the
 * signature alone cannot tell them apart):
 *
 *   - the sign-in session JWT (the `auth` cookie): `typ: JWT`, and `aud`
 *     either the session audience `urn:id.org.ai:session` (with a `sid`,
 *     since security review H4) or absent (minted before H4). It is the
 *     Person's own credential.
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

/**
 * The `aud` of a browser-session JWT. A URN, so no OAuth client or resource
 * server can be registered under it (DCR ids are generated, CIMD ids are
 * https URLs with a path).
 */
export const ID_ORG_AI_SESSION_AUDIENCE = 'urn:id.org.ai:session'

/** Is `aud` the session audience (alone), or absent as on a pre-H4 session? */
function isSessionAudience(aud: unknown): boolean {
  if (aud === undefined || aud === null) return true
  if (aud === ID_ORG_AI_SESSION_AUDIENCE) return true
  return Array.isArray(aud) && aud.length === 1 && aud[0] === ID_ORG_AI_SESSION_AUDIENCE
}

export type IdOrgAiTokenClass = 'session' | 'id_token' | 'access_token' | 'other'

/** Classify a VERIFIED token from its protected header and payload. */
export function idOrgAiTokenClass(header: { typ?: unknown; crit?: unknown }, payload: { aud?: unknown }): IdOrgAiTokenClass {
  const typ = typeof header.typ === 'string' ? header.typ.toLowerCase() : undefined
  if (typ === 'at+jwt' || typ === 'application/at+jwt') return 'access_token'
  // Any critical extension (the access token's aud_bound, or one not yet
  // defined) is not a session.
  if (header.crit !== undefined) return 'other'
  if (typ !== undefined && typ !== 'jwt') return 'other'
  // Any `aud` other than the session audience (even an empty one) names an
  // audience: not a session.
  if (!isSessionAudience(payload.aud)) return 'id_token'
  return 'session'
}

/** True when a verified id.org.ai JWT is the Person's sign-in session token. */
export function isIdOrgAiSessionToken(header: { typ?: unknown; crit?: unknown }, payload: { aud?: unknown }): boolean {
  return idOrgAiTokenClass(header, payload) === 'session'
}
