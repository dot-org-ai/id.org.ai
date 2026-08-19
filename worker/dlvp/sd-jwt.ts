/**
 * dlvp/sd-jwt.ts — SD-JWT-VC parse + verify, WebCrypto-only, ZERO new heavy dep.
 *
 * id.org.ai already ships a full JWS verifier (src/sdk/oauth/jwt-verify.ts:
 * RS256/ES256/EdDSA + importPublicJwk + JWKS), so SD-JWT-VC VERIFICATION (not
 * issuance) is exactly three steps, all on primitives already present:
 *
 *   (1) ISSUER SIGNATURE — the SD-JWT is `<issuer-jwt>~<d1>~…~<dN>~<kb-jwt>`;
 *       verify the issuer JWT with verifyJWT() against a session-injected trust
 *       map of issuer JWKS (iss → JWK). (ES256 is the SD-JWT-VC default; EdDSA
 *       + RSA also flow through the same verifier.)
 *   (2) SELECTIVE DISCLOSURE — for each presented disclosure decode
 *       base64url([salt, name, value]), compute base64url(SHA-256(<disclosure
 *       ascii>)), require membership in the issuer JWT `_sd` array
 *       (`_sd_alg` = 'sha-256'); reconstruct ONLY the disclosed claims.
 *   (3) KEY BINDING = the nonce binding — the trailing KB-JWT (typ 'kb+jwt') is
 *       verified with verifyJWT against the issuer JWT's `cnf.jwk`, asserting
 *       nonce === r, aud === resolver origin, and
 *       sd_hash === base64url(SHA-256(<issuer-jwt~d1~…~dN~>)).
 *
 * ┌─ DEFERRED + TICKETED (bd model-gap) ──────────────────────────────────────┐
 * │ • Real issuer TRUST LIST (GS1-rooted did:web / ID-JAG registry) — v1 uses  │
 * │   a session-injected iss→JWK trust map (test fixtures self-generate keys). │
 * │   id.org.ai-e9a.                                                            │
 * │ • The full OIDC4VP wallet-issuance flow (authorization request/response,   │
 * │   presentation_definition / DCQL, wallet invocation, OpenID4VCI) — v1      │
 * │   VERIFIES presentations; it does not run the wallet flow. id.org.ai-06t.  │
 * │ • Nested `_sd` inside disclosed objects / recursive disclosures, array     │
 * │   element `...` digests, and `_sd_alg` other than sha-256 — v1 handles     │
 * │   top-level object-property disclosures with sha-256.                      │
 * │ • BBS+ / mDL / ZK — SYNTHESIS D2, separate primitives. id.org.ai-ac3.      │
 * └────────────────────────────────────────────────────────────────────────────┘
 */

import { verifyJWT, decodeJWT, importPublicJwk, type JWK } from '../../src/sdk/oauth/jwt-verify'
import { base64UrlDecode, base64UrlEncode } from '../../src/sdk/oauth/pkce'

/** A session-injected trust map: issuer id (`iss`/`vct` root) → its public JWK. */
export type IssuerTrustMap = Record<string, JWK>

/** The parsed SD-JWT combined form. */
export interface ParsedSdJwt {
  issuerJwt: string
  disclosures: string[]
  kbJwt: string | null
}

/** A successful SD-JWT-VC presentation verification. */
export interface SdJwtVerified {
  ok: true
  /** The credential type (`vct`). */
  vct: string
  /** The issuer (`iss`). */
  iss: string
  /** The reconstructed disclosed claims (undisclosed _sd digests stay hidden). */
  claims: Record<string, unknown>
  /** The holder confirmation key (`cnf.jwk`) the KB-JWT was verified against. */
  cnfJwk: JWK
  /** RFC 7638 thumbprint of the cnf jwk (the scoped-pseudonym seed). */
  cnfThumbprint: string
  /** The key-binding assertions (present only when a KB-JWT was required + valid). */
  kb: { nonce: string; aud: string; sdHash: string } | null
  /** SHA-256 (base64url) digest of the presented SD-JWT sans KB (the sd_hash input). */
  presentationDigest: string
}

export interface SdJwtFailed {
  ok: false
  reason: string
  code:
    | 'MALFORMED'
    | 'UNTRUSTED_ISSUER'
    | 'ISSUER_SIG_INVALID'
    | 'SD_ALG_UNSUPPORTED'
    | 'DISCLOSURE_UNMATCHED'
    | 'NO_CNF'
    | 'KB_MISSING'
    | 'KB_SIG_INVALID'
    | 'NONCE_MISMATCH'
    | 'AUD_MISMATCH'
    | 'SD_HASH_MISMATCH'
}

export type SdJwtResult = SdJwtVerified | SdJwtFailed

/** Verification options (the nonce/aud the KB-JWT must bind to). */
export interface SdJwtVerifyOptions {
  trust: IssuerTrustMap
  /** The resolution nonce `r` the KB-JWT `nonce` MUST equal. */
  expectedNonce: string
  /** The resolver origin the KB-JWT `aud` MUST equal. */
  expectedAud: string
  /** Require a key-binding JWT (true for a DLVP presentation). Default true. */
  requireKeyBinding?: boolean
}

// ── base64url helpers over strings/bytes ─────────────────────────────────────

function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s)
}

async function sha256b64u(input: Uint8Array | string): Promise<string> {
  const bytes = typeof input === 'string' ? utf8(input) : input
  const digest = await crypto.subtle.digest('SHA-256', bytes as unknown as ArrayBuffer)
  return base64UrlEncode(digest)
}

function decodeB64uToString(b64u: string): string {
  return new TextDecoder().decode(new Uint8Array(base64UrlDecode(b64u)))
}

// ── RFC 7638 JWK thumbprint (the scoped pseudonym seed) ──────────────────────

/**
 * Compute the RFC 7638 JWK thumbprint (base64url SHA-256 over the canonical
 * required-members JSON). Supports EC, OKP, and RSA public keys.
 */
export async function jwkThumbprint(jwk: JWK): Promise<string> {
  let canonical: string
  if (jwk.kty === 'EC') {
    canonical = `{"crv":"${jwk.crv}","kty":"EC","x":"${jwk.x}","y":"${jwk.y}"}`
  } else if (jwk.kty === 'OKP') {
    canonical = `{"crv":"${jwk.crv}","kty":"OKP","x":"${jwk.x}"}`
  } else if (jwk.kty === 'RSA') {
    canonical = `{"e":"${jwk.e}","kty":"RSA","n":"${jwk.n}"}`
  } else {
    canonical = JSON.stringify(jwk)
  }
  return sha256b64u(canonical)
}

// ── Parse ────────────────────────────────────────────────────────────────────

/**
 * Split the SD-JWT combined form on `~`. The first element is the issuer JWT;
 * the trailing element is the KB-JWT iff it looks like a JWT (contains '.');
 * everything between is a disclosure. A trailing empty segment (format ending in
 * `~` with no KB) is dropped.
 */
export function parseSdJwt(compact: string): ParsedSdJwt | null {
  if (typeof compact !== 'string' || compact.length === 0) return null
  const parts = compact.split('~')
  if (parts.length < 1) return null
  const issuerJwt = parts[0]!
  if (issuerJwt.split('.').length !== 3) return null
  const rest = parts.slice(1)
  let kbJwt: string | null = null
  if (rest.length > 0) {
    const last = rest[rest.length - 1]!
    if (last === '') {
      rest.pop() // trailing ~ with no KB-JWT
    } else if (last.split('.').length === 3) {
      kbJwt = rest.pop()! // a JWT-shaped trailing segment is the KB-JWT
    }
  }
  return { issuerJwt, disclosures: rest.filter((d) => d.length > 0), kbJwt }
}

// ── Verify ─────────────────────────────────────────────────────────────────

function fail(code: SdJwtFailed['code'], reason: string): SdJwtFailed {
  return { ok: false, code, reason }
}

/**
 * Verify an SD-JWT-VC presentation (the three steps). Fail-closed: any structural
 * or cryptographic problem returns a typed failure, NEVER a fabricated pass.
 */
export async function verifySdJwtPresentation(
  compact: string,
  opts: SdJwtVerifyOptions,
): Promise<SdJwtResult> {
  const requireKb = opts.requireKeyBinding ?? true
  const parsed = parseSdJwt(compact)
  if (!parsed) return fail('MALFORMED', 'not a well-formed SD-JWT combined form')

  // Decode the issuer JWT to learn iss + pick the trust-map key.
  const decoded = decodeJWT(parsed.issuerJwt)
  if (!decoded) return fail('MALFORMED', 'issuer JWT does not decode')
  const iss = typeof decoded.payload.iss === 'string' ? decoded.payload.iss : undefined
  if (!iss) return fail('MALFORMED', 'issuer JWT has no iss claim')
  const trustJwk = opts.trust[iss]
  if (!trustJwk) return fail('UNTRUSTED_ISSUER', `no trusted JWK for issuer ${iss}`)

  // (1) ISSUER SIGNATURE.
  const key = await importPublicJwk(trustJwk, decoded.header.alg)
  if (!key) return fail('UNTRUSTED_ISSUER', `trust JWK does not match alg ${decoded.header.alg}`)
  const issVerify = await verifyJWT(parsed.issuerJwt, { publicKey: key })
  if (!issVerify.valid) return fail('ISSUER_SIG_INVALID', issVerify.error)

  const payload = issVerify.payload
  const vct = typeof payload.vct === 'string' ? payload.vct : ''
  const sdAlg = (payload._sd_alg as string | undefined) ?? 'sha-256'
  if (sdAlg !== 'sha-256') return fail('SD_ALG_UNSUPPORTED', `_sd_alg ${sdAlg} unsupported in v1`)
  const sdDigests: string[] = Array.isArray(payload._sd) ? (payload._sd as string[]) : []

  // (2) SELECTIVE DISCLOSURE — each disclosure's digest MUST be in `_sd`.
  const claims: Record<string, unknown> = {}
  for (const disc of parsed.disclosures) {
    const digest = await sha256b64u(disc)
    if (!sdDigests.includes(digest)) {
      return fail('DISCLOSURE_UNMATCHED', `disclosure digest ${digest} not present in issuer _sd`)
    }
    let arr: unknown
    try {
      arr = JSON.parse(decodeB64uToString(disc))
    } catch {
      return fail('MALFORMED', 'disclosure is not valid base64url JSON')
    }
    // Object-property disclosure: [salt, claimName, claimValue].
    if (Array.isArray(arr) && arr.length === 3 && typeof arr[1] === 'string') {
      claims[arr[1] as string] = arr[2]
    } else {
      return fail('MALFORMED', 'v1 supports [salt,name,value] object-property disclosures only')
    }
  }

  // Carry any plaintext (non-selective) claims present alongside _sd, minus the
  // SD-JWT structural members — these are disclosed by construction.
  for (const [k, v] of Object.entries(payload)) {
    if (['_sd', '_sd_alg', 'cnf', 'iss', 'iat', 'exp', 'nbf', 'aud', 'vct', 'jti'].includes(k)) continue
    if (!(k in claims)) claims[k] = v
  }

  // The cnf holder key (needed for KB verification + the pseudonym).
  const cnf = payload.cnf as { jwk?: JWK } | undefined
  const cnfJwk = cnf?.jwk
  if (!cnfJwk) {
    if (requireKb) return fail('NO_CNF', 'issuer JWT has no cnf.jwk to key-bind against')
    // Non-KB path (e.g. brand provenance without holder binding) — allowed only
    // when the caller does not require key binding.
    return {
      ok: true,
      vct,
      iss,
      claims,
      cnfJwk: {} as JWK,
      cnfThumbprint: '',
      kb: null,
      presentationDigest: await sha256b64u(sansKb(parsed)),
    }
  }

  const cnfThumbprint = await jwkThumbprint(cnfJwk)
  const presentationDigest = await sha256b64u(sansKb(parsed))

  if (!requireKb) {
    return { ok: true, vct, iss, claims, cnfJwk, cnfThumbprint, kb: null, presentationDigest }
  }

  // (3) KEY BINDING — the nonce binding.
  if (!parsed.kbJwt) return fail('KB_MISSING', 'presentation has no key-binding JWT')
  const kbDecoded = decodeJWT(parsed.kbJwt)
  if (!kbDecoded) return fail('MALFORMED', 'KB-JWT does not decode')
  if (kbDecoded.header.typ !== 'kb+jwt') {
    return fail('MALFORMED', `KB-JWT typ must be 'kb+jwt', got '${kbDecoded.header.typ}'`)
  }
  const holderKey = await importPublicJwk(cnfJwk, kbDecoded.header.alg)
  if (!holderKey) return fail('NO_CNF', `cnf.jwk does not match KB alg ${kbDecoded.header.alg}`)
  const kbVerify = await verifyJWT(parsed.kbJwt, { publicKey: holderKey })
  if (!kbVerify.valid) return fail('KB_SIG_INVALID', kbVerify.error)

  const kbPayload = kbVerify.payload
  if (kbPayload.nonce !== opts.expectedNonce) {
    return fail('NONCE_MISMATCH', `KB nonce ${String(kbPayload.nonce)} !== r ${opts.expectedNonce}`)
  }
  const kbAud = Array.isArray(kbPayload.aud) ? kbPayload.aud[0] : kbPayload.aud
  if (kbAud !== opts.expectedAud) {
    return fail('AUD_MISMATCH', `KB aud ${String(kbAud)} !== resolver ${opts.expectedAud}`)
  }
  const sdHash = kbPayload.sd_hash as string | undefined
  if (sdHash !== presentationDigest) {
    return fail('SD_HASH_MISMATCH', `KB sd_hash ${String(sdHash)} !== SHA-256(presentation)`)
  }

  return {
    ok: true,
    vct,
    iss,
    claims,
    cnfJwk,
    cnfThumbprint,
    kb: { nonce: opts.expectedNonce, aud: opts.expectedAud, sdHash: presentationDigest },
    presentationDigest,
  }
}

/** The exact bytes the KB-JWT's `sd_hash` is computed over: `issuer-jwt~d1~…~dN~`. */
function sansKb(parsed: ParsedSdJwt): string {
  return [parsed.issuerJwt, ...parsed.disclosures, ''].join('~')
}
