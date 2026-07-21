/**
 * Stable token-verification primitive for id.org.ai.
 *
 * This is the canonical seam that builder.domains (and other .ax surfaces)
 * call to turn an id.org.ai-issued JWT into a verified identity:
 *
 *     env.AUTH.verifyToken(token) -> { valid, identity? , error? }
 *
 * It is a thin wrapper over the already-shipped JWT verifier in
 * `../oauth/jwt-verify` (`verifyJWT`), which performs full JWT validation:
 *   - RS256/ES* signature verification via Web Crypto
 *   - exp / nbf / iat claim checks (with clock tolerance)
 *   - issuer check
 *   - audience check (only when an expected audience is supplied)
 *
 * This module does NOT re-implement any of those checks — it selects the
 * correct signing key (by `kid`, with key-rotation fallback), delegates the
 * cryptographic + claim validation to `verifyJWT`, and then projects the
 * verified payload onto a stable `VerifiedIdentity` shape. On any failure it
 * returns `{ valid: false, error }` and never throws.
 */

import { verifyJWT, decodeJWT, type JWTPayload } from '../oauth/jwt-verify'
import type { JWKS, JWKSPublicKey } from '../jwt/signing'
import { CANONICAL_AUTH_ORIGIN } from './index'

// ═══════════════════════════════════════════════════════════════════════════
// Public Types
// ═══════════════════════════════════════════════════════════════════════════

/**
 * The verified identity projected from an id.org.ai-issued token. Contains the
 * subject plus the claims a consumer (e.g. builder.domains) needs to authorize
 * a projected custom-domain page.
 */
export interface VerifiedIdentity {
  /** Subject — the identity id the token was issued for. Always present. */
  sub: string
  /** Space-delimited scope string, if the token carried a `scope` claim. */
  scope?: string
  /** Parsed scopes (from `scope` string or `scopes` array), if present. */
  scopes?: string[]
  /** Tenant / organisation id (from `tenant`, `org_id`, or `org.id`). */
  tenant?: string
  /** Agent id, if the token was minted for an agent (`agent_id` / `agent`). */
  agent?: string
  /** Organisation id (alias of `tenant`, kept for parity with AuthUser). */
  org?: string
  email?: string
  name?: string
  roles?: string[]
  permissions?: string[]
  /** Issuer that minted the token (validated to equal the expected issuer). */
  issuer?: string
  /** Audience the token was minted for, if any. */
  audience?: string | string[]
  /** The full, verified JWT payload — for consumers needing extra claims. */
  claims: JWTPayload
}

export type VerifyTokenResult =
  | { valid: true; identity: VerifiedIdentity; error?: undefined }
  | { valid: false; error: string; identity?: undefined }

export interface VerifyTokenOptions {
  /**
   * In-memory JWKS to verify against (e.g. `SigningKeyManager.getJWKS()`).
   * Preferred in the Worker to avoid a self-fetch to our own JWKS endpoint.
   */
  jwks?: JWKS
  /** A single pre-imported public key (alternative to `jwks`). */
  publicKey?: CryptoKey
  /** Remote JWKS URL (alternative to `jwks`/`publicKey`); fetched by verifyJWT. */
  jwksUrl?: string
  /** Expected issuer. Defaults to id.org.ai's canonical origin. */
  issuer?: string
  /**
   * Expected audience. When supplied, verifyJWT enforces that the token's
   * `aud` claim matches. When omitted, the audience is not constrained
   * (matches OAuth introspection behaviour for tokens without an `aud`).
   */
  audience?: string | string[]
  /** Clock tolerance in seconds for exp/nbf/iat (default: verifyJWT's 60). */
  clockTolerance?: number
}

// ═══════════════════════════════════════════════════════════════════════════
// Public API
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Verify an id.org.ai-issued JWT and project it onto a stable identity.
 *
 * Delegates all cryptographic + claim validation to `verifyJWT`. Never throws.
 */
export async function verifyToken(token: string, options: VerifyTokenOptions = {}): Promise<VerifyTokenResult> {
  // ── Input guard: malformed / empty tokens fail closed, no throw ──────────
  if (typeof token !== 'string' || token.trim() === '') {
    return { valid: false, error: 'Missing or empty token' }
  }

  const issuer = options.issuer ?? CANONICAL_AUTH_ORIGIN
  const { audience, clockTolerance } = options

  const baseOptions = {
    issuer,
    ...(audience !== undefined && { audience }),
    ...(clockTolerance !== undefined && { clockTolerance }),
  }

  try {
    // ── Path A: caller supplied a single public key or a remote JWKS URL ──
    // Delegate straight to verifyJWT — it owns key fetch + all checks.
    if (options.publicKey || options.jwksUrl) {
      const result = await verifyJWT(token, {
        ...baseOptions,
        ...(options.publicKey && { publicKey: options.publicKey }),
        ...(options.jwksUrl && { jwksUrl: options.jwksUrl }),
      })
      return projectResult(result, issuer)
    }

    // ── Path B: in-memory JWKS. Select key by kid, verify with verifyJWT. ─
    if (options.jwks) {
      const decoded = decodeJWT(token)
      if (!decoded) {
        return { valid: false, error: 'Invalid JWT format' }
      }

      const kid = decoded.header.kid
      const alg = decoded.header.alg
      const candidates = selectCandidateKeys(options.jwks.keys, kid)
      if (candidates.length === 0) {
        return { valid: false, error: 'No matching key found in JWKS' }
      }

      let lastError = 'Invalid signature'
      for (const jwk of candidates) {
        let publicKey: CryptoKey
        try {
          publicKey = await importPublicKey(jwk, alg)
        } catch {
          // Key can't be imported for this alg — try the next candidate.
          continue
        }

        const result = await verifyJWT(token, { ...baseOptions, publicKey })
        if (result.valid) {
          return projectResult(result, issuer)
        }

        // A signature failure means we picked the wrong key (rotation) — keep
        // trying. Any other failure (issuer/exp/audience) is authoritative:
        // the key was correct, the token is simply not acceptable.
        if (result.error === 'Invalid signature') {
          lastError = result.error
          continue
        }
        return projectResult(result, issuer)
      }

      return { valid: false, error: lastError }
    }

    return { valid: false, error: 'No verification key provided (jwks, publicKey, or jwksUrl required)' }
  } catch (err) {
    // Defensive: verifyJWT already returns errors rather than throwing, but the
    // seam must never throw at its callers (builder.domains projected request).
    return { valid: false, error: err instanceof Error ? err.message : 'Unknown error during verification' }
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// Internal Helpers
// ═══════════════════════════════════════════════════════════════════════════

/** Map verifyJWT's discriminated result onto VerifyTokenResult. */
function projectResult(
  result: Awaited<ReturnType<typeof verifyJWT>>,
  issuer: string,
): VerifyTokenResult {
  if (!result.valid) {
    return { valid: false, error: result.error }
  }
  const payload = result.payload
  if (!payload.sub || typeof payload.sub !== 'string') {
    // A signed token with no subject cannot identify anyone — fail closed.
    return { valid: false, error: 'Token missing subject (sub) claim' }
  }
  return { valid: true, identity: projectIdentity(payload, issuer) }
}

/** Project a verified JWT payload onto the stable VerifiedIdentity shape. */
function projectIdentity(payload: JWTPayload, issuer: string): VerifiedIdentity {
  const org = payload.org as { id?: string } | undefined
  const tenant =
    (typeof payload.tenant === 'string' ? payload.tenant : undefined) ??
    (typeof payload.org_id === 'string' ? (payload.org_id as string) : undefined) ??
    org?.id

  const scopeStr = typeof payload.scope === 'string' ? payload.scope : undefined
  const scopesArr = Array.isArray(payload.scopes)
    ? (payload.scopes as unknown[]).filter((s): s is string => typeof s === 'string')
    : scopeStr
      ? scopeStr.split(' ').filter(Boolean)
      : undefined

  const agent =
    (typeof payload.agent_id === 'string' ? (payload.agent_id as string) : undefined) ??
    (typeof payload.agent === 'string' ? (payload.agent as string) : undefined)

  return {
    sub: payload.sub as string,
    ...(scopeStr !== undefined && { scope: scopeStr }),
    ...(scopesArr !== undefined && { scopes: scopesArr }),
    ...(tenant !== undefined && { tenant, org: tenant }),
    ...(agent !== undefined && { agent }),
    ...(typeof payload.email === 'string' && { email: payload.email as string }),
    ...(typeof payload.name === 'string' && { name: payload.name as string }),
    ...(Array.isArray(payload.roles) && { roles: payload.roles as string[] }),
    ...(Array.isArray(payload.permissions) && { permissions: payload.permissions as string[] }),
    issuer: (payload.iss as string | undefined) ?? issuer,
    ...(payload.aud !== undefined && { audience: payload.aud }),
    claims: payload,
  }
}

/** Return JWKS keys matching `kid`, or all keys when there's no usable match. */
function selectCandidateKeys(keys: JWKSPublicKey[], kid: string | undefined): JWKSPublicKey[] {
  if (kid) {
    const matched = keys.filter((k) => k.kid === kid)
    if (matched.length > 0) return matched
  }
  // No kid, or no key advertised that kid — fall back to trying every key so
  // key rotation (multiple live keys) still verifies.
  return keys
}

/** Import an RSA public JWK into a CryptoKey usable for signature verify. */
async function importPublicKey(jwk: JWKSPublicKey, alg: string): Promise<CryptoKey> {
  // id.org.ai signs RS256; honour the token header's declared RSA hash so an
  // RS384/RS512 rollout keeps verifying without a code change.
  const effectiveAlg = alg || jwk.alg
  if (jwk.kty === 'RSA') {
    const hash = effectiveAlg === 'RS384' ? 'SHA-384' : effectiveAlg === 'RS512' ? 'SHA-512' : 'SHA-256'
    return crypto.subtle.importKey(
      'jwk',
      { kty: 'RSA', n: jwk.n, e: jwk.e, alg: jwk.alg, use: 'sig' },
      { name: 'RSASSA-PKCS1-v1_5', hash },
      false,
      ['verify'],
    )
  }
  throw new Error(`Unsupported key type for verification: ${jwk.kty}`)
}
