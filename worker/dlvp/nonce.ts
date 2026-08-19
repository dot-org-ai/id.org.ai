/**
 * dlvp/nonce.ts — the resolution nonce `r` + the STATELESS session request-object
 * (lens-B moves 1–2; the "one nonce" half of the symmetry).
 *
 * `r` is a 256-bit ephemeral random value (WebCrypto getRandomValues). A random
 * nonce is NOT a key and needs NO provisioned binding or issuer secret — it is
 * in-request and non-persisted, satisfying RAILS (session creds only).
 *
 * The CO-PRESENTATION-REQUEST is a request-object JWT SIGNED by the resolver's
 * existing signing key (the id.org.ai issuer key via SigningKeyManager) — so the
 * whole session is STATELESS: no server-held half-state, hence NO new provisioned
 * binding. In tests a session-generated RS256 key stands in (no live keys).
 *
 * THE FOUR-PLACE NONCE BINDING (what makes two presentations ONE event): `r`
 * appears in exactly four sites and all must agree at settle —
 *   (1) the signed session request-object `nonce`;
 *   (2) the provisional EPCIS event `dlvp.nonce` (r ⊆ e);
 *   (3) EACH side's KB-JWT `nonce`;
 *   (4) the minted receipt VC `dlvp.nonce`.
 * `nonceBindingHolds` asserts (1)===(2)===(3consumer)===(3brand).
 */

import { base64UrlEncode } from '../../src/sdk/oauth/pkce'
import {
  generateSigningKey,
  signJWT,
  verifyJWTWithKeyManager,
  type SigningKey,
  type SigningKeyManager,
} from '../../src/sdk/jwt/signing'
import { verifyJWT } from '../../src/sdk/oauth/jwt-verify'
import type { CoPresentationRequest, DlvpSessionRequest, Ask } from './protocol'
import type { DualLegOffer } from './offer'

export const RESOLVER_ORIGIN = 'https://id.org.ai'
/** Session request-object lifetime (short-lived — lens-B move 2). */
export const SESSION_TTL_SECONDS = 120

/** Mint the 256-bit resolution nonce `r` (base64url). */
export function mintNonce(): string {
  const bytes = new Uint8Array(32)
  crypto.getRandomValues(bytes)
  return base64UrlEncode(bytes.buffer as ArrayBuffer)
}

/** Mint the id of the provisional EPCIS event `e` (r ⊆ e). */
export function mintEventId(): string {
  return `epcis:${crypto.randomUUID()}`
}

/**
 * A minimal signer seam: sign arbitrary claims into a compact JWT, and verify one
 * back against our own key. Production wraps the DO-backed SigningKeyManager;
 * tests inject a session-generated RS256 key. Either way the session is stateless.
 */
export interface DlvpSigner {
  sign(claims: Record<string, unknown>, opts: { expiresIn: number }): Promise<string>
  verify(jwt: string): Promise<Record<string, unknown> | null>
}

/**
 * A session signer built from a freshly-generated RS256 key (test/dev default).
 * No live keys, no binding, no persistence — session creds only (RAILS).
 */
export async function createSessionSigner(issuer = RESOLVER_ORIGIN): Promise<DlvpSigner> {
  const key: SigningKey = await generateSigningKey()
  return signerFromKey(key, issuer)
}

/** Wrap a concrete SigningKey as a DlvpSigner (used by createSessionSigner). */
export function signerFromKey(key: SigningKey, issuer = RESOLVER_ORIGIN): DlvpSigner {
  return {
    async sign(claims, opts) {
      // signJWT injects iss/iat/exp; the request-object claims ride alongside.
      return signJWT(key, { sub: 'dlvp', ...claims }, { issuer, expiresIn: opts.expiresIn })
    },
    async verify(jwt) {
      const res = await verifyJWT(jwt, { publicKey: key.publicKey, issuer })
      return res.valid ? (res.payload as Record<string, unknown>) : null
    },
  }
}

/**
 * Wrap the DO-backed SigningKeyManager (the id.org.ai issuer key) as a
 * DlvpSigner — the PRODUCTION signer. Stateless: it signs/verifies the session
 * request-object with the estate's existing issuer key, so DLVP needs no new
 * provisioned binding.
 */
export function signerFromKeyManager(manager: SigningKeyManager, issuer = RESOLVER_ORIGIN): DlvpSigner {
  return {
    async sign(claims, opts) {
      return manager.sign({ sub: 'dlvp', ...claims }, { issuer, expiresIn: opts.expiresIn })
    },
    async verify(jwt) {
      return verifyJWTWithKeyManager(jwt, manager, { issuer })
    },
  }
}

/**
 * Build (unsigned) the CO-PRESENTATION-REQUEST claims for a session over one
 * identifier. The signer adds iss/iat/exp when it signs.
 */
export function buildCoPresentationRequest(
  req: DlvpSessionRequest,
  nonce: string,
  epcisEventId: string,
  parties: { consumer: string; brand: string },
  resolverOrigin = RESOLVER_ORIGIN,
): Omit<CoPresentationRequest, 'iat' | 'exp'> {
  const consumerAsk: Ask = req.consumerAsk ?? []
  const brandAsk: Ask = req.brandOffer ?? []
  return {
    iss: resolverOrigin,
    aud: [parties.consumer, parties.brand],
    sub: req.identifier,
    nonce,
    epcisEventId,
    consumerAsk,
    brandAsk,
    resolverAud: resolverOrigin,
    // Phase-6: fold the dual-leg OFFER into the SIGNED claims (tamper-proof terms).
    ...(req.offer ? { offer: req.offer } : {}),
  }
}

/** The four nonce sites that must agree at settle. */
export interface FourPlaceBind {
  sessionNonce: string
  eventNonce: string
  consumerKbNonce: string
  brandKbNonce: string
}

/** True iff the resolution nonce `r` agrees across all four bind sites. */
export function nonceBindingHolds(b: FourPlaceBind): boolean {
  return (
    typeof b.sessionNonce === 'string' &&
    b.sessionNonce.length > 0 &&
    b.sessionNonce === b.eventNonce &&
    b.eventNonce === b.consumerKbNonce &&
    b.consumerKbNonce === b.brandKbNonce
  )
}
