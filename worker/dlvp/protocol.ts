/**
 * dlvp/protocol.ts — the DLVP v1 wire vocabulary (SYNTHESIS §3 / lens-B §1).
 *
 * DLVP = Digital Link Verifiable Presentation: a SYMMETRIC profile of OIDC4VP.
 * The novelty that ships in v1 is the SYMMETRY — one resolution nonce `r`, two
 * SD-JWT-VC presentations (consumer + brand), each key-bound to `r`, settled
 * ATOMICALLY against one EPCIS event, minting an ISO/IEC 27560 consent receipt
 * as an addressable, revocable VC.
 *
 * This module carries TYPES ONLY — no crypto, no I/O. The verifier lives in
 * sd-jwt.ts, the session binding in nonce.ts, the counter-join in
 * counter-verify.ts, the receipt in receipt.ts, and the HTTP surface in
 * worker/routes/dlvp.ts.
 *
 * ┌─ SCOPE (v1, bounded — SYNTHESIS D2) ──────────────────────────────────────┐
 * │ SHIPS: symmetric co-presentation, one nonce → two KB-bound presentations, │
 * │ one EPCIS event, the dual-verifier counter-join, the ISO 27560 receipt.   │
 * │ DEFERRED (each a bd model-gap): ZK set-membership, BBS+ unlinkable        │
 * │ multi-show, PSI/OPRF blind exchange, mDL/mdoc, the full OIDC4VP wallet     │
 * │ issuance flow, atomic disclosure↔VALUE settlement, real issuer trust      │
 * │ lists, persistent status-list store. See DEFERRALS.md / bd model-gaps.    │
 * └────────────────────────────────────────────────────────────────────────────┘
 */

import type { VerificationVerdict } from '../../src/sdk/credential/types'

// ── Predicates (the asked/offered claims) ───────────────────────────────────

/**
 * One predicate a party asks the counterparty to prove, or offers to prove.
 * A predicate names a claim and (optionally) the value/operator it must satisfy.
 * v1 evaluates equality/presence + numeric `>=` on disclosed SD-JWT claims;
 * richer predicate logic (ranges, set-membership, ZK) is DEFERRED.
 */
export interface Predicate {
  /** The disclosed claim name, e.g. 'owns', 'tier', 'age_over_18', 'genuine'. */
  claim: string
  /** Optional operator; default is presence/equality. */
  op?: 'eq' | 'gte' | 'present'
  /** Optional expected value for eq/gte. */
  value?: string | number | boolean
}

/** The consumer's ask list and the brand's offer/ask list are both Predicate[]. */
export type Ask = Predicate[]

// ── The session request (move 1): open a co-presentation over an identifier ──

/** POST /dlvp/session request body. */
export interface DlvpSessionRequest {
  /** The canonical DL identifier: "01/{gtin}/21/{serial}" | "01/{gtin}" | "vin/{vin}" | "8003/{grai}"… */
  identifier: string
  /** What the consumer asks the brand to prove. */
  consumerAsk: Ask
  /** What the brand offers to prove / asks the consumer (symmetric). */
  brandOffer?: Ask
}

/**
 * The CO-PRESENTATION-REQUEST — the STATELESS request-object JWT the resolver
 * signs (move 2). It carries the nonce `r` both parties bind their presentations
 * to. Stateless = no server-held half-state = NO new provisioned binding (RAILS).
 * These are the JWT claims; the wire form is the signed compact JWT string.
 */
export interface CoPresentationRequest {
  /** iss — the resolver origin (https://id.org.ai). */
  iss: string
  /** aud — the two counterparties (symmetric). */
  aud: string[]
  /** sub — the identifier under co-presentation. */
  sub: string
  /** nonce — the resolution nonce `r` (base64url, 256-bit). The binding anchor. */
  nonce: string
  /** epcisEventId — the id of the provisional EPCIS event `e` (r ⊆ e). */
  epcisEventId: string
  /** What the consumer asked. */
  consumerAsk: Ask
  /** What the brand asked/offered. */
  brandAsk: Ask
  /** The resolver origin each KB-JWT must set as its `aud`. */
  resolverAud: string
  /** exp / iat — RFC 7519, injected by the signer (short-lived, ~120s). */
  exp?: number
  iat?: number
}

// ── The settle request (move 3–5): the v1 synchronous atomic co-settle ───────

/** POST /dlvp/settle request body. */
export interface DlvpSettleRequest {
  /** The signed CO-PRESENTATION-REQUEST JWT returned from /dlvp/session. */
  session: string
  /** The consumer's SD-JWT-VC presentation (issuer-jwt~disc…~kb-jwt), bound to r. */
  consumerPresentation: string
  /** The brand's SD-JWT-VC presentation, bound to the same r. */
  brandPresentation: string
}

// ── The DLVP verdict (the C3 dual-verifier tier) ─────────────────────────────

/**
 * The DLVP-local verdict union. Layers the counter-verified tier ON TOP of the
 * shared credential VerificationVerdict WITHOUT touching the pinned credential
 * wire (specs/axp-acceptance.spec.json pins response SHAPE, not type names — the
 * new member is also added to the shared union additively in credential/types.ts
 * per the Phase-5 plan, but DLVP carries its own alias so the coupling is
 * explicit and local).
 *
 *   holder-presented-vc-counterverified — the holder presented a VC AND
 *   id.org.ai cross-checked it against the registry of record in the SAME round.
 *   Strictly stronger than either alone (C3). No wallet/issuer/registry mints it.
 */
export type DlvpVerdict = VerificationVerdict

export const DLVP_COUNTERVERIFIED: DlvpVerdict = 'holder-presented-vc-counterverified'

// ── The mutual-disclosure receipt (ISO/IEC 27560) ────────────────────────────

/** One purpose entry inside the receipt's services→purposes[] (ISO 27560). */
export interface ConsentPurpose {
  purpose: string
  purposeCategory: string
  consentType: 'EXPLICIT' | 'IMPLICIT'
  /** The disclosed predicates for this purpose (the pii/claim categories). */
  piiCategories: string[]
  primaryPurpose: boolean
  termination: string
  thirdPartyDisclosure: boolean
}

/**
 * The ISO/IEC 27560 consent-receipt payload (the substance minted into the VC).
 * `piiPrincipalId` is NEVER a raw identity — it is the consumer cnf-jwk
 * thumbprint (a scoped pseudonym), per lens-B §2.6.
 */
export interface Iso27560Receipt {
  version: string
  jurisdiction: string
  consentTimestamp: string
  collectionMethod: 'dlvp-symmetric-presentation'
  consentReceiptID: string
  /** The controller(s) — the brand party. */
  piiControllers: string[]
  /** The consumer's scoped pseudonym (cnf jwk thumbprint), never raw identity. */
  piiPrincipalId: string
  services: Array<{ service: string; purposes: ConsentPurpose[] }>
  sensitive: boolean
  spiCat: string[]
}

/** The DLVP binding block carried inside the minted receipt VC. */
export interface DlvpBinding {
  /** The resolution nonce r — appears in all four bind sites. */
  nonce: string
  epcisEventId: string
  /** SHA-256 digest (base64url) of the consumer's presented SD-JWT (sans KB). */
  consumerPresentationDigest: string
  brandPresentationDigest: string
  /** The provisional consent bizStep (non-ratified GS1). */
  bizStep: string
}

/** A Token-Status-List reference (v1: served/in-memory; persistent store DEFERRED). */
export interface StatusListRef {
  /** The status list URI. */
  uri: string
  /** The bit index this receipt occupies. */
  idx: number
  /** Current state (v1 in-memory). */
  status: 'valid' | 'revoked'
}

/**
 * The minted MutualDisclosureReceipt — the addressable, revocable VC.
 * `grai` is its AI-8003 Digital Link key (resolves through the existing door).
 * `vcJwt` is the signed receipt VC (vct = https://id.org.ai/vct/consent-receipt).
 */
export interface MutualDisclosureReceipt {
  grai: string
  /** The resolvable Digital Link URL for the receipt (existing /8003 door). */
  digitalLink: string
  vcJwt: string
  iso27560: Iso27560Receipt
  dlvp: DlvpBinding
  status: StatusListRef
}

// ── The settle response ──────────────────────────────────────────────────────

/** POST /dlvp/settle success response. */
export interface DlvpSettleResult {
  verdict: DlvpVerdict
  /** What the BRAND disclosed to the consumer (the consumer's satisfied asks). */
  disclosedToConsumer: Record<string, unknown>
  /** What the CONSUMER disclosed to the brand (the brand's satisfied asks). */
  disclosedToBrand: Record<string, unknown>
  receipt: {
    grai: string
    digitalLink: string
    vcJwt: string
    statusListRef: StatusListRef
  }
  /** The stamped EPCIS events (provisional bizSteps; no-op sink in v1). */
  epcis: Array<Record<string, unknown>>
}

/** The typed DLVP error (atomic-or-nothing: on any failure, NOTHING is recorded). */
export interface DlvpError {
  error: {
    code:
      | 'SESSION_INVALID'
      | 'SESSION_EXPIRED'
      | 'PRESENTATION_INVALID'
      | 'NONCE_MISMATCH'
      | 'AUD_MISMATCH'
      | 'SD_HASH_MISMATCH'
      | 'BAD_REQUEST'
      | 'RECEIPT_NOT_FOUND'
    /** Which side failed, when applicable. */
    side?: 'consumer' | 'brand'
    message: string
    hint: string
  }
}
