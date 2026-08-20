/**
 * dlvp/receipt.ts — the ISO/IEC 27560 consent receipt as an addressable,
 * revocable Verifiable Credential (lens-B §2.1, SYNTHESIS C6).
 *
 * The receipt is minted as a signed VC (vct = https://id.org.ai/vct/consent-
 * receipt), `cnf`-bound to the consumer's confirmation key, carrying the DLVP
 * binding block (nonce r, epcisEventId, both presentation digests, the provisional
 * consent bizStep). It is addressed by a GRAI (AI 8003) so it resolves through the
 * EXISTING /8003/{grai} door, and its status rides a Token Status List (store.ts).
 *
 * `piiPrincipalId` is NEVER a raw identity — it is the consumer cnf-jwk thumbprint
 * (a scoped pseudonym, lens-B §2.6). Linkable within a brand, not across (v1;
 * BBS+ cross-show unlinkability is DEFERRED).
 *
 * ┌─ DEFERRED + TICKETED (bd model-gap) ──────────────────────────────────────┐
 * │ • The receipt as a cnf-bound, TRADEABLE instrument with full Token-Status- │
 * │   List revocation semantics + metered/decaying grants — v1 is single-grant │
 * │   + revocable (in-memory status), not metered. id.org.ai-ac3 / id.org.ai-56v.│
 * │ • The GRAI registry WRITE so /8003/{grai} returns the RECEIPT itself       │
 * │   (v1: the GRAI resolves through the door to the generic key doc; the      │
 * │   receipt VC is fetched via GET /dlvp/receipt/:grai). id.org.ai-56v.        │
 * │ • Real jurisdiction/law mapping — v1 stamps a provisional jurisdiction.    │
 * └────────────────────────────────────────────────────────────────────────────┘
 */

import { mod10CheckDigit } from '../resolve/identifiers'
import { BIZSTEP_CONSENTING } from './bizsteps'
import type { DlvpSigner } from './nonce'
import type { DlvpStore } from './store'
import type { JWK } from '../../src/sdk/oauth/jwt-verify'
import type {
  Iso27560Receipt,
  ConsentPurpose,
  DlvpBinding,
  MutualDisclosureReceipt,
  Predicate,
} from './protocol'

export const CONSENT_RECEIPT_VCT = 'https://id.org.ai/vct/consent-receipt'
export const RESOLVER_ORIGIN = 'https://id.org.ai'
/** v1 provisional jurisdiction stamp (real law mapping deferred). */
export const PROVISIONAL_JURISDICTION = 'provisional/unspecified'

/** Mint a well-formed, resolvable GRAI (AI 8003): 13-digit body + mod-10 check + serial. */
export function mintGrai(): string {
  const body = Array.from({ length: 13 }, () => Math.floor(Math.random() * 10)).join('')
  const core = body + String(mod10CheckDigit(body))
  const serialChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
  const serialBytes = new Uint8Array(12)
  crypto.getRandomValues(serialBytes)
  const serial = Array.from(serialBytes, (b) => serialChars[b % serialChars.length]).join('')
  return `${core}${serial}`
}

/** Render a predicate as a human piiCategory label for the receipt. */
function predicateLabel(p: Predicate): string {
  if (p.op === 'gte' && p.value !== undefined) return `${p.claim}>=${p.value}`
  if (p.op === 'eq' && p.value !== undefined) return `${p.claim}=${p.value}`
  return p.claim
}

/**
 * Build the ISO/IEC 27560 consent-receipt payload. The disclosed predicates
 * become the piiCategories; the consumer pseudonym is the cnf-jwk thumbprint.
 */
export function buildIso27560(params: {
  consentReceiptID: string
  brandController: string
  consumerPseudonym: string
  consumerAsk: Predicate[]
  brandAsk: Predicate[]
  consentTimestamp?: string
}): Iso27560Receipt {
  const purposes: ConsentPurpose[] = [
    {
      purpose: 'mutual-selective-disclosure',
      purposeCategory: 'consented-verified-edge',
      consentType: 'EXPLICIT',
      // What the consumer disclosed to the brand (the brand's asks) + what the
      // brand disclosed to the consumer (the consumer's asks) — both recorded.
      piiCategories: [...params.brandAsk.map(predicateLabel), ...params.consumerAsk.map(predicateLabel)],
      primaryPurpose: true,
      termination: 'on-revocation-or-grant-expiry',
      thirdPartyDisclosure: false,
    },
  ]
  return {
    version: 'ISO/IEC 27560:2023 (provisional profile)',
    jurisdiction: PROVISIONAL_JURISDICTION,
    consentTimestamp: params.consentTimestamp ?? new Date().toISOString(),
    collectionMethod: 'dlvp-symmetric-presentation',
    consentReceiptID: params.consentReceiptID,
    piiControllers: [params.brandController],
    piiPrincipalId: params.consumerPseudonym,
    services: [{ service: 'id.org.ai-dlvp', purposes }],
    sensitive: false,
    spiCat: [],
  }
}

/**
 * Mint the MutualDisclosureReceipt: build the ISO 27560 payload, reserve a status
 * bit, sign the receipt VC, and persist it in the store. Returns the full
 * addressable, revocable receipt.
 */
export async function mintReceipt(params: {
  signer: DlvpSigner
  store: DlvpStore
  brandController: string
  consumerCnfJwk: JWK
  consumerPseudonym: string
  consumerAsk: Predicate[]
  brandAsk: Predicate[]
  nonce: string
  epcisEventId: string
  consumerPresentationDigest: string
  brandPresentationDigest: string
  resolverOrigin?: string
  expiresIn?: number
}): Promise<MutualDisclosureReceipt> {
  const origin = params.resolverOrigin ?? RESOLVER_ORIGIN
  const grai = mintGrai()
  const digitalLink = `${origin}/8003/${grai}`
  const statusRef = params.store.reserveStatus(grai)

  const iso27560 = buildIso27560({
    consentReceiptID: grai,
    brandController: params.brandController,
    consumerPseudonym: params.consumerPseudonym,
    consumerAsk: params.consumerAsk,
    brandAsk: params.brandAsk,
  })

  const dlvp: DlvpBinding = {
    nonce: params.nonce,
    epcisEventId: params.epcisEventId,
    consumerPresentationDigest: params.consumerPresentationDigest,
    brandPresentationDigest: params.brandPresentationDigest,
    bizStep: BIZSTEP_CONSENTING,
  }

  // The receipt VC claims (signed by the resolver's issuer key).
  const vcClaims: Record<string, unknown> = {
    sub: grai,
    vct: CONSENT_RECEIPT_VCT,
    cnf: { jwk: params.consumerCnfJwk },
    status: { status_list: { uri: statusRef.uri, idx: statusRef.idx } },
    iso27560,
    dlvp,
  }
  const vcJwt = await params.signer.sign(vcClaims, { expiresIn: params.expiresIn ?? 60 * 60 * 24 * 365 })

  const receipt: MutualDisclosureReceipt = {
    grai,
    digitalLink,
    vcJwt,
    iso27560,
    dlvp,
    status: statusRef,
  }
  params.store.put(receipt)
  return receipt
}
