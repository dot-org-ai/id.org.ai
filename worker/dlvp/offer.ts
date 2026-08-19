/**
 * dlvp/offer.ts — the BIDIRECTIONAL dual-leg OFFER (SYNTHESIS §3 Phase-6,
 * lens-C economic design). A Phase-6 extension of the one-way AXP OFFER envelope:
 * two legs, one per party, each carrying what THAT party gives the counterparty.
 *
 * The OFFER travels INSIDE the signed co-presentation-request (nonce.ts folds it
 * into the session claims), so `minConfidence` and the value terms are tamper-
 * proof under the resolver's own signature. The settle-offer body carries only
 * the value-leg proof, never the terms.
 *
 * DEFAULT regulatory posture (bake-in): value flows TO the discloser — the brand
 * pays the consumer. Disclosure stays optional / granular / revocable / no-
 * detriment (the public identity doc still resolves on decline). US-first framing.
 *
 * ┌─ C5 possession-confidence ladder (SYNTHESIS C5) ──────────────────────────┐
 * │ minConfidence ADVERTISES tiers 1–5; settlement fail-closes above rung 3    │
 * │ (V1_MAX_SETTLE_TIER) because counter-verify caps at rung 3 today. An OFFER  │
 * │ with minConfidence 4 or 5 is a well-formed advertisement that can NEVER     │
 * │ clear in v1. Declared scope narrowing — bd model-gap id.org.ai-67g.         │
 * └────────────────────────────────────────────────────────────────────────────┘
 */

import { ID_VOC } from '../resolve/linkset'
import { BIZSTEP_CLEARING } from './bizsteps'
import { assertAllowedValueType, MICROS_PER_USD, type AllowedValueType } from './value-types'
import type { Predicate } from './protocol'

/** The C5 possession-confidence ladder. Advertise 1–5; counter-verify reaches ≤3 in v1. */
export type PossessionTier = 1 | 2 | 3 | 4 | 5

/** The rung ceiling settlement can actually clear at in v1 (counter-verify caps here). */
export const V1_MAX_SETTLE_TIER: PossessionTier = 3

/**
 * The value ONE leg transfers to the counterparty (discriminated on `valueType`).
 * `verified-attribute` references a P5-disclosed SD-JWT predicate AS the value.
 */
export type ValueLeg =
  | { valueType: 'micro-payment'; amountMicros: number; asset?: 'USD' }
  | { valueType: 'credential-grant'; vct: string; grantScope?: string }
  | { valueType: 'verified-attribute'; attributes: Predicate[] }

/** One leg of the OFFER: what `party` GIVES the counterparty. */
export interface OfferLeg {
  party: 'consumer' | 'brand'
  give: ValueLeg
  description?: string
}

/** The bidirectional dual-leg OFFER advertised on the id:offer linkset face. */
export interface DualLegOffer {
  $context: typeof ID_VOC
  $type: 'DualLegOffer'
  offerId: string
  /** The DL identifier this OFFER is advertised on. */
  anchor: string
  /** EXACTLY two legs — one per party (consumer + brand); direction is derived. */
  legs: [OfferLeg, OfferLeg]
  /** C5 gate: the possession rung the value at stake demands (coupon=1, warranty=3, resale/transfer=4–5). */
  minConfidence: PossessionTier
  /** ISO-8601 validThrough (quote@1 discipline — an expired OFFER never settles). */
  expiry: string
  /** Names the SettlementPort profile (mock in v1). */
  settlementProfile: string
  /** Provisional clearing bizStep (non-ratified GS1). */
  bizStep: string
  /** This is our openly-draft superset — no GS1 ratification claimed. */
  draftSuperset: true
}

/** Default settlement profile name (the mock/no-op port in v1). */
export const MOCK_SETTLEMENT_PROFILE = 'mock:v1'

/**
 * The C5 gate — pure and testable. An OFFER only clears when the proven rung
 * meets its minConfidence. (The settle path additionally fail-closes above
 * V1_MAX_SETTLE_TIER, so minConfidence 4/5 is unreachable in v1.)
 */
export function confidenceSatisfied(reachedRung: PossessionTier, minConfidence: PossessionTier): boolean {
  return reachedRung >= minConfidence
}

/** Alias reading naturally at the settle seam. */
export function offerAccepts(offer: DualLegOffer, reachedRung: PossessionTier): boolean {
  return confidenceSatisfied(reachedRung, offer.minConfidence)
}

/** Mint an opaque OFFER id. */
export function mintOfferId(): string {
  return `offer_${crypto.randomUUID()}`
}

/**
 * Build the DEFAULT regulatory posture OFFER: value flows TO the discloser
 * (brand pays consumer). `consumerGives` is what the consumer discloses (a
 * verified-attribute leg); `brandGives` is what the brand pays (micro-payment or
 * credential-grant). Fails closed if either leg names a fenced value type.
 */
export function buildBrandPaysConsumerOffer(params: {
  anchor: string
  consumerGives: ValueLeg
  brandGives: ValueLeg
  minConfidence?: PossessionTier
  offerId?: string
  expiry?: string
  settlementProfile?: string
}): DualLegOffer {
  // Fence both legs at construction (fail-closed).
  assertAllowedValueType(params.consumerGives.valueType)
  assertAllowedValueType(params.brandGives.valueType)
  return {
    $context: ID_VOC,
    $type: 'DualLegOffer',
    offerId: params.offerId ?? mintOfferId(),
    anchor: params.anchor,
    legs: [
      { party: 'consumer', give: params.consumerGives, description: 'the consumer discloses a verified attribute' },
      { party: 'brand', give: params.brandGives, description: 'the brand pays the discloser' },
    ],
    minConfidence: params.minConfidence ?? 1,
    expiry: params.expiry ?? new Date(Date.now() + 5 * 60_000).toISOString(),
    settlementProfile: params.settlementProfile ?? MOCK_SETTLEMENT_PROFILE,
    bizStep: BIZSTEP_CLEARING,
    draftSuperset: true,
  }
}

/** A typed OFFER validation outcome. */
export type OfferValidation = { ok: true } | { ok: false; code: OfferInvalidCode; reason: string }

export type OfferInvalidCode =
  | 'LEG_COUNT'
  | 'PARTY_DUP'
  | 'INSTRUMENT_FENCED'
  | 'BAD_MICROS'
  | 'EMPTY_ATTRIBUTES'
  | 'EXPIRED'
  | 'BAD_CONFIDENCE'

/**
 * Validate an OFFER: exactly two legs (one per party), every value type inside
 * the fence, micros are non-negative integers, verified-attribute legs are non-
 * empty, minConfidence in 1..5, and (when `now` given) not past expiry.
 * Pure — never throws; returns a typed outcome.
 */
export function validateOffer(o: DualLegOffer, now: number = Date.now()): OfferValidation {
  if (!Array.isArray(o.legs) || o.legs.length !== 2) {
    return { ok: false, code: 'LEG_COUNT', reason: 'an OFFER must carry exactly two legs (one per party)' }
  }
  const parties = new Set(o.legs.map((l) => l.party))
  if (parties.size !== 2 || !parties.has('consumer') || !parties.has('brand')) {
    return { ok: false, code: 'PARTY_DUP', reason: 'the two legs must be one consumer leg and one brand leg' }
  }
  if (!Number.isInteger(o.minConfidence) || o.minConfidence < 1 || o.minConfidence > 5) {
    return { ok: false, code: 'BAD_CONFIDENCE', reason: 'minConfidence must be an integer tier 1..5' }
  }
  for (const leg of o.legs) {
    if (!isAllowedLeg(leg.give)) {
      return {
        ok: false,
        code: 'INSTRUMENT_FENCED',
        reason: `leg '${leg.party}' names value type '${(leg.give as { valueType?: string }).valueType}' outside the present-value fence`,
      }
    }
    if (leg.give.valueType === 'micro-payment') {
      const m = leg.give.amountMicros
      if (!Number.isInteger(m) || m < 0) {
        return { ok: false, code: 'BAD_MICROS', reason: 'micro-payment amountMicros must be a non-negative integer' }
      }
    }
    if (leg.give.valueType === 'verified-attribute') {
      if (!Array.isArray(leg.give.attributes) || leg.give.attributes.length === 0) {
        return { ok: false, code: 'EMPTY_ATTRIBUTES', reason: 'a verified-attribute leg must reference at least one predicate' }
      }
    }
  }
  if (o.expiry) {
    const exp = Date.parse(o.expiry)
    if (!Number.isNaN(exp) && exp <= now) {
      return { ok: false, code: 'EXPIRED', reason: 'the OFFER validThrough has passed' }
    }
  }
  return { ok: true }
}

/** Present-value fence at the leg level (mirrors assertAllowedValueType without throwing). */
function isAllowedLeg(give: { valueType?: unknown }): give is ValueLeg {
  return typeof give?.valueType === 'string' && isAllowed(give.valueType)
}
function isAllowed(t: string): t is AllowedValueType {
  try {
    assertAllowedValueType(t)
    return true
  } catch {
    return false
  }
}

/** Convenience: a USD amount → integer micros (money law: integers only). */
export function usdToMicros(usd: number): number {
  return Math.round(usd * MICROS_PER_USD)
}
