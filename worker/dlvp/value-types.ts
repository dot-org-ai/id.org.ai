/**
 * dlvp/value-types.ts — the Phase-6 VALUE-TYPE FENCE (Howey / EDPB).
 *
 * The dual-leg OFFER carries a `ValueLeg` per party. v1 permits BILATERAL
 * PRESENT-VALUE ONLY: a micro-payment, a credential-grant, or a verified
 * attribute presented AS the value. There is NO pooled/common-enterprise
 * instrument — no shares, options, futures, bonding curves — because a common
 * enterprise with an expectation of profit from others' efforts is the Howey
 * trigger (HYPOTHESES Q4). Those are a SEPARATE counsel-gated post-v1 track.
 *
 * ┌─ NAMING FENCE (EU EDPB Opinion 08/2024) — do NOT remove ──────────────────┐
 * │ The mechanism the brief calls "data-as-payment" ships on the wire as the   │
 * │ literal `verified-attribute`. The phrases "data as payment" / "pay with     │
 * │ your data" MUST NEVER appear in a field name, wire literal, or user-facing  │
 * │ string: the LANGUAGE is the regulatory risk, not the mechanism. The ISO     │
 * │ 27560 consent receipt (P5) is the compliance artifact.                     │
 * └────────────────────────────────────────────────────────────────────────────┘
 *
 * The id.org.ai worker does NOT import vin/apis, so MICROS_PER_USD is defined
 * locally (mirror of the estate integer-micros money law).
 */

/** Integer micros per USD — money is integer micros, never a float (estate law). */
export const MICROS_PER_USD = 1_000_000

/**
 * v1 ALLOWED value types — bilateral PRESENT-VALUE only. No common enterprise,
 * therefore no Howey investment contract.
 *   - micro-payment      : integer USD micros, brand→consumer by default.
 *   - credential-grant   : a VC minted to the counterparty (warranty/access/authenticity).
 *   - verified-attribute : an SD-JWT predicate presented AS the value (the
 *                          mechanism the brief calls "data-as-payment" — the wire
 *                          literal is `verified-attribute`, deliberately).
 */
export const ALLOWED_VALUE_TYPES = ['micro-payment', 'credential-grant', 'verified-attribute'] as const
export type AllowedValueType = (typeof ALLOWED_VALUE_TYPES)[number]

/** Back-compat alias: a value type on the wire is always an allowed type. */
export type ValueType = AllowedValueType

/**
 * v1 FORBIDDEN value types — every one is a pooled/common-enterprise or forward
 * instrument (Howey-positive or credit-risk), out of scope for Phase-6. Building
 * any of these is a SEPARATE counsel-gated post-v1 epic, NOT a gap to ticket.
 */
export const FORBIDDEN_VALUE_TYPES = [
  'provenance-share', // residual on future resale — Howey 4/4
  'option',
  'future',
  'intent-forward',
  'attention-future',
  'bonding-curve',
  'authenticity-bond',
  'consent-dividend', // data-cooperative equity
  'liability-swap',
  'provenance-collateral',
  'auction-clearing', // reverse disclosure auction — pooled price discovery
  'mutual-credit',
  'running-tab', // netted credit line — credit risk, not a single atomic clear
] as const
export type ForbiddenValueType = (typeof FORBIDDEN_VALUE_TYPES)[number]

/** True iff `t` is one of the three v1-allowed present-value types. */
export function isAllowedValueType(t: string): t is AllowedValueType {
  return (ALLOWED_VALUE_TYPES as readonly string[]).includes(t)
}

/** True iff `t` is one of the explicitly-fenced instrument types. */
export function isForbiddenValueType(t: string): t is ForbiddenValueType {
  return (FORBIDDEN_VALUE_TYPES as readonly string[]).includes(t)
}

/**
 * Thrown when an OFFER leg names a value type outside the v1 present-value fence
 * (every FORBIDDEN instrument, and any unknown literal). Fail-CLOSED.
 */
export class OfferInstrumentFenced extends Error {
  readonly code = 'INSTRUMENT_FENCED' as const
  readonly valueType: string
  constructor(valueType: string) {
    super(
      `value type '${valueType}' is outside the v1 present-value fence ` +
        `(allowed: ${ALLOWED_VALUE_TYPES.join(', ')}). Instruments are a counsel-gated post-v1 track.`,
    )
    this.name = 'OfferInstrumentFenced'
    this.valueType = valueType
  }
}

/**
 * Fail-closed guard: return the value type when allowed, else throw
 * OfferInstrumentFenced. Any non-allowed literal — every FORBIDDEN instrument and
 * any typo/unknown — is rejected.
 */
export function assertAllowedValueType(t: string): AllowedValueType {
  if (!isAllowedValueType(t)) throw new OfferInstrumentFenced(t)
  return t
}
