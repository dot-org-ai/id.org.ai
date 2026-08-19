/**
 * The bidirectional dual-leg OFFER schema + the C5 minConfidence gate. Asserts
 * the brand-pays-consumer default posture (value flows TO the discloser),
 * validateOffer's fence + shape checks, and confidenceSatisfied/offerAccepts
 * including the v1 narrowing that a minConfidence 4/5 OFFER can never clear.
 */
import { describe, it, expect } from 'vitest'
import {
  buildBrandPaysConsumerOffer,
  validateOffer,
  confidenceSatisfied,
  offerAccepts,
  V1_MAX_SETTLE_TIER,
  usdToMicros,
  type DualLegOffer,
} from '../worker/dlvp/offer'
import { OfferInstrumentFenced } from '../worker/dlvp/value-types'
import { BIZSTEP_CLEARING } from '../worker/dlvp/bizsteps'

const ANCHOR = '01/09506000134352/21/SER1'

function brandPaysConsumer(minConfidence = 1): DualLegOffer {
  return buildBrandPaysConsumerOffer({
    anchor: ANCHOR,
    consumerGives: { valueType: 'verified-attribute', attributes: [{ claim: 'owns', op: 'present' }] },
    brandGives: { valueType: 'micro-payment', amountMicros: usdToMicros(0.1), asset: 'USD' },
    minConfidence,
  })
}

describe('buildBrandPaysConsumerOffer (default regulatory posture)', () => {
  it('builds exactly two legs: consumer discloses, brand pays (value flows to the discloser)', () => {
    const o = brandPaysConsumer()
    expect(o.$type).toBe('DualLegOffer')
    expect(o.legs).toHaveLength(2)
    const consumer = o.legs.find((l) => l.party === 'consumer')!
    const brand = o.legs.find((l) => l.party === 'brand')!
    expect(consumer.give.valueType).toBe('verified-attribute')
    expect(brand.give.valueType).toBe('micro-payment')
    // The brand leg pays; the consumer leg discloses. Direction is derived.
    expect(brand.give).toMatchObject({ valueType: 'micro-payment', amountMicros: 100_000 })
    expect(o.bizStep).toBe(BIZSTEP_CLEARING)
    expect(o.draftSuperset).toBe(true)
  })

  it('fails closed if a leg names a fenced instrument', () => {
    expect(() =>
      buildBrandPaysConsumerOffer({
        anchor: ANCHOR,
        consumerGives: { valueType: 'verified-attribute', attributes: [{ claim: 'owns' }] },
        // @ts-expect-error deliberately fenced instrument
        brandGives: { valueType: 'provenance-share', amountMicros: 1 },
      }),
    ).toThrow(OfferInstrumentFenced)
  })
})

describe('validateOffer', () => {
  it('accepts a well-formed brand-pays-consumer OFFER', () => {
    expect(validateOffer(brandPaysConsumer())).toEqual({ ok: true })
  })

  it('rejects a wrong leg count', () => {
    const o = brandPaysConsumer()
    const bad = { ...o, legs: [o.legs[0]] } as unknown as DualLegOffer
    expect(validateOffer(bad)).toMatchObject({ ok: false, code: 'LEG_COUNT' })
  })

  it('rejects two legs for the same party', () => {
    const o = brandPaysConsumer()
    const bad = { ...o, legs: [o.legs[0], { ...o.legs[0] }] } as DualLegOffer
    expect(validateOffer(bad)).toMatchObject({ ok: false, code: 'PARTY_DUP' })
  })

  it('rejects a fenced instrument leg', () => {
    const o = brandPaysConsumer()
    const bad = {
      ...o,
      legs: [o.legs.find((l) => l.party === 'consumer')!, { party: 'brand', give: { valueType: 'option' } }],
    } as unknown as DualLegOffer
    expect(validateOffer(bad)).toMatchObject({ ok: false, code: 'INSTRUMENT_FENCED' })
  })

  it('rejects non-integer / negative micros', () => {
    const o = brandPaysConsumer()
    const brand = { party: 'brand' as const, give: { valueType: 'micro-payment' as const, amountMicros: 1.5 } }
    const bad = { ...o, legs: [o.legs.find((l) => l.party === 'consumer')!, brand] } as DualLegOffer
    expect(validateOffer(bad)).toMatchObject({ ok: false, code: 'BAD_MICROS' })
  })

  it('rejects an empty verified-attribute leg', () => {
    const o = brandPaysConsumer()
    const consumer = { party: 'consumer' as const, give: { valueType: 'verified-attribute' as const, attributes: [] } }
    const bad = { ...o, legs: [consumer, o.legs.find((l) => l.party === 'brand')!] } as DualLegOffer
    expect(validateOffer(bad)).toMatchObject({ ok: false, code: 'EMPTY_ATTRIBUTES' })
  })

  it('rejects an expired OFFER', () => {
    const o = { ...brandPaysConsumer(), expiry: new Date(Date.now() - 1000).toISOString() }
    expect(validateOffer(o)).toMatchObject({ ok: false, code: 'EXPIRED' })
  })

  it('rejects a minConfidence outside 1..5', () => {
    const o = { ...brandPaysConsumer(), minConfidence: 0 } as unknown as DualLegOffer
    expect(validateOffer(o)).toMatchObject({ ok: false, code: 'BAD_CONFIDENCE' })
  })
})

describe('C5 confidence gate', () => {
  it('confidenceSatisfied is a >= comparison', () => {
    expect(confidenceSatisfied(3, 3)).toBe(true)
    expect(confidenceSatisfied(3, 1)).toBe(true)
    expect(confidenceSatisfied(2, 3)).toBe(false)
  })

  it('offerAccepts gates on the OFFER minConfidence', () => {
    expect(offerAccepts(brandPaysConsumer(1), 3)).toBe(true)
    expect(offerAccepts(brandPaysConsumer(3), 3)).toBe(true)
    expect(offerAccepts(brandPaysConsumer(3), 2)).toBe(false)
  })

  it('an advertised minConfidence 4/5 is above the v1 settle ceiling (rung 3)', () => {
    // The OFFER is well-formed and advertises 1..5, but settlement caps at rung 3.
    expect(validateOffer(brandPaysConsumer(4))).toEqual({ ok: true })
    expect(V1_MAX_SETTLE_TIER).toBe(3)
    // Even a perfect rung-3 counter-verify cannot satisfy a minConfidence-4 OFFER.
    expect(offerAccepts(brandPaysConsumer(4), 3)).toBe(false)
  })
})
