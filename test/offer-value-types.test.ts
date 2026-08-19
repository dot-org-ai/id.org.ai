/**
 * The Phase-6 VALUE-TYPE FENCE (Howey / EDPB). Every v1-allowed present-value
 * type passes; every fenced instrument (and any unknown literal) is rejected
 * fail-closed. Also asserts the naming fence: the wire literal is
 * `verified-attribute`, and "data as payment" / "pay with your data" never
 * appears as a value-type literal.
 */
import { describe, it, expect } from 'vitest'
import {
  ALLOWED_VALUE_TYPES,
  FORBIDDEN_VALUE_TYPES,
  isAllowedValueType,
  isForbiddenValueType,
  assertAllowedValueType,
  OfferInstrumentFenced,
  MICROS_PER_USD,
} from '../worker/dlvp/value-types'

describe('value-type fence: allowed present-value types', () => {
  it('permits exactly the three bilateral present-value types', () => {
    expect([...ALLOWED_VALUE_TYPES].sort()).toEqual(['credential-grant', 'micro-payment', 'verified-attribute'])
  })

  for (const t of ALLOWED_VALUE_TYPES) {
    it(`accepts ${t}`, () => {
      expect(isAllowedValueType(t)).toBe(true)
      expect(assertAllowedValueType(t)).toBe(t)
      expect(isForbiddenValueType(t)).toBe(false)
    })
  }
})

describe('value-type fence: forbidden instruments (Howey / pooled)', () => {
  for (const t of FORBIDDEN_VALUE_TYPES) {
    it(`rejects the instrument ${t} fail-closed`, () => {
      expect(isAllowedValueType(t)).toBe(false)
      expect(isForbiddenValueType(t)).toBe(true)
      expect(() => assertAllowedValueType(t)).toThrow(OfferInstrumentFenced)
    })
  }

  it('covers the whole instrument zoo the brief names', () => {
    // Sanity: the fence list contains the named forbidden instruments.
    for (const t of [
      'provenance-share',
      'option',
      'future',
      'attention-future',
      'bonding-curve',
      'consent-dividend',
      'liability-swap',
      'provenance-collateral',
      'auction-clearing',
      'mutual-credit',
      'running-tab',
    ]) {
      expect(isForbiddenValueType(t)).toBe(true)
    }
  })

  it('rejects any unknown/typo literal fail-closed', () => {
    for (const t of ['', 'money', 'payment', 'crypto', 'share', 'stock', 'data-as-payment', 'pay-with-your-data']) {
      expect(isAllowedValueType(t)).toBe(false)
      expect(() => assertAllowedValueType(t)).toThrow(OfferInstrumentFenced)
    }
  })

  it('the thrown fence error carries a typed code + the offending type', () => {
    try {
      assertAllowedValueType('option')
      throw new Error('should have thrown')
    } catch (e) {
      expect(e).toBeInstanceOf(OfferInstrumentFenced)
      expect((e as OfferInstrumentFenced).code).toBe('INSTRUMENT_FENCED')
      expect((e as OfferInstrumentFenced).valueType).toBe('option')
    }
  })
})

describe('naming fence (EDPB): the mechanism ships as verified-attribute', () => {
  it('the allowed literal is verified-attribute, NOT a data-as-payment phrase', () => {
    expect((ALLOWED_VALUE_TYPES as readonly string[]).includes('verified-attribute')).toBe(true)
    expect((ALLOWED_VALUE_TYPES as readonly string[]).includes('data-as-payment')).toBe(false)
    expect((ALLOWED_VALUE_TYPES as readonly string[]).includes('pay-with-your-data')).toBe(false)
    // And such phrasing is fenced, never accepted.
    expect(isAllowedValueType('data-as-payment')).toBe(false)
  })
})

describe('money law', () => {
  it('integer micros per USD', () => {
    expect(MICROS_PER_USD).toBe(1_000_000)
    expect(Number.isInteger(MICROS_PER_USD)).toBe(true)
  })
})
