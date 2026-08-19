/**
 * Pure-unit tests for the Phase-4 key-grammar expansion in
 * worker/resolve/identifiers.ts: CSET-82, the 17-expiry data-attribute grammar,
 * and parseDlKey over 00 SSCC / 414 GLN / 8004 GIAI / 8003 GRAI / 253 GDTI.
 *
 * Additive — the shipped resolve-identifiers.test.ts (parseDlPath / mod10 / VIN)
 * is untouched.
 */
import { describe, it, expect } from 'vitest'
import {
  parseDlKey,
  isCset82,
  isExpiryDate,
  mod10Verify,
  KEY_GRAMMAR,
  SUPPORTED_PRIMARY_KEYS,
} from '../worker/resolve/identifiers'

// Valid check-digit samples (computed from the ported mod-10).
const SSCC = '106141411234567897'
const GLN = '1234567890128'
const GRAI_CORE = '01234567890128' // 14-digit core, no serial
const GDTI_CORE = '1234567890128' // 13-digit core, no serial

describe('CSET-82 charset', () => {
  it('accepts alphanumerics and the CSET-82 symbols', () => {
    expect(isCset82('ABC-123')).toBe(true)
    expect(isCset82("a!\"%&'()*+,-./:;<=>?_")).toBe(true)
  })
  it('rejects out-of-set chars and length violations', () => {
    expect(isCset82('has space')).toBe(false)
    expect(isCset82('back\\slash')).toBe(false)
    expect(isCset82('', 1)).toBe(false)
    expect(isCset82('toolong', 1, 3)).toBe(false)
  })
})

describe('AI 17 expiry data-attribute grammar (never a path qualifier)', () => {
  it('accepts YYMMDD with valid MM and DD (incl 00 end-of-month)', () => {
    expect(isExpiryDate('261231')).toBe(true)
    expect(isExpiryDate('260600')).toBe(true) // DD=00 end-of-month
  })
  it('rejects bad month/day and non-6-digit', () => {
    expect(isExpiryDate('261301')).toBe(false) // MM=13
    expect(isExpiryDate('260132')).toBe(false) // DD=32
    expect(isExpiryDate('2612')).toBe(false)
  })
})

describe('parseDlKey — 00 SSCC (logistic instance)', () => {
  it('parses a valid SSCC with a numeric core to check', () => {
    const p = parseDlKey(['00', SSCC])
    expect('error' in p).toBe(false)
    if ('error' in p) return
    expect(p.name).toBe('SSCC')
    expect(p.grain).toBe('instance')
    expect(p.checkDigit).toBe(true)
    expect(p.numericCore).toBe(SSCC)
    expect(mod10Verify(p.numericCore!).pass).toBe(true)
  })
  it('rejects a wrong length', () => {
    const p = parseDlKey(['00', '123'])
    expect('error' in p).toBe(true)
    if ('error' in p) expect(p.error).toBe('CONFORMANCE')
  })
})

describe('parseDlKey — 414 GLN (place)', () => {
  it('parses a valid GLN', () => {
    const p = parseDlKey(['414', GLN])
    expect('error' in p).toBe(false)
    if ('error' in p) return
    expect(p.grain).toBe('place')
    expect(mod10Verify(p.numericCore!).pass).toBe(true)
  })
})

describe('parseDlKey — 8004 GIAI (asset, NO check digit)', () => {
  it('parses a CSET-82 GIAI and asserts it carries no check digit', () => {
    const p = parseDlKey(['8004', 'ASSET-001/A'])
    expect('error' in p).toBe(false)
    if ('error' in p) return
    expect(p.grain).toBe('asset')
    expect(p.checkDigit).toBe(false)
    expect(p.numericCore).toBeUndefined()
  })
  it('rejects a value over 30 chars', () => {
    const p = parseDlKey(['8004', 'A'.repeat(31)])
    expect('error' in p).toBe(true)
  })
})

describe('parseDlKey — 8003 GRAI (asset class / instance)', () => {
  it('class grain when only the 14-digit core is present', () => {
    const p = parseDlKey(['8003', GRAI_CORE])
    expect('error' in p).toBe(false)
    if ('error' in p) return
    expect(p.grain).toBe('asset')
    expect(p.serial).toBeUndefined()
    expect(mod10Verify(p.numericCore!).pass).toBe(true)
  })
  it('instance grain when a serial trails the core', () => {
    const p = parseDlKey(['8003', GRAI_CORE + 'SER1'])
    expect('error' in p).toBe(false)
    if ('error' in p) return
    expect(p.grain).toBe('instance')
    expect(p.serial).toBe('SER1')
    expect(p.numericCore).toBe(GRAI_CORE)
  })
  it('rejects a serial over 16 chars', () => {
    const p = parseDlKey(['8003', GRAI_CORE + 'S'.repeat(17)])
    expect('error' in p).toBe(true)
  })
})

describe('parseDlKey — 253 GDTI (document class / instance)', () => {
  it('class grain with the 13-digit core', () => {
    const p = parseDlKey(['253', GDTI_CORE])
    expect('error' in p).toBe(false)
    if ('error' in p) return
    expect(p.grain).toBe('document')
    expect(p.serial).toBeUndefined()
  })
  it('instance grain with a trailing serial', () => {
    const p = parseDlKey(['253', GDTI_CORE + 'DOC42'])
    expect('error' in p).toBe(false)
    if ('error' in p) return
    expect(p.grain).toBe('instance')
    expect(p.serial).toBe('DOC42')
  })
})

describe('parseDlKey — rejections', () => {
  it('rejects an unsupported AI', () => {
    const p = parseDlKey(['9999', 'x'])
    expect('error' in p).toBe(true)
    if ('error' in p) expect(p.error).toBe('CONFORMANCE')
  })
  it('rejects a dangling trailing segment', () => {
    const p = parseDlKey(['00', SSCC, '10'])
    expect('error' in p).toBe(true)
  })
  it('tolerates an even trailing AI pair without changing grain', () => {
    const p = parseDlKey(['00', SSCC, '99', 'x'])
    expect('error' in p).toBe(false)
    if ('error' in p) return
    expect(p.toleratedExtra).toBe(true)
    expect(p.grain).toBe('instance')
  })
})

describe('key grammar table exports', () => {
  it('advertises the six supported primary keys', () => {
    expect(SUPPORTED_PRIMARY_KEYS).toEqual(['01', '00', '414', '8004', '8003', '253'])
    expect(Object.keys(KEY_GRAMMAR).sort()).toEqual(['00', '253', '414', '8003', '8004'].sort())
  })
})
