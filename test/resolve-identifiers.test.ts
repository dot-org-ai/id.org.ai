/**
 * Pure-unit tests for the ported validators + DL path parser
 * (worker/resolve/identifiers.ts) and the conservative capture stamp
 * (worker/resolve/capture.ts).
 */
import { describe, it, expect } from 'vitest'
import {
  isVinShape,
  vinVerify,
  isGtinShape,
  mod10Verify,
  mod10CheckDigit,
  parseDlPath,
} from '../worker/resolve/identifiers'
import { buildCaptureStamp, stampResolve, BIZSTEP_RESOLVING, noopCaptureSink } from '../worker/resolve/capture'

describe('vinVerify - ISO 3779', () => {
  it('accepts a well-formed valid VIN', () => {
    expect(isVinShape('1HGCM82633A004352')).toBe(true)
    expect(vinVerify('1HGCM82633A004352').pass).toBe(true)
  })

  it('accepts the X check-digit VIN', () => {
    expect(vinVerify('1M8GDM9AXKP042788').pass).toBe(true)
  })

  it('rejects a wrong check digit (grammar still valid)', () => {
    expect(isVinShape('1HGCM82653A004352')).toBe(true)
    const r = vinVerify('1HGCM82653A004352')
    expect(r.pass).toBe(false)
    expect(r.expected).toBe('3')
    expect(r.got).toBe('5')
  })

  it('rejects VIN-alphabet violations (I/O/Q) at the grammar gate', () => {
    expect(isVinShape('1HGCM8263IA004352')).toBe(false)
    expect(isVinShape('1HGCM8263OA004352')).toBe(false)
    expect(isVinShape('1HGCM8263QA004352')).toBe(false)
  })

  it('rejects wrong length', () => {
    expect(isVinShape('1HGCM82633A00435')).toBe(false)
    expect(isVinShape('1HGCM82633A0043521')).toBe(false)
  })
})

describe('mod10Verify - GS1 GenSpecs §7.9', () => {
  it('accepts a valid GTIN-14', () => {
    expect(isGtinShape('09506000134352')).toBe(true)
    expect(mod10Verify('09506000134352').pass).toBe(true)
  })

  it('accepts a valid GTIN-13', () => {
    expect(mod10Verify('0360002914522').pass).toBe(true)
  })

  it('rejects a wrong check digit', () => {
    const r = mod10Verify('09506000134353')
    expect(r.pass).toBe(false)
    expect(r.expected).toBe(2)
    expect(r.got).toBe(3)
  })

  it('mod10CheckDigit matches the known body', () => {
    expect(mod10CheckDigit('0950600013435')).toBe(2)
  })

  it('isGtinShape rejects non-numeric and off-length', () => {
    expect(isGtinShape('12345')).toBe(false) // 5 digits
    expect(isGtinShape('0950600013435X')).toBe(false) // non-numeric
    expect(isGtinShape('09506000134')).toBe(false) // 11 digits (not 8/12/13/14)
    expect(isGtinShape('095060001343')).toBe(true) // 12 digits IS a valid GTIN length
  })
})

describe('parseDlPath - leftmost primary key /01[/21]', () => {
  it('parses bare /01/{gtin} as class grain', () => {
    const p = parseDlPath(['01', '09506000134352'])
    expect('error' in p).toBe(false)
    if ('error' in p) return
    expect(p.gtin).toBe('09506000134352')
    expect(p.serial).toBeUndefined()
  })

  it('parses /01/{gtin}/21/{serial} as instance grain', () => {
    const p = parseDlPath(['01', '09506000134352', '21', 'XYZ789'])
    expect('error' in p).toBe(false)
    if ('error' in p) return
    expect(p.serial).toBe('XYZ789')
    expect(p.qualifiers).toEqual([{ ai: '21', value: 'XYZ789' }])
  })

  it('tolerates an unknown trailing AI without changing grain', () => {
    const p = parseDlPath(['01', '09506000134352', '10', 'LOT42'])
    expect('error' in p).toBe(false)
    if ('error' in p) return
    expect(p.serial).toBeUndefined()
    expect(p.toleratedExtra).toBe(true)
  })

  it('rejects a non-01 primary key with CONFORMANCE', () => {
    const p = parseDlPath(['00', '123456789012345678'])
    expect('error' in p).toBe(true)
    if ('error' in p) expect(p.error).toBe('CONFORMANCE')
  })

  it('rejects a bad GTIN shape with CONFORMANCE', () => {
    const p = parseDlPath(['01', '123'])
    expect('error' in p).toBe(true)
    if ('error' in p) expect(p.error).toBe('CONFORMANCE')
  })

  it('rejects a dangling segment with CONFORMANCE', () => {
    const p = parseDlPath(['01', '09506000134352', '21'])
    expect('error' in p).toBe(true)
  })
})

describe('capture stamp - conservative, no-op sink', () => {
  it('builds the resolve stamp shape with the draft digital bizStep', () => {
    const s = buildCaptureStamp('https://id.org.ai/vin/1HGCM82633A004352', 'anon')
    expect(s.type).toBe('ObjectEvent')
    expect(s.action).toBe('OBSERVE')
    expect(s['why.bizStep']).toBe(BIZSTEP_RESOLVING)
    expect(BIZSTEP_RESOLVING).toBe('https://gs1.org.ai/cbv/BizStep-resolving')
    expect(s['who.principal']).toBe('anon')
    expect(s.provisional).toBe(true)
    expect(s.epcList).toEqual(['https://id.org.ai/vin/1HGCM82633A004352'])
  })

  it('stampResolve returns the stamp and the default sink is a no-op', () => {
    const s = stampResolve('https://id.org.ai/01/09506000134352', 'human_abc')
    expect(s['who.principal']).toBe('human_abc')
    // noop sink swallows without throwing
    expect(() => noopCaptureSink.emit(s)).not.toThrow()
  })

  it('a throwing sink never breaks the read', () => {
    const boom = {
      emit() {
        throw new Error('sink down')
      },
    }
    expect(() => stampResolve('https://id.org.ai/vin/x', 'anon', boom)).not.toThrow()
  })
})
