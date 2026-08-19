/**
 * Coverage for buildConsentRequirements() — the id:consent linkset face the resolver
 * advertises in-band (Phase-5). Flagged untested by review; this asserts its shape,
 * the C5 minConfidence, the offerBindings→consumerAsk mapping, and the draft-superset
 * (non-ratified-GS1) marking.
 */
import { describe, it, expect } from 'vitest'
import { buildConsentRequirements } from '../worker/resolve/linkset'
import type { ResolvedManifest } from '../worker/registry/port'

const ANCHOR = 'https://id.org.ai/01/09506000134352'

describe('buildConsentRequirements (id:consent face)', () => {
  it('advertises DLVP/1 with an endpoint, C5 minConfidence, and the draft-superset marking', () => {
    const cr = buildConsentRequirements(ANCHOR)
    expect(cr.protocol).toBe('DLVP/1')
    expect(cr.method).toBe('POST')
    expect(cr.endpoint).toBeTruthy()
    expect(cr.anchor).toBe(ANCHOR)
    expect(cr.draftSuperset).toBe(true)
    expect(cr.minConfidence).toBe(1) // coupon-tier default (SYNTHESIS C5)
    // provisional bizStep — never a ratified GS1 CBV URI
    expect(cr.bizStep).toContain('gs1.org.ai/cbv/BizStep-')
    expect(cr.bizStep).not.toContain('ref.gs1.org')
  })

  it('defaults the consumer ask to owns-presence when no record is provisioned', () => {
    const cr = buildConsentRequirements(ANCHOR)
    expect(cr.consumerAsk).toEqual([{ claim: 'owns', op: 'present' }])
    expect(cr.brandOffer.length).toBeGreaterThan(0)
  })

  it('maps a provisioned record’s offerBindings to consumer presence-asks', () => {
    const manifest = { policy: { offerBindings: ['membership', 'age_over_18'] } } as unknown as ResolvedManifest
    const cr = buildConsentRequirements(ANCHOR, manifest)
    expect(cr.consumerAsk).toEqual([
      { claim: 'membership', op: 'present' },
      { claim: 'age_over_18', op: 'present' },
    ])
  })
})
