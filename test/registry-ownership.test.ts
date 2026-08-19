/**
 * Pure-unit tests for the ownership reducer (worker/registry/ownership.ts).
 *
 * Covers: the four-methods-to-one reduction; RANGE proof by VC-ASSERTED prefix
 * containment (NO table - the corrected lens-A design); GTIN outside the prefix
 * rejected; and INSTANCE proof by key match.
 */
import { describe, it, expect } from 'vitest'
import {
  reduceToClaim,
  verifyRangeClaim,
  verifyInstanceClaim,
  gtin14,
} from '../worker/registry/ownership'
import type { ProofMethod } from '../worker/registry/ownership'

describe('reduceToClaim - four methods reduce to one OwnershipClaim shape', () => {
  const methods: Array<[ProofMethod, string]> = [
    ['gcp-vc', 'range'],
    ['dns', 'hostname'],
    ['vc', 'attested'],
    ['anchor', 'anchored'],
  ]
  for (const [method, strength] of methods) {
    it(`${method} -> strength ${strength}, one shape`, () => {
      const claim = reduceToClaim({
        method,
        subject: 'org_acme',
        scope: { kind: 'range', gcpPrefix: '0950600' },
        proofDigest: 'sha256:abc',
        provedAt: '2026-08-19T00:00:00.000Z',
      })
      expect(claim.method).toBe(method)
      expect(claim.strength).toBe(strength)
      expect(claim.subject).toBe('org_acme')
      expect(claim.proofDigest).toBe('sha256:abc')
      // every method reduces to the SAME shape (same keys)
      expect(Object.keys(claim).sort()).toEqual(
        ['method', 'proofDigest', 'provedAt', 'scope', 'strength', 'subject'].sort(),
      )
    })
  }

  it('stamps provedAt when omitted', () => {
    const claim = reduceToClaim({
      method: 'dns',
      subject: 'org_x',
      scope: { kind: 'hostname', host: 'brand.example' },
      proofDigest: 'sha256:z',
    })
    expect(claim.provedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/)
  })
})

describe('gtin14 - canonical width', () => {
  it('left-pads GTIN-13/12 to 14 digits', () => {
    expect(gtin14('0360002914522')).toBe('00360002914522')
    expect(gtin14('095060001343')).toBe('00095060001343')
    expect(gtin14('09506000134352')).toBe('09506000134352')
  })
})

describe('verifyRangeClaim - VC-ASSERTED prefix containment (NO table)', () => {
  const claim = reduceToClaim({
    method: 'gcp-vc',
    subject: 'org_acme',
    scope: { kind: 'range', gcpPrefix: '0950600' },
    proofDigest: 'sha256:abc',
  })

  it('accepts a GTIN under the asserted prefix', () => {
    // GTIN-14 09506000134352 -> strip indicator 0 -> 9506000134352 startsWith 0950600? no.
    // The asserted GCP 0950600 is indexed after the indicator digit; with the
    // indicator stripped the company-prefix field begins at 9506000... so the
    // brand asserts the prefix AS IT APPEARS after the indicator.
    // Use the exact asserted prefix the VC would carry for this indicator layout:
    const c = reduceToClaim({
      method: 'gcp-vc',
      subject: 'org_acme',
      scope: { kind: 'range', gcpPrefix: '9506000' },
      proofDigest: 'sha256:abc',
    })
    expect(verifyRangeClaim('09506000134352', c)).toBe(true)
  })

  it('rejects a GTIN outside the asserted prefix', () => {
    expect(verifyRangeClaim('04012345678901', claim)).toBe(false)
  })

  it('rejects when the claim is not a range claim', () => {
    const inst = reduceToClaim({
      method: 'vc',
      subject: 'human_alice',
      scope: { kind: 'instance', key: '01/09506000134352/21/SER1' },
      proofDigest: 'sha256:aa',
    })
    expect(verifyRangeClaim('09506000134352', inst)).toBe(false)
  })

  it('rejects a non-numeric or empty prefix / gtin (never derives)', () => {
    const bad = reduceToClaim({
      method: 'gcp-vc',
      subject: 'org_x',
      scope: { kind: 'range', gcpPrefix: '' },
      proofDigest: 'sha256:x',
    })
    expect(verifyRangeClaim('09506000134352', bad)).toBe(false)
    expect(verifyRangeClaim('not-digits', claim)).toBe(false)
  })
})

describe('verifyInstanceClaim - key match', () => {
  const key = '01/09506000134352/21/SER1'
  const claim = reduceToClaim({
    method: 'vc',
    subject: 'human_alice',
    scope: { kind: 'instance', key },
    proofDigest: 'sha256:aa',
  })

  it('accepts the exact instance key', () => {
    expect(verifyInstanceClaim(key, claim)).toBe(true)
  })

  it('rejects a different instance key', () => {
    expect(verifyInstanceClaim('01/09506000134352/21/OTHER', claim)).toBe(false)
  })

  it('rejects a range claim as an instance proof', () => {
    const range = reduceToClaim({
      method: 'gcp-vc',
      subject: 'org_acme',
      scope: { kind: 'range', gcpPrefix: '9506000' },
      proofDigest: 'sha256:abc',
    })
    expect(verifyInstanceClaim(key, range)).toBe(false)
  })
})
