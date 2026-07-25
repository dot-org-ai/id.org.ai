/**
 * Ordered credential-gate enforcement (ADR 0012 M8 → ADR 0016 C3) — the
 * pure decision core behind POST /credentials/enforce.
 */

import { describe, it, expect } from 'vitest'
import {
  CREDENTIAL_GATES_V1,
  supplyGateFor,
  demandGateFor,
  enforceOrdered,
} from '../src/sdk/credential'
import type { VerificationResult, VerifyPrincipal } from '../src/sdk/credential'

const HUMAN: VerifyPrincipal = { id: 'user_pat', workerType: 'human' }
const AGENT: VerifyPrincipal = { id: 'agent_1', workerType: 'agent' }

function makeVerification(overrides: Partial<VerificationResult> = {}): VerificationResult {
  return {
    live: true,
    goodStanding: true,
    holder: { name: 'Pat', kind: 'human', id: '99999' },
    reps: [],
    source: { mode: 'registry', registry: 'uspto-oed', sourceClass: 'public-lookup', status: 'real' },
    freshness: { cached: false, cadence: { kind: 'per-query' }, staleBeyondCadence: false },
    checkedAt: '2026-07-25T12:00:00Z',
    verdict: 'registry-verified',
    registryStatus: 'Active',
    satisfiesActClass: true,
    ...overrides,
  }
}

describe('the gates table', () => {
  it('holds file.patent and cm-ecf as objects carrying a jurisdiction — never bools', () => {
    expect(supplyGateFor('file.patent')?.requiresSigner).toEqual({
      jurisdiction: 'US',
      credentialType: 'uspto-registered',
      registry: 'uspto-oed',
    })
    expect(demandGateFor('cm-ecf')?.requiresAccess).toEqual({ jurisdiction: 'US', entitlementType: 'cm-ecf-access' })
  })

  it('answers null for unratified acts and upstreams', () => {
    expect(supplyGateFor('file.wizardry')).toBeNull()
    expect(demandGateFor('narnia')).toBeNull()
  })

  it('is deep-frozen', () => {
    expect(() => {
      ;(CREDENTIAL_GATES_V1.acts as Record<string, unknown>)['file.new'] = {}
    }).toThrow()
  })
})

describe('enforceOrdered — the ratified order, first denial wins', () => {
  it('stops an agent signer at humanSigner BEFORE any credential math', () => {
    // The agent also has no credential — but humanSigner must be the gate named.
    const decision = enforceOrdered({ act: 'file.patent', signer: AGENT, signerVerification: null })
    expect(decision).toMatchObject({ denied: true, gate: 'humanSigner' })
  })

  it('denies an uncredentialed human at requiresSigner, echoing the gate as an object with a jurisdiction', () => {
    const decision = enforceOrdered({ act: 'file.patent', signer: HUMAN, signerVerification: null })
    expect(decision.denied).toBe(true)
    if (!decision.denied) return
    expect(decision.gate).toBe('requiresSigner')
    expect(decision.required).toMatchObject({ jurisdiction: 'US' })
  })

  it('passes a human signer with fresh registry-verified evidence', () => {
    const decision = enforceOrdered({ act: 'file.patent', signer: HUMAN, signerVerification: makeVerification() })
    expect(decision).toEqual({ denied: false, gates: ['humanSigner', 'requiresSigner'] })
  })

  it('NEVER lets holder-attested evidence clear the supply gate (ADR 0018 R4)', () => {
    const decision = enforceOrdered({
      act: 'file.patent',
      signer: HUMAN,
      signerVerification: makeVerification({ verdict: 'holder-attested', satisfiesActClass: false }),
    })
    expect(decision.denied).toBe(true)
    if (!decision.denied) return
    expect(decision.gate).toBe('requiresSigner')
    expect(decision.reason).toContain('holder-attested')
  })

  it('denies evidence with a freshness failure — a cached pass is no pass', () => {
    const decision = enforceOrdered({
      act: 'file.patent',
      signer: HUMAN,
      signerVerification: makeVerification({ satisfiesActClass: false, freshnessFailure: 'cached-for-act' }),
    })
    expect(decision.denied).toBe(true)
    if (!decision.denied) return
    expect(decision.gate).toBe('requiresSigner')
    expect(decision.reason).toContain('cached-for-act')
  })

  it('denies live-but-not-good-standing evidence', () => {
    const decision = enforceOrdered({
      act: 'file.patent',
      signer: HUMAN,
      signerVerification: makeVerification({ goodStanding: false }),
    })
    expect(decision).toMatchObject({ denied: true, gate: 'requiresSigner' })
  })

  it('surfaces the evidence cure on denial (unverifiable-by-registry path)', () => {
    const decision = enforceOrdered({
      act: 'file.patent',
      signer: HUMAN,
      signerVerification: makeVerification({
        verdict: 'unverifiable-by-registry',
        live: false,
        goodStanding: false,
        satisfiesActClass: false,
        cure: { action: 'connect-source', channel: 'uspto-oed', note: 'bind the source' },
      }),
    })
    expect(decision.denied).toBe(true)
    if (!decision.denied) return
    expect(decision.cure).toMatchObject({ action: 'connect-source' })
  })

  it('denies an unentitled principal at requiresAccess with the jurisdiction object', () => {
    const decision = enforceOrdered({ upstream: 'cm-ecf', principal: HUMAN, principalEntitled: false })
    expect(decision.denied).toBe(true)
    if (!decision.denied) return
    expect(decision.gate).toBe('requiresAccess')
    expect(decision.required).toMatchObject({ jurisdiction: 'US' })
  })

  it('passes an entitled principal at requiresAccess', () => {
    const decision = enforceOrdered({ upstream: 'cm-ecf', principal: HUMAN, principalEntitled: true })
    expect(decision).toEqual({ denied: false, gates: ['requiresAccess'] })
  })

  it('walks supply THEN demand when both are named — supply denial wins first', () => {
    const decision = enforceOrdered({
      act: 'file.patent',
      upstream: 'cm-ecf',
      signer: HUMAN,
      principal: HUMAN,
      signerVerification: null,
      principalEntitled: true,
    })
    expect(decision).toMatchObject({ denied: true, gate: 'requiresSigner' })
  })

  it('denies an unratified act with a typed reason', () => {
    const decision = enforceOrdered({ act: 'file.wizardry', signer: HUMAN })
    expect(decision.denied).toBe(true)
    if (!decision.denied) return
    expect(decision.reason).toContain('file.wizardry')
  })
})
