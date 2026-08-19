/**
 * DLVP C3 dual-verifier counter-join. A verified consumer VC is counter-checked
 * against the Phase-4 RegistryPort: subject-match + scope-consistency mints the
 * strictly-stronger holder-presented-vc-counterverified; otherwise it falls to
 * holder-attested (never fabricates a counter-match); an unprovisioned registry
 * stays holder-attested.
 */
import { describe, it, expect } from 'vitest'
import { counterVerify, extractOwnershipAssertion } from '../worker/dlvp/counter-verify'
import { MemoryRegistryPort } from '../worker/registry/memory'
import { emptyRegistryPort } from '../worker/registry/port'
import type { IdentifierRecord, OwnerRef, Linkset, PolicyRef } from '../worker/registry/port'
import type { SdJwtVerified } from '../worker/dlvp/sd-jwt'

const GTIN = '09506000134352'
const INSTANCE_KEY = `01/${GTIN}/21/SER1`

/** A minimal verified-presentation stub (counterVerify reads only .claims). */
function pres(claims: Record<string, unknown>): SdJwtVerified {
  return {
    ok: true,
    vct: 'https://id.org.ai/vct/ownership',
    iss: 'https://issuer.example',
    claims,
    cnfJwk: { kty: 'EC' },
    cnfThumbprint: 'tp-consumer',
    kb: { nonce: 'r', aud: 'https://id.org.ai', sdHash: 'h' },
    presentationDigest: 'd',
  }
}

function instanceRegistry() {
  const policy: PolicyRef = { id: 'pol', tier: 0, cacheable: true, existenceNeutral: true }
  const owner: OwnerRef = {
    ownerId: 'human_alice',
    claim: {
      method: 'vc',
      subject: 'human_alice',
      scope: { kind: 'instance', key: INSTANCE_KEY },
      proofDigest: 'sha256:x',
      provedAt: '2026-08-19T00:00:00.000Z',
      strength: 'attested',
    },
    scope: { kind: 'instance', key: INSTANCE_KEY },
  }
  const linkset: Linkset = { id: 'ls', defaultLink: 'gs1:pip', links: [] }
  const record: IdentifierRecord = {
    key: INSTANCE_KEY,
    grain: 'instance',
    canonicalId: 'inst_1',
    ownerRef: 'human_alice',
    linksetRef: 'ls',
    defaultLink: 'gs1:pip',
    policyRef: 'pol',
    provenance: { proofId: 'p', provedAt: '2026-08-19T00:00:00.000Z', method: 'vc' },
    etag: 'W/"1"',
    updatedAt: '2026-08-19T00:00:00.000Z',
  }
  return new MemoryRegistryPort({ identifier: [record], owner: [owner], linkset: [linkset], policy: [policy] })
}

describe('extractOwnershipAssertion', () => {
  it('reads owner_subject + owns (instance) and gcp (range)', () => {
    expect(extractOwnershipAssertion({ owner_subject: 'human_alice', owns: INSTANCE_KEY })).toEqual({
      subject: 'human_alice',
      scope: { kind: 'instance', key: INSTANCE_KEY },
    })
    expect(extractOwnershipAssertion({ owner_subject: 'org_acme', gcp: '9506000' })).toEqual({
      subject: 'org_acme',
      scope: { kind: 'range', gcpPrefix: '9506000' },
    })
    expect(extractOwnershipAssertion({ tier: 2 })).toEqual({ subject: undefined, scope: undefined })
  })
})

describe('counterVerify', () => {
  it('subject + scope match the registry owner -> holder-presented-vc-counterverified', async () => {
    const res = await counterVerify({
      presentation: pres({ owner_subject: 'human_alice', owns: INSTANCE_KEY }),
      identifier: INSTANCE_KEY,
      grain: 'instance',
      registry: instanceRegistry(),
    })
    expect(res.verdict).toBe('holder-presented-vc-counterverified')
    expect(res.owner).toBe('human_alice')
    expect(res.registryStrength).toBe('attested')
    expect(res.rung).toBe(3)
  })

  it('subject mismatch -> holder-attested (never fabricates a counter-match)', async () => {
    const res = await counterVerify({
      presentation: pres({ owner_subject: 'human_mallory', owns: INSTANCE_KEY }),
      identifier: INSTANCE_KEY,
      grain: 'instance',
      registry: instanceRegistry(),
    })
    expect(res.verdict).toBe('holder-attested')
    expect(res.owner).toBe('human_alice')
  })

  it('scope inconsistent with the registry claim -> holder-attested', async () => {
    const res = await counterVerify({
      presentation: pres({ owner_subject: 'human_alice', owns: `01/${GTIN}/21/DIFFERENT` }),
      identifier: INSTANCE_KEY,
      grain: 'instance',
      registry: instanceRegistry(),
    })
    expect(res.verdict).toBe('holder-attested')
  })

  it('unprovisioned registry -> holder-attested (VC verified, not registry-counter-checked)', async () => {
    const res = await counterVerify({
      presentation: pres({ owner_subject: 'human_alice', owns: INSTANCE_KEY }),
      identifier: INSTANCE_KEY,
      grain: 'instance',
      registry: emptyRegistryPort(),
    })
    expect(res.verdict).toBe('holder-attested')
    expect(res.note).toContain('not provisioned')
  })

  it('a VC with no ownership assertion -> holder-attested at rung 1', async () => {
    const res = await counterVerify({
      presentation: pres({ tier: 2 }),
      identifier: INSTANCE_KEY,
      grain: 'instance',
      registry: instanceRegistry(),
    })
    expect(res.verdict).toBe('holder-attested')
    expect(res.rung).toBe(1)
  })
})
