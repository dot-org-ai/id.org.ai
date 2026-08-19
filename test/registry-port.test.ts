/**
 * Pure-unit tests for the registry PORT + the MemoryRegistryPort fixture
 * (worker/registry/port.ts + worker/registry/memory.ts).
 *
 * Covers: the honest emptyRegistryPort typed miss; seed -> lookup joining the
 * four independent-lifecycle records into one ResolvedManifest; class -> lot ->
 * instance policy inheritance; and instance-owner shadowing.
 */
import { describe, it, expect } from 'vitest'
import { emptyRegistryPort } from '../worker/registry/port'
import type {
  IdentifierRecord,
  OwnerRef,
  Linkset,
  PolicyRef,
} from '../worker/registry/port'
import { MemoryRegistryPort } from '../worker/registry/memory'

const classPolicy: PolicyRef = {
  id: 'pol_class',
  tier: 0,
  cacheable: true,
  existenceNeutral: true,
}

const brandOwner: OwnerRef = {
  ownerId: 'org_acme',
  claim: {
    method: 'gcp-vc',
    subject: 'org_acme',
    scope: { kind: 'range', gcpPrefix: '0950600' },
    proofDigest: 'sha256:deadbeef',
    provedAt: '2026-08-19T00:00:00.000Z',
    strength: 'range',
  },
  gcpPrefix: '0950600',
  scope: { kind: 'range', gcpPrefix: '0950600' },
}

const brandLinkset: Linkset = {
  id: 'ls_acme_class',
  links: [{ linkType: 'gs1:pip', href: 'https://acme.example/p/134352' }],
  defaultLink: 'gs1:pip',
}

const classRecord: IdentifierRecord = {
  key: '01/09506000134352',
  grain: 'class',
  canonicalId: 'product_xioNCf7',
  ownerRef: 'org_acme',
  linksetRef: 'ls_acme_class',
  defaultLink: 'gs1:pip',
  policyRef: 'pol_class',
  provenance: { proofId: 'proof_1', provedAt: '2026-08-19T00:00:00.000Z', method: 'gcp-vc' },
  etag: 'W/"v1"',
  updatedAt: '2026-08-19T00:00:00.000Z',
}

describe('emptyRegistryPort - the honest default', () => {
  it('answers every lookup with a TYPED not-provisioned (never fabricates)', async () => {
    const port = emptyRegistryPort()
    const r = await port.lookup('01/09506000134352', 'class')
    expect(r.found).toBe(false)
    if (r.found) return
    expect(r.reason).toBe('not-provisioned')
    expect(r.detail).toContain('01/09506000134352')
  })

  it('carries a custom detail when provided', async () => {
    const r = await emptyRegistryPort('R2 registry offline').lookup('vin/x', 'class')
    expect(r.found).toBe(false)
    if (r.found) return
    expect(r.detail).toContain('R2 registry offline')
  })
})

describe('MemoryRegistryPort - seed -> lookup -> join', () => {
  it('joins the four independent records into one ResolvedManifest', async () => {
    const reg = new MemoryRegistryPort({
      identifier: [classRecord],
      owner: [brandOwner],
      linkset: [brandLinkset],
      policy: [classPolicy],
    })
    const r = await reg.lookup('01/09506000134352', 'class')
    expect(r.found).toBe(true)
    if (!r.found) return
    expect(r.manifest.canonicalId).toBe('product_xioNCf7')
    expect(r.manifest.owner.ownerId).toBe('org_acme')
    expect(r.manifest.linkset.id).toBe('ls_acme_class')
    expect(r.manifest.policy.id).toBe('pol_class')
    expect(r.manifest.defaultLink).toBe('gs1:pip')
    expect(r.manifest.etag).toBe('W/"v1"')
  })

  it('a missing key is a TYPED no-record miss (existence-neutral)', async () => {
    const reg = new MemoryRegistryPort()
    const r = await reg.lookup('01/00000000000000', 'class')
    expect(r.found).toBe(false)
    if (r.found) return
    expect(r.reason).toBe('no-record')
  })

  it('a record with an unresolved ref is a no-record miss, not a half-manifest', async () => {
    const reg = new MemoryRegistryPort({
      identifier: [classRecord], // owner/linkset/policy NOT seeded
    })
    const r = await reg.lookup('01/09506000134352', 'class')
    expect(r.found).toBe(false)
    if (r.found) return
    expect(r.reason).toBe('no-record')
    expect(r.detail).toContain('unresolved refs')
  })

  it('inherits policy class -> instance when the instance record has no own policy', async () => {
    const instanceRecord: IdentifierRecord = {
      ...classRecord,
      key: '01/09506000134352/21/SER1',
      grain: 'instance',
      canonicalId: 'product_instance_1',
      policyRef: 'pol_absent', // does not resolve -> inherit class parent's policy
    }
    const reg = new MemoryRegistryPort({
      identifier: [classRecord, instanceRecord],
      owner: [brandOwner],
      linkset: [brandLinkset],
      policy: [classPolicy],
    })
    const r = await reg.lookup('01/09506000134352/21/SER1', 'instance')
    expect(r.found).toBe(true)
    if (!r.found) return
    // inherited from the class parent
    expect(r.manifest.policy.id).toBe('pol_class')
  })

  it('an instance-scoped OwnerRef shadows the class owner on one key', async () => {
    const aliceOwner: OwnerRef = {
      ownerId: 'human_alice',
      claim: {
        method: 'vc',
        subject: 'human_alice',
        scope: { kind: 'instance', key: '01/09506000134352/21/SER1' },
        proofDigest: 'sha256:aa11',
        provedAt: '2026-08-19T01:00:00.000Z',
        strength: 'attested',
      },
      scope: { kind: 'instance', key: '01/09506000134352/21/SER1' },
    }
    const instanceRecord: IdentifierRecord = {
      ...classRecord,
      key: '01/09506000134352/21/SER1',
      grain: 'instance',
      canonicalId: 'product_instance_1',
      ownerRef: 'human_alice', // instance-scoped owner shadows the brand
      linksetRef: 'ls_acme_class',
      policyRef: 'pol_class',
    }
    const reg = new MemoryRegistryPort({
      identifier: [classRecord, instanceRecord],
      owner: [brandOwner, aliceOwner],
      linkset: [brandLinkset],
      policy: [classPolicy],
    })
    // class key still owned by the brand
    const cls = await reg.lookup('01/09506000134352', 'class')
    expect(cls.found && cls.manifest.owner.ownerId).toBe('org_acme')
    // instance key shadowed by Alice
    const inst = await reg.lookup('01/09506000134352/21/SER1', 'instance')
    expect(inst.found && inst.manifest.owner.ownerId).toBe('human_alice')
  })

  it('an instance with no own owner inherits the class owner', async () => {
    const instanceRecord: IdentifierRecord = {
      ...classRecord,
      key: '01/09506000134352/21/SER2',
      grain: 'instance',
      canonicalId: 'product_instance_2',
      ownerRef: 'org_absent', // does not resolve -> inherit class parent's owner
    }
    const reg = new MemoryRegistryPort({
      identifier: [classRecord, instanceRecord],
      owner: [brandOwner],
      linkset: [brandLinkset],
      policy: [classPolicy],
    })
    const r = await reg.lookup('01/09506000134352/21/SER2', 'instance')
    expect(r.found && r.manifest.owner.ownerId).toBe('org_acme')
  })
})
