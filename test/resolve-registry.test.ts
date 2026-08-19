/**
 * Integration tests for the Phase-4 registry-backed resolver
 * (worker/routes/resolve.ts). A seeded MemoryRegistryPort is injected via
 * createResolveApp({registry}) and exercised in-process with app.request; the
 * production-mount regressions (new key routes, /.well-known/gs1resolver, OAuth
 * untouched) go through SELF against the real worker (empty registry default).
 */
import { describe, it, expect } from 'vitest'
import { SELF } from 'cloudflare:test'
import { createResolveApp } from '../worker/routes/resolve'
import { MemoryRegistryPort } from '../worker/registry/memory'
import type { IdentifierRecord, OwnerRef, Linkset, PolicyRef } from '../worker/registry/port'

const BASE = 'https://id.org.ai'
const VALID_GTIN = '09506000134352'

// Valid check-digit samples for the Phase-4 keys.
const SSCC = '106141411234567897'
const GLN = '1234567890128'
const GRAI_CORE = '01234567890128'
const GDTI_CORE = '1234567890128'

function seededApp() {
  const policy: PolicyRef = { id: 'pol_class', tier: 0, cacheable: true, existenceNeutral: true }
  const owner: OwnerRef = {
    ownerId: 'org_acme',
    claim: {
      method: 'gcp-vc',
      subject: 'org_acme',
      scope: { kind: 'range', gcpPrefix: '9506000' },
      proofDigest: 'sha256:abc',
      provedAt: '2026-08-19T00:00:00.000Z',
      strength: 'range',
    },
    gcpPrefix: '9506000',
    scope: { kind: 'range', gcpPrefix: '9506000' },
  }
  const linkset: Linkset = {
    id: 'ls_acme',
    defaultLink: 'gs1:pip',
    links: [
      { linkType: 'gs1:pip', href: 'https://acme.example/p/134352', title: 'Product information' },
    ],
  }
  const record: IdentifierRecord = {
    key: `01/${VALID_GTIN}`,
    grain: 'class',
    canonicalId: 'product_xioNCf7abc',
    ownerRef: 'org_acme',
    linksetRef: 'ls_acme',
    defaultLink: 'gs1:pip',
    policyRef: 'pol_class',
    provenance: { proofId: 'proof_1', provedAt: '2026-08-19T00:00:00.000Z', method: 'gcp-vc' },
    etag: 'W/"v1"',
    updatedAt: '2026-08-19T00:00:00.000Z',
  }
  const registry = new MemoryRegistryPort({
    identifier: [record],
    owner: [owner],
    linkset: [linkset],
    policy: [policy],
  })
  return createResolveApp({ registry })
}

describe('registry-backed identity doc (seeded MemoryRegistryPort)', () => {
  it('a provisioned GTIN emits the registry canonicalId as $id + owner + gs1:linkset', async () => {
    const app = seededApp()
    const res = await app.request(`${BASE}/01/${VALID_GTIN}`, { headers: { accept: 'application/ld+json' } })
    expect(res.status).toBe(200)
    const doc = (await res.json()) as Record<string, unknown>
    expect(doc.$id).toBe('product_xioNCf7abc')
    const owner = doc.owner as { identifier: string; proof: { method: string; strength: string } }
    expect(owner.identifier).toBe('org_acme')
    expect(owner.proof.method).toBe('gcp-vc')
    expect(owner.proof.strength).toBe('range')
    expect(doc['gs1:linkset']).toBe(`${BASE}/01/${VALID_GTIN}?linkType=linkset`)
  })

  it('browser (Sec-Fetch navigate) on a provisioned record emits a REAL 303 to defaultLink', async () => {
    const app = seededApp()
    const res = await app.request(`${BASE}/01/${VALID_GTIN}`, {
      headers: { 'sec-fetch-mode': 'navigate', accept: 'text/html' },
      redirect: 'manual',
    })
    expect(res.status).toBe(303)
    expect(res.headers.get('location')).toBe('https://acme.example/p/134352')
  })

  it('an UNprovisioned key keeps the existence-neutral self-derived doc (behavior-preserving)', async () => {
    const app = seededApp()
    // A different GTIN with no record -> self-derived $id, no owner.
    const res = await app.request(`${BASE}/01/00012345678905`, { headers: { accept: 'application/ld+json' } })
    expect(res.status).toBe(200)
    const doc = (await res.json()) as Record<string, unknown>
    expect(doc.$id).toBe(`${BASE}/01/00012345678905`)
    expect(doc.owner).toBeUndefined()
    expect(doc['gs1:linkset']).toBeUndefined()
  })
})

describe('RFC 9264 linkset face', () => {
  it('?linkType=linkset -> 200 application/linkset+json with anchor + id:* entries', async () => {
    const app = seededApp()
    const res = await app.request(`${BASE}/01/${VALID_GTIN}?linkType=linkset`)
    expect(res.status).toBe(200)
    expect(res.headers.get('content-type')).toContain('application/linkset+json')
    const body = (await res.json()) as { linkset: Array<Record<string, unknown>> }
    const entry = body.linkset[0]
    expect(entry.anchor).toBe(`${BASE}/01/${VALID_GTIN}`)
    // the four id:* faces are addressable
    expect(entry['https://id.org.ai/voc/offer']).toBeDefined()
    expect(entry['https://id.org.ai/voc/consent']).toBeDefined()
    expect(entry['https://id.org.ai/voc/event']).toBeDefined()
    expect(entry['https://id.org.ai/voc/owner']).toBeDefined()
    // the registry gs1:pip link is merged in
    expect(entry['https://ref.gs1.org/voc/pip']).toBeDefined()
  })

  it('Accept: application/linkset+json -> 200 linkset (no redirect)', async () => {
    const app = seededApp()
    const res = await app.request(`${BASE}/01/${VALID_GTIN}`, {
      headers: { accept: 'application/linkset+json' },
      redirect: 'manual',
    })
    expect(res.status).toBe(200)
    expect(res.headers.get('content-type')).toContain('application/linkset+json')
  })

  it('?linkType=all -> the same linkset set', async () => {
    const app = seededApp()
    const res = await app.request(`${BASE}/01/${VALID_GTIN}?linkType=all`)
    expect(res.status).toBe(200)
    expect(res.headers.get('content-type')).toContain('application/linkset+json')
  })

  it('an unprovisioned key still serves a linkset with only self + id:* entries', async () => {
    const app = seededApp()
    const res = await app.request(`${BASE}/01/00012345678905?linkType=linkset`)
    expect(res.status).toBe(200)
    const body = (await res.json()) as { linkset: Array<Record<string, unknown>> }
    expect(body.linkset[0]['https://id.org.ai/voc/offer']).toBeDefined()
    // no gs1:pip merged (no record)
    expect(body.linkset[0]['https://ref.gs1.org/voc/pip']).toBeUndefined()
  })
})

describe('extended id:* typed stub faces', () => {
  const cases: Array<[string, string]> = [
    ['id:offer', 'Offer'],
    ['id:consent', 'ConsentRequest'],
    ['id:event', 'EpcisEventSeam'],
    ['id:owner', 'OwnershipClaim'],
  ]
  for (const [linkType, type] of cases) {
    it(`?linkType=${linkType} -> 200 typed placeholder stub with a ticket`, async () => {
      const app = seededApp()
      const res = await app.request(`${BASE}/01/${VALID_GTIN}?linkType=${encodeURIComponent(linkType)}`)
      expect(res.status).toBe(200)
      expect(res.headers.get('content-type')).toContain('application/json')
      const stub = (await res.json()) as Record<string, unknown>
      expect(stub.$type).toBe(type)
      expect(stub.status).toBe('placeholder')
      expect(stub.draftSuperset).toBe(true)
      expect(typeof stub.ticket).toBe('string')
    })
  }

  it('id:owner on a provisioned record carries the proven owner', async () => {
    const app = seededApp()
    const res = await app.request(`${BASE}/01/${VALID_GTIN}?linkType=id%3Aowner`)
    const stub = (await res.json()) as Record<string, unknown>
    expect(stub.owner).toBe('org_acme')
  })
})

describe('Phase-4 generalised key routes (production mount, empty registry)', () => {
  const grainCases: Array<[string, string, string]> = [
    [`/00/${SSCC}`, 'Product', 'sscc'],
    [`/414/${GLN}`, 'Place', 'gln'],
    [`/8004/ASSET-1`, 'Product', 'giai'],
    [`/8003/${GRAI_CORE}`, 'Product', 'grai'],
    [`/253/${GDTI_CORE}`, 'CreativeWork', 'gdti'],
  ]
  for (const [path, type, propertyID] of grainCases) {
    it(`${path} -> 200 ${type}`, async () => {
      const res = await SELF.fetch(`${BASE}${path}`, { headers: { accept: 'application/ld+json' } })
      expect(res.status).toBe(200)
      const doc = (await res.json()) as Record<string, unknown>
      expect(doc.$type).toBe(type)
      expect((doc.identifier as Array<{ propertyID: string }>)[0].propertyID).toBe(propertyID)
    })
  }

  it('GRAI with a trailing serial -> instance grain (Product) with serialNumber', async () => {
    const res = await SELF.fetch(`${BASE}/8003/${GRAI_CORE}SER1`, { headers: { accept: 'application/ld+json' } })
    expect(res.status).toBe(200)
    const doc = (await res.json()) as Record<string, unknown>
    const ids = doc.identifier as Array<{ propertyID: string; value: string }>
    expect(ids.some((i) => i.propertyID === 'serialNumber' && i.value === 'SER1')).toBe(true)
  })

  it('bad SSCC check digit -> 400 CHECKSUM_FAIL', async () => {
    const res = await SELF.fetch(`${BASE}/00/106141411234567890`)
    expect(res.status).toBe(400)
    const body = (await res.json()) as { error: { code: string } }
    expect(body.error.code).toBe('CHECKSUM_FAIL')
  })

  it('bad GLN grammar -> 400 CONFORMANCE', async () => {
    const res = await SELF.fetch(`${BASE}/414/123`)
    expect(res.status).toBe(400)
    const body = (await res.json()) as { error: { code: string } }
    expect(body.error.code).toBe('CONFORMANCE')
  })

  it('GIAI carries no check digit (a valid CSET-82 GIAI resolves) ', async () => {
    const res = await SELF.fetch(`${BASE}/8004/ANYTHING-GOES_1`, { headers: { accept: 'application/ld+json' } })
    expect(res.status).toBe(200)
  })
})

describe('/.well-known/gs1resolver (production mount)', () => {
  it('advertises the six primary keys, id:* draft superset, compression=false', async () => {
    const res = await SELF.fetch(`${BASE}/.well-known/gs1resolver`)
    expect(res.status).toBe(200)
    const desc = (await res.json()) as {
      supportedPrimaryKeys: string[]
      supportedLinkType: string[]
      draftSupersetLinkType: string[]
      supportsCompression: boolean
    }
    expect(desc.supportedPrimaryKeys).toEqual(['01', '00', '414', '8004', '8003', '253'])
    expect(desc.supportsCompression).toBe(false)
    expect(desc.draftSupersetLinkType).toContain('id:offer')
    expect(desc.supportedLinkType).toContain('gs1:pip')
  })

  it('does NOT shadow the shipped OAuth well-known metadata', async () => {
    const res = await SELF.fetch(`${BASE}/.well-known/oauth-authorization-server`)
    expect(res.status).toBe(200)
    const body = (await res.json()) as Record<string, unknown>
    expect(body.issuer ?? body.authorization_endpoint).toBeDefined()
  })
})
