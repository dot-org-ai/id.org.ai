/**
 * The adapter roster (id-vy7) — the §4 table of the three-part-process-check
 * build design: real where the research found public lookups/bulk files,
 * honest typed stubs everywhere else.
 */

import { describe, it, expect } from 'vitest'
import {
  REGISTRY_ADAPTERS,
  CREDENTIAL_TYPE_REGISTRY_V1,
  registryForCredentialType,
} from '../src/sdk/credential'
import type { AdapterContext, AdapterStatus, SourceClass } from '../src/sdk/credential'

const NOW = new Date('2026-07-25T12:00:00Z')

/** The design §4 table, pinned: id → { class, status }. */
const EXPECTED: Record<string, { sourceClass: SourceClass; status: AdapterStatus }> = {
  'mn-dvs-dealer': { sourceClass: 'public-lookup', status: 'real' },
  'tx-dmv-dealer': { sourceClass: 'public-lookup', status: 'real' },
  'ca-dmv-olsis': { sourceClass: 'public-lookup', status: 'real' },
  'az-mvd-dealer-report': { sourceClass: 'bulk-ingest', status: 'real' },
  'tx-dmv-spreadsheet': { sourceClass: 'bulk-ingest', status: 'real' },
  'fl-flhsmv-lists': { sourceClass: 'bulk-ingest', status: 'stub' },
  'nipr-pdb': { sourceClass: 'sanctioned-aggregator', status: 'stub' },
  'nmls-b2b': { sourceClass: 'subscription', status: 'stub' },
  auctionaccess: { sourceClass: 'partner', status: 'stub' },
  'auctionaccess-holder-pull': { sourceClass: 'partner-interim', status: 'real-interim' },
  // The ADR 0016 C5 registry-lookup exemplar the pinned spec demands — not
  // one of the nine industry-process adapters.
  'uspto-oed': { sourceClass: 'public-lookup', status: 'real' },
}

describe('REGISTRY_ADAPTERS — the ratified roster', () => {
  it('contains exactly the design §4 adapters plus uspto-oed', () => {
    expect(Object.keys(REGISTRY_ADAPTERS).sort()).toEqual(Object.keys(EXPECTED).sort())
  })

  for (const [id, expected] of Object.entries(EXPECTED)) {
    it(`${id} declares class '${expected.sourceClass}' and status '${expected.status}'`, () => {
      const adapter = REGISTRY_ADAPTERS[id]
      expect(adapter.id).toBe(id)
      expect(adapter.sourceClass).toBe(expected.sourceClass)
      expect(adapter.status).toBe(expected.status)
      expect(adapter.issuer.length).toBeGreaterThan(0)
    })
  }

  it('is frozen', () => {
    expect(Object.isFrozen(REGISTRY_ADAPTERS)).toBe(true)
    expect(Object.isFrozen(CREDENTIAL_TYPE_REGISTRY_V1)).toBe(true)
  })
})

describe('CREDENTIAL_TYPE_REGISTRY_V1 — every ratified type resolves', () => {
  it('maps every credential type to a registered adapter', () => {
    for (const [type, registry] of Object.entries(CREDENTIAL_TYPE_REGISTRY_V1)) {
      expect(REGISTRY_ADAPTERS[registry], `type '${type}' names registry '${registry}'`).toBeDefined()
      expect(registryForCredentialType(type)).toBe(registry)
    }
  })

  it('answers null for an unratified type — no silent fallback', () => {
    expect(registryForCredentialType('wizard-license')).toBeNull()
  })
})

describe('honest stubs never fake-pass', () => {
  // A port that would look alive to any adapter tempted to consult it.
  const temptingPort = {
    async fetch() {
      return {
        ok: true as const,
        data: { found: true, dealer: { name: 'Looks Live LLC', licenseNumber: 'X', status: 'Active' } },
        asOf: NOW.toISOString(),
        fromCache: false,
      }
    },
  }
  const ctx: AdapterContext = { port: temptingPort, now: NOW, effectClass: 'act' }

  const stubIds = Object.entries(EXPECTED)
    .filter(([, v]) => v.status === 'stub')
    .map(([id]) => id)

  for (const id of stubIds) {
    it(`${id} answers unverifiable-by-registry with a cure, ignoring the port`, async () => {
      const answer = await REGISTRY_ADAPTERS[id].lookup({ credential: { type: 'any' } }, ctx)
      expect(answer.verdict).toBe('unverifiable-by-registry')
      if (answer.verdict !== 'unverifiable-by-registry') return
      expect(answer.cure).toBeDefined()
      expect(answer.reason.length).toBeGreaterThan(0)
    })
  }

  it('auctionaccess-holder-pull never answers registry-verified, even with a full export', async () => {
    const answer = await REGISTRY_ADAPTERS['auctionaccess-holder-pull'].lookup(
      {
        credential: { type: 'auction-access-holder-attested' },
        holderAttested: {
          exportedBy: 'org_dealer1',
          exportedAt: NOW.toISOString(),
          membership: { id: '100-123', status: 'Active' },
          repCards: [],
        },
      },
      ctx,
    )
    expect(answer.verdict).toBe('holder-attested')
  })
})
