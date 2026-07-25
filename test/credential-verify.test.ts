/**
 * verify(credential, principal) — ADR 0016 C5 / ADR 0018 (id-hww).
 *
 * Covers the adapter classes end-to-end through verify(): real
 * public-lookup mapping (MN/TX/CA), bulk-ingest cadence discipline (AZ),
 * honest stubs (FL/NIPR/NMLS/AuctionACCESS), the holder-attested interim
 * tier, freshness-by-effect-class, and typed request validation.
 */

import { describe, it, expect } from 'vitest'
import { verify } from '../src/sdk/credential'
import type {
  HolderPortalExport,
  PresentedCredential,
  SourcePort,
  SourceRequest,
  VerifyPrincipal,
} from '../src/sdk/credential'
import { unconnectedSourcePort } from '../src/sdk/credential'

const NOW = new Date('2026-07-25T12:00:00Z')

const ORG: VerifyPrincipal = { id: 'org_dealer1', workerType: 'organization' }
const HUMAN: VerifyPrincipal = { id: 'user_pat', workerType: 'human' }

function okPort(data: unknown, opts: { asOf?: string; fromCache?: boolean } = {}): SourcePort & { requests: SourceRequest[] } {
  const requests: SourceRequest[] = []
  return {
    requests,
    async fetch(req: SourceRequest) {
      requests.push(req)
      return { ok: true as const, data, asOf: opts.asOf ?? NOW.toISOString(), fromCache: opts.fromCache ?? false }
    },
  }
}

function mnCredential(overrides: Partial<PresentedCredential> = {}): PresentedCredential {
  return { type: 'mn-dealer-license', licenseNumber: 'MN-4821', ...overrides }
}

describe('verify — registry-verified pass (public-lookup)', () => {
  it('answers registry-verified, live and in good standing, fresh at the act, for an Active MN dealer', async () => {
    const port = okPort({ found: true, dealership: { name: 'Lakeside Motors', licenseNumber: 'MN-4821', status: 'Active' } })
    const result = await verify(mnCredential(), ORG, { effectClass: 'act', port, now: NOW })
    expect(result.success).toBe(true)
    if (!result.success) return
    const v = result.data
    expect(v.verdict).toBe('registry-verified')
    expect(v.live).toBe(true)
    expect(v.goodStanding).toBe(true)
    expect(v.registryStatus).toBe('Active')
    expect(v.holder).toEqual({ name: 'Lakeside Motors', kind: 'organization', id: 'MN-4821', jurisdiction: 'MN' })
    expect(v.source).toEqual({ mode: 'registry', registry: 'mn-dvs-dealer', sourceClass: 'public-lookup', status: 'real' })
    expect(v.freshness.cached).toBe(false)
    expect(v.satisfiesActClass).toBe(true)
    expect(v.checkedAt).toBe(NOW.toISOString())
    // MN enumerates no salesperson worker IDs — platform_edge regime.
    expect(v.reps).toEqual([])
  })

  it('demands bypass-cache from the port on an act-class check', async () => {
    const port = okPort({ found: false })
    await verify(mnCredential(), ORG, { effectClass: 'act', port, now: NOW })
    expect(port.requests[0].freshness).toBe('bypass-cache')
  })

  it('allows cache on a read-class check and discloses the TTL', async () => {
    const port = okPort({ found: false })
    const result = await verify(mnCredential(), ORG, { effectClass: 'read', port, now: NOW })
    expect(port.requests[0].freshness).toBe('allow-cache')
    if (!result.success) throw new Error('expected success')
    expect(result.data.freshness.maxAgeSeconds).toBe(604_800)
  })

  it('answers an authoritative not-found as registry-verified live=false (never an error)', async () => {
    const port = okPort({ found: false })
    const result = await verify(mnCredential(), ORG, { effectClass: 'act', port, now: NOW })
    if (!result.success) throw new Error('expected success')
    expect(result.data.verdict).toBe('registry-verified')
    expect(result.data.live).toBe(false)
    expect(result.data.goodStanding).toBe(false)
    expect(result.data.registryStatus).toBe('not-found')
    expect(result.data.holder).toBeNull()
  })
})

describe('verify — status semantics are never collapsed to a boolean', () => {
  it("keeps TX 'APA Expired' fully effective with the verbatim status", async () => {
    const port = okPort({ found: true, dealer: { name: 'Alamo Auto', licenseNumber: 'P123456', status: 'APA Expired' } })
    const result = await verify({ type: 'tx-dealer-license', licenseNumber: 'P123456' }, ORG, { effectClass: 'act', port, now: NOW })
    if (!result.success) throw new Error('expected success')
    expect(result.data.live).toBe(true)
    expect(result.data.goodStanding).toBe(true)
    expect(result.data.registryStatus).toBe('APA Expired')
  })

  it('keeps a suspended license live but NOT in good standing (two fields)', async () => {
    const port = okPort({ found: true, dealer: { name: 'Alamo Auto', licenseNumber: 'P123456', status: 'Suspended' } })
    const result = await verify({ type: 'tx-dealer-license', licenseNumber: 'P123456' }, ORG, { effectClass: 'act', port, now: NOW })
    if (!result.success) throw new Error('expected success')
    expect(result.data.live).toBe(true)
    expect(result.data.goodStanding).toBe(false)
  })

  it('fails closed on an unknown status while preserving it verbatim', async () => {
    const port = okPort({ found: true, dealer: { name: 'Alamo Auto', licenseNumber: 'P123456', status: 'Pending Review' } })
    const result = await verify({ type: 'tx-dealer-license', licenseNumber: 'P123456' }, ORG, { effectClass: 'act', port, now: NOW })
    if (!result.success) throw new Error('expected success')
    expect(result.data.live).toBe(false)
    expect(result.data.goodStanding).toBe(false)
    expect(result.data.registryStatus).toBe('Pending Review')
  })
})

describe('verify — CA OLSIS enumerates salesperson worker IDs', () => {
  it('carries the registry-issued worker IDs and standing on reps', async () => {
    const port = okPort({
      found: true,
      licensee: { kind: 'dealer', name: 'Bay Autos', number: 'C-9001', status: 'Active' },
      salespersons: [
        { number: 'S-100', name: 'Ana', status: 'Active' },
        { number: 'S-101', status: 'Expired' },
      ],
    })
    const result = await verify({ type: 'ca-dealer-license', licenseNumber: 'C-9001' }, ORG, { effectClass: 'act', port, now: NOW })
    if (!result.success) throw new Error('expected success')
    expect(result.data.reps).toEqual([
      { registry: 'state_vehicle_salesperson', workerId: 'S-100', name: 'Ana', standing: 'Active' },
      { registry: 'state_vehicle_salesperson', workerId: 'S-101', standing: 'Expired' },
    ])
  })
})

describe('verify — freshness discipline (ADR 0018 R5)', () => {
  it('types a cached answer on an act-class check as a failure, never a silent pass', async () => {
    const port = okPort({ found: true, dealership: { name: 'Lakeside Motors', licenseNumber: 'MN-4821', status: 'Active' } }, { fromCache: true })
    const result = await verify(mnCredential(), ORG, { effectClass: 'act', port, now: NOW })
    if (!result.success) throw new Error('expected success')
    expect(result.data.freshness.cached).toBe(true)
    expect(result.data.freshnessFailure).toBe('cached-for-act')
    expect(result.data.satisfiesActClass).toBe(false)
    // The finding itself is still reported honestly.
    expect(result.data.live).toBe(true)
  })

  it('accepts an AZ bulk answer fresh against the latest twice-weekly file', async () => {
    const fileAsOf = new Date(NOW.getTime() - 3 * 86_400_000).toISOString() // 3 days old — inside Tue/Thu cadence
    const port = okPort({ fileAsOf, found: true, dealer: { name: 'Desert Cars', licenseNumber: 'AZ-77', status: 'Active' } })
    const result = await verify({ type: 'az-dealer-license', licenseNumber: 'AZ-77' }, ORG, { effectClass: 'act', port, now: NOW })
    if (!result.success) throw new Error('expected success')
    expect(result.data.satisfiesActClass).toBe(true)
    expect(result.data.freshness.asOf).toBe(fileAsOf)
    expect(result.data.freshness.staleBeyondCadence).toBe(false)
  })

  it('types staleness beyond the twice-weekly cadence as a failure', async () => {
    const fileAsOf = new Date(NOW.getTime() - 8 * 86_400_000).toISOString() // 8 days — a publication was missed
    const port = okPort({ fileAsOf, found: true, dealer: { name: 'Desert Cars', licenseNumber: 'AZ-77', status: 'Active' } })
    const result = await verify({ type: 'az-dealer-license', licenseNumber: 'AZ-77' }, ORG, { effectClass: 'act', port, now: NOW })
    if (!result.success) throw new Error('expected success')
    expect(result.data.freshness.staleBeyondCadence).toBe(true)
    expect(result.data.freshnessFailure).toBe('stale-beyond-cadence')
    expect(result.data.satisfiesActClass).toBe(false)
  })

  it('refuses an AZ answer that cannot say which file it speaks from', async () => {
    const port = okPort({ found: true, dealer: { name: 'Desert Cars', licenseNumber: 'AZ-77', status: 'Active' } }, { asOf: '' })
    const result = await verify({ type: 'az-dealer-license', licenseNumber: 'AZ-77' }, ORG, { effectClass: 'act', port, now: NOW })
    if (!result.success) throw new Error('expected success')
    expect(result.data.verdict).toBe('unverifiable-by-registry')
    expect(result.data.cure).toMatchObject({ action: 'refresh-bulk-file', channel: 'az-mvd-dealer-report' })
  })
})

describe('verify — honest stubs surface, never fake-pass', () => {
  const livePayload = { found: true, dealer: { name: 'Looks Live LLC', licenseNumber: 'X', status: 'Active' } }

  const stubCases: Array<{ type: string; registry: string; cureAction: string }> = [
    { type: 'fl-dealer-license', registry: 'fl-flhsmv-lists', cureAction: 'confirm-source' },
    { type: 'nipr-business-entity-producer', registry: 'nipr-pdb', cureAction: 'subscribe' },
    { type: 'carrier-appointment', registry: 'nipr-pdb', cureAction: 'subscribe' },
    { type: 'nmls-entity', registry: 'nmls-b2b', cureAction: 'subscribe' },
    { type: 'nmls-mlo', registry: 'nmls-b2b', cureAction: 'subscribe' },
    { type: 'auction-access-membership', registry: 'auctionaccess', cureAction: 'apply-partner' },
    { type: 'auction-access-rep', registry: 'auctionaccess', cureAction: 'apply-partner' },
  ]

  for (const { type, registry, cureAction } of stubCases) {
    it(`${registry} answers unverifiable-by-registry with a '${cureAction}' cure for ${type} — even when handed a live-looking payload`, async () => {
      const port = okPort(livePayload)
      const result = await verify({ type, licenseNumber: 'X' }, ORG, { effectClass: 'act', port, now: NOW })
      if (!result.success) throw new Error('expected success')
      expect(result.data.verdict).toBe('unverifiable-by-registry')
      expect(result.data.live).toBe(false)
      expect(result.data.goodStanding).toBe(false)
      expect(result.data.satisfiesActClass).toBe(false)
      expect(result.data.cure?.action).toBe(cureAction)
      // Stubs never consult the port for a finding.
      expect(port.requests).toHaveLength(0)
    })
  }

  it('maps an unconnected source to unverifiable-by-registry with a connect-source cure (real adapters)', async () => {
    const result = await verify(mnCredential(), ORG, { effectClass: 'act', port: unconnectedSourcePort(), now: NOW })
    if (!result.success) throw new Error('expected success')
    expect(result.data.verdict).toBe('unverifiable-by-registry')
    expect(result.data.cure).toMatchObject({ action: 'connect-source', channel: 'mn-dvs-dealer' })
    expect(result.data.satisfiesActClass).toBe(false)
  })
})

describe('verify — the holder-attested interim tier (AuctionACCESS pull)', () => {
  const exported: HolderPortalExport = {
    exportedBy: 'org_dealer1',
    exportedAt: NOW.toISOString(),
    membership: { id: '100-123-456', status: 'Active' },
    repCards: [{ repCardId: '100M-42', name: 'Rey', status: 'Active' }],
  }

  it('answers holder-attested with the rep-card roster — and NEVER satisfies an act-class predicate', async () => {
    const result = await verify(
      { type: 'auction-access-holder-attested', membershipId: '100-123-456' },
      ORG,
      { effectClass: 'act', port: unconnectedSourcePort(), now: NOW, holderAttested: exported },
    )
    if (!result.success) throw new Error('expected success')
    expect(result.data.verdict).toBe('holder-attested')
    expect(result.data.live).toBe(true)
    expect(result.data.goodStanding).toBe(true)
    expect(result.data.satisfiesActClass).toBe(false)
    expect(result.data.reps).toEqual([{ registry: 'auction_access_rep', workerId: '100M-42', name: 'Rey', standing: 'Active' }])
    expect(result.data.source.sourceClass).toBe('partner-interim')
  })

  it('answers unverifiable with a holder-pull cure when no export is presented', async () => {
    const result = await verify(
      { type: 'auction-access-holder-attested', membershipId: '100-123-456' },
      ORG,
      { effectClass: 'act', port: unconnectedSourcePort(), now: NOW },
    )
    if (!result.success) throw new Error('expected success')
    expect(result.data.verdict).toBe('unverifiable-by-registry')
    expect(result.data.cure?.action).toBe('holder-pull')
  })
})

describe('verify — typed request validation', () => {
  it('rejects a missing credential type', async () => {
    const result = await verify({ type: '' }, HUMAN, { effectClass: 'act', port: unconnectedSourcePort(), now: NOW })
    expect(result.success).toBe(false)
    if (result.success) return
    expect(result.error.field).toBe('credential.type')
  })

  it('rejects an unratified credential type', async () => {
    const result = await verify({ type: 'wizard-license' }, HUMAN, { effectClass: 'act', port: unconnectedSourcePort(), now: NOW })
    expect(result.success).toBe(false)
    if (result.success) return
    expect(result.error.message).toContain('wizard-license')
  })

  it('rejects an unknown effect class', async () => {
    const result = await verify(mnCredential(), ORG, {
      effectClass: 'teleport' as never,
      port: unconnectedSourcePort(),
      now: NOW,
    })
    expect(result.success).toBe(false)
    if (result.success) return
    expect(result.error.field).toBe('effectClass')
  })

  it('rejects an empty principal id', async () => {
    const result = await verify(mnCredential(), { id: '', workerType: 'human' }, { effectClass: 'act', port: unconnectedSourcePort(), now: NOW })
    expect(result.success).toBe(false)
    if (result.success) return
    expect(result.error.field).toBe('principal.id')
  })
})
