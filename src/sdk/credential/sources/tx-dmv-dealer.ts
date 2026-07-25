/**
 * tx-dmv-dealer — Texas DMV dealer (GDN) Salesforce lookup.
 * Class: public-lookup · Status: REAL · Cadence: per-query lookup over data
 * the registry refreshes daily.
 *
 * The load-bearing status semantics (registry research, 2026-07-25):
 * 'APA Expired' means expired-but-renewal-under-review — the license is
 * STILL FULLY EFFECTIVE. Standing is never a boolean; the verbatim status
 * survives into `registryStatus` and the two booleans are mapped, never
 * collapsed (ADR 0018 R1a).
 *
 * Expected normalized port payload for resource 'dealer-lookup':
 *   { found: boolean, dealer?: { name, licenseNumber, status, city? } }
 */

import type { RegistryAnswer } from '../types'
import type { AdapterContext, RegistryAdapter, RegistryQuery } from './adapter'
import { mapStatus, portFreshness, unavailableAnswer } from './adapter'

interface TxLookupPayload {
  found: boolean
  dealer?: { name: string; licenseNumber: string; status: string; city?: string }
}

export const TX_STATUS_SEMANTICS = {
  Active: { live: true, goodStanding: true },
  // Expired-but-renewal-under-review: still fully effective. Never collapse.
  'APA Expired': { live: true, goodStanding: true },
  Suspended: { live: true, goodStanding: false },
  Expired: { live: false, goodStanding: false },
  Revoked: { live: false, goodStanding: false },
  Cancelled: { live: false, goodStanding: false },
  Closed: { live: false, goodStanding: false },
} as const

export const txDmvDealer: RegistryAdapter = {
  id: 'tx-dmv-dealer',
  issuer: 'Texas Department of Motor Vehicles',
  mode: 'registry',
  sourceClass: 'public-lookup',
  cadence: { kind: 'per-query' },
  status: 'real',

  async lookup(query: RegistryQuery, ctx: AdapterContext): Promise<RegistryAnswer> {
    const licenseNumber = query.credential.licenseNumber ?? query.credential.registrationNumber
    const result = await ctx.port.fetch({
      source: 'tx-dmv-dealer',
      resource: 'dealer-lookup',
      params: {
        ...(licenseNumber ? { licenseNumber } : {}),
        ...(query.credential.holderName ? { name: query.credential.holderName } : {}),
      },
      freshness: portFreshness(ctx.effectClass),
    })
    if (!result.ok) return unavailableAnswer('tx-dmv-dealer', result)

    const payload = result.data as TxLookupPayload
    if (!payload.found || !payload.dealer) {
      return {
        verdict: 'registry-verified',
        live: false,
        goodStanding: false,
        registryStatus: 'not-found',
        holder: null,
        reps: [],
        asOf: result.asOf,
        fromCache: result.fromCache,
      }
    }

    const d = payload.dealer
    return {
      verdict: 'registry-verified',
      ...mapStatus(d.status, TX_STATUS_SEMANTICS),
      holder: { name: d.name, kind: 'organization', id: d.licenseNumber, jurisdiction: 'TX' },
      // TX enumerates NO salesperson worker IDs (ADR 0018 R2 platform_edge regime).
      reps: [],
      asOf: result.asOf,
      fromCache: result.fromCache,
    }
  },
}
