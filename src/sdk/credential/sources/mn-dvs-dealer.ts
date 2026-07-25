/**
 * mn-dvs-dealer — Minnesota DVS eServices dealership directory.
 * Class: public-lookup · Status: REAL (build-first — gates the operating
 * MN cell's Phase 1) · Cadence: per-query.
 *
 * Hands-on probe 2026-07-25: `onlineservices.dps.mn.gov/EServices/?Link=Dealerships`
 * is a FAST Enterprises eServices app. The HTML shell redirects to
 * `/EServices/_/` and there IS a JSON backend (the FAST "Director"
 * protocol), but it is session-cookie-bound — not an anonymous REST GET.
 * The session walk lives in the src.do source; this adapter consumes the
 * normalized answer below. Field coverage of the directory is still an
 * outstanding hands-on confirmation (ADR 0018 Consequences, open item (c)),
 * so the payload contract here is deliberately minimal and fail-closed.
 *
 * Expected normalized port payload for resource 'dealership-lookup':
 *   { found: boolean, dealership?: { name, licenseNumber, status, city? } }
 */

import type { RegistryAnswer } from '../types'
import type { AdapterContext, RegistryAdapter, RegistryQuery } from './adapter'
import { mapStatus, portFreshness, unavailableAnswer } from './adapter'

interface MnLookupPayload {
  found: boolean
  dealership?: { name: string; licenseNumber: string; status: string; city?: string }
}

/** MN DVS status semantics — fail closed on anything unlisted. */
const MN_STATUS_SEMANTICS = {
  Active: { live: true, goodStanding: true },
  Suspended: { live: true, goodStanding: false },
  Expired: { live: false, goodStanding: false },
  Revoked: { live: false, goodStanding: false },
  Cancelled: { live: false, goodStanding: false },
} as const

export const mnDvsDealer: RegistryAdapter = {
  id: 'mn-dvs-dealer',
  issuer: 'Minnesota Department of Public Safety, Driver and Vehicle Services',
  mode: 'registry',
  sourceClass: 'public-lookup',
  cadence: { kind: 'per-query' },
  status: 'real',

  async lookup(query: RegistryQuery, ctx: AdapterContext): Promise<RegistryAnswer> {
    const licenseNumber = query.credential.licenseNumber ?? query.credential.registrationNumber
    const result = await ctx.port.fetch({
      source: 'mn-dvs-dealer',
      resource: 'dealership-lookup',
      params: {
        ...(licenseNumber ? { licenseNumber } : {}),
        ...(query.credential.holderName ? { name: query.credential.holderName } : {}),
      },
      freshness: portFreshness(ctx.effectClass),
    })
    if (!result.ok) return unavailableAnswer('mn-dvs-dealer', result)

    const payload = result.data as MnLookupPayload
    if (!payload.found || !payload.dealership) {
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

    const d = payload.dealership
    return {
      verdict: 'registry-verified',
      ...mapStatus(d.status, MN_STATUS_SEMANTICS),
      holder: { name: d.name, kind: 'organization', id: d.licenseNumber, jurisdiction: 'MN' },
      // MN enumerates NO salesperson worker IDs (ADR 0018 R2 platform_edge regime).
      reps: [],
      asOf: result.asOf,
      fromCache: result.fromCache,
    }
  },
}
