/**
 * ca-dmv-olsis — California DMV Occupational Licensing Status Information
 * System. Class: public-lookup · Status: REAL (salesperson coverage still to
 * be verified hands-on, ADR 0018 open item (c)) · Cadence: per-query.
 *
 * The only source among the five researched dealer states that enumerates
 * INDIVIDUAL vehicle-salesperson worker IDs — so this adapter also feeds
 * predicate (2)'s `state_vehicle_salesperson` regime: the returned `reps`
 * carry the registry's own worker IDs and standing (ADR 0017 R5).
 *
 * Expected normalized port payload for resource 'licensee-lookup':
 *   { found, licensee?: { kind: 'dealer'|'salesperson', name, number, status },
 *     salespersons?: [{ number, name, status }] }
 */

import type { RegistryAnswer, RepRecord } from '../types'
import type { AdapterContext, RegistryAdapter, RegistryQuery } from './adapter'
import { mapStatus, portFreshness, unavailableAnswer } from './adapter'

interface CaLookupPayload {
  found: boolean
  licensee?: { kind: 'dealer' | 'salesperson'; name: string; number: string; status: string }
  salespersons?: { number: string; name?: string; status: string }[]
}

const CA_STATUS_SEMANTICS = {
  Active: { live: true, goodStanding: true },
  Probation: { live: true, goodStanding: false },
  Suspended: { live: true, goodStanding: false },
  Expired: { live: false, goodStanding: false },
  Revoked: { live: false, goodStanding: false },
  Cancelled: { live: false, goodStanding: false },
} as const

export const caDmvOlsis: RegistryAdapter = {
  id: 'ca-dmv-olsis',
  issuer: 'California Department of Motor Vehicles, Occupational Licensing',
  mode: 'registry',
  sourceClass: 'public-lookup',
  cadence: { kind: 'per-query' },
  status: 'real',

  async lookup(query: RegistryQuery, ctx: AdapterContext): Promise<RegistryAnswer> {
    const number = query.credential.licenseNumber ?? query.credential.registrationNumber
    const result = await ctx.port.fetch({
      source: 'ca-dmv-olsis',
      resource: 'licensee-lookup',
      params: {
        ...(number ? { number } : {}),
        ...(query.credential.holderName ? { name: query.credential.holderName } : {}),
        kind: query.credential.type === 'ca-vehicle-salesperson' ? 'salesperson' : 'dealer',
      },
      freshness: portFreshness(ctx.effectClass),
    })
    if (!result.ok) return unavailableAnswer('ca-dmv-olsis', result)

    const payload = result.data as CaLookupPayload
    if (!payload.found || !payload.licensee) {
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

    const lic = payload.licensee
    const reps: RepRecord[] = (payload.salespersons ?? []).map((s) => ({
      registry: 'state_vehicle_salesperson',
      workerId: s.number,
      ...(s.name ? { name: s.name } : {}),
      standing: s.status,
    }))

    return {
      verdict: 'registry-verified',
      ...mapStatus(lic.status, CA_STATUS_SEMANTICS),
      holder: {
        name: lic.name,
        kind: lic.kind === 'salesperson' ? 'human' : 'organization',
        id: lic.number,
        jurisdiction: 'CA',
      },
      reps,
      asOf: result.asOf,
      fromCache: result.fromCache,
    }
  },
}
