/**
 * uspto-oed — the USPTO Office of Enrollment and Discipline practitioner
 * roster (the pinned spec's registry-lookup exemplar, beads id-hww).
 * Class: public-lookup · Status: REAL over the ingested roster · Cadence:
 * per-query against the src.do-ingested roster.
 *
 * Not one of the nine ADR 0018 industry-process adapters — this is the
 * ADR 0016 C5 registry-lookup mode the acceptance spec pins
 * (`source.registry = "uspto-oed"`, roster `practitionerCount ≥ 40000`).
 * Roster ingest is src.do's scope; this adapter consumes the lookup and the
 * roster stats through the port and reports honestly when nothing is
 * ingested yet.
 *
 * Expected normalized port payloads:
 *   'roster-lookup' → { found, practitioner?: { name, registrationNumber, status } }
 *   'roster-stats'  → { practitionerCount: number, refreshedAt: string }
 */

import type { RegistryAnswer } from '../types'
import type { AdapterContext, RegistryAdapter, RegistryDescriptor, RegistryQuery } from './adapter'
import { mapStatus, portFreshness, unavailableAnswer } from './adapter'

interface OedLookupPayload {
  found: boolean
  practitioner?: { name: string; registrationNumber: string; status: string }
}

interface OedStatsPayload {
  practitionerCount: number
  refreshedAt: string
}

const OED_STATUS_SEMANTICS = {
  Active: { live: true, goodStanding: true },
  'Administratively Suspended': { live: true, goodStanding: false },
  Suspended: { live: true, goodStanding: false },
  Excluded: { live: false, goodStanding: false },
  Resigned: { live: false, goodStanding: false },
  Deceased: { live: false, goodStanding: false },
} as const

export const usptoOed: RegistryAdapter = {
  id: 'uspto-oed',
  issuer: 'United States Patent and Trademark Office, Office of Enrollment and Discipline',
  mode: 'registry',
  sourceClass: 'public-lookup',
  cadence: { kind: 'per-query' },
  status: 'real',

  async lookup(query: RegistryQuery, ctx: AdapterContext): Promise<RegistryAnswer> {
    const registrationNumber = query.credential.registrationNumber ?? query.credential.licenseNumber
    const result = await ctx.port.fetch({
      source: 'uspto-oed',
      resource: 'roster-lookup',
      params: { ...(registrationNumber ? { registrationNumber } : {}) },
      freshness: portFreshness(ctx.effectClass),
    })
    if (!result.ok) return unavailableAnswer('uspto-oed', result)

    const payload = result.data as OedLookupPayload
    if (!payload.found || !payload.practitioner) {
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

    const p = payload.practitioner
    return {
      verdict: 'registry-verified',
      ...mapStatus(p.status, OED_STATUS_SEMANTICS),
      holder: { name: p.name, kind: 'human', id: p.registrationNumber, jurisdiction: 'US' },
      reps: [],
      asOf: result.asOf,
      fromCache: result.fromCache,
    }
  },

  async describe(ctx: AdapterContext): Promise<RegistryDescriptor> {
    const base: Omit<RegistryDescriptor, 'ingested' | 'practitionerCount' | 'refreshedAt'> = {
      id: 'uspto-oed',
      mode: 'registry',
      issuer: usptoOed.issuer,
      sourceClass: 'public-lookup',
      status: 'real',
      cadence: { kind: 'per-query' },
    }
    const stats = await ctx.port.fetch({
      source: 'uspto-oed',
      resource: 'roster-stats',
      params: {},
      freshness: 'allow-cache',
    })
    if (!stats.ok) {
      return { ...base, ingested: false, practitionerCount: 0, note: `roster ${stats.unavailable}: ${stats.detail}` }
    }
    const payload = stats.data as OedStatsPayload
    return {
      ...base,
      ingested: true,
      practitionerCount: payload.practitionerCount,
      refreshedAt: payload.refreshedAt,
    }
  },
}
