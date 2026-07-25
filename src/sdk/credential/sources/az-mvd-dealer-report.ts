/**
 * az-mvd-dealer-report — Arizona MVD licensed-dealer report.
 * Class: bulk-ingest · Status: REAL, cadence-bounded · Cadence: twice-weekly
 * Excel (published Tue/Thu).
 *
 * A file-published source supports only fresh-against-latest-file: `asOf`
 * (the file's own publication moment) is MANDATORY, surfaced explicitly on
 * the answer, and an answer whose file is stale beyond the twice-weekly
 * cadence becomes a typed freshness failure in verify() — never a silent
 * pass (ADR 0018 R5).
 *
 * Expected normalized port payload for resource 'dealer-report-lookup':
 *   { fileAsOf: string, found: boolean, dealer?: { name, licenseNumber, status } }
 */

import type { RegistryAnswer } from '../types'
import type { AdapterContext, RegistryAdapter, RegistryQuery } from './adapter'
import { mapStatus, portFreshness, unavailableAnswer } from './adapter'

interface AzReportPayload {
  fileAsOf?: string
  found: boolean
  dealer?: { name: string; licenseNumber: string; status: string }
}

const AZ_STATUS_SEMANTICS = {
  Active: { live: true, goodStanding: true },
  Suspended: { live: true, goodStanding: false },
  Expired: { live: false, goodStanding: false },
  Revoked: { live: false, goodStanding: false },
  Cancelled: { live: false, goodStanding: false },
} as const

export const azMvdDealerReport: RegistryAdapter = {
  id: 'az-mvd-dealer-report',
  issuer: 'Arizona Department of Transportation, Motor Vehicle Division',
  mode: 'registry',
  sourceClass: 'bulk-ingest',
  cadence: { kind: 'twice-weekly', publishDays: ['Tue', 'Thu'] },
  status: 'real',

  async lookup(query: RegistryQuery, ctx: AdapterContext): Promise<RegistryAnswer> {
    const licenseNumber = query.credential.licenseNumber ?? query.credential.registrationNumber
    const result = await ctx.port.fetch({
      source: 'az-mvd-dealer-report',
      resource: 'dealer-report-lookup',
      params: { ...(licenseNumber ? { licenseNumber } : {}) },
      freshness: portFreshness(ctx.effectClass),
    })
    if (!result.ok) return unavailableAnswer('az-mvd-dealer-report', result)

    const payload = result.data as AzReportPayload
    // asOf is mandatory for a bulk file — an answer that cannot say which
    // publication it speaks from cannot certify anything (typed, not silent).
    const asOf = payload.fileAsOf ?? result.asOf
    if (!asOf) {
      return {
        verdict: 'unverifiable-by-registry',
        reason: 'AZ dealer report answer carried no file asOf — freshness cannot be certified',
        cure: {
          action: 'refresh-bulk-file',
          channel: 'az-mvd-dealer-report',
          note: 'Re-ingest the latest twice-weekly (Tue/Thu) MVD dealer Excel with its publication date',
        },
      }
    }

    if (!payload.found || !payload.dealer) {
      return {
        verdict: 'registry-verified',
        live: false,
        goodStanding: false,
        registryStatus: 'not-found',
        holder: null,
        reps: [],
        asOf,
        fromCache: result.fromCache,
      }
    }

    const d = payload.dealer
    return {
      verdict: 'registry-verified',
      ...mapStatus(d.status, AZ_STATUS_SEMANTICS),
      holder: { name: d.name, kind: 'organization', id: d.licenseNumber, jurisdiction: 'AZ' },
      // AZ enumerates NO salesperson worker IDs (ADR 0018 R2 platform_edge regime).
      reps: [],
      asOf,
      fromCache: result.fromCache,
    }
  },
}
