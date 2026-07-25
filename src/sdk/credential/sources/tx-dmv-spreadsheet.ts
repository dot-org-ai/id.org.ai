/**
 * tx-dmv-spreadsheet — Texas DMV daily dealer-data download.
 * Class: bulk-ingest · Status: REAL (cross-check / cache role behind the
 * per-query tx-dmv-dealer lookup) · Cadence: daily.
 *
 * Same status semantics as tx-dmv-dealer ('APA Expired' is still fully
 * effective — never collapse). Being file-published, `asOf` is mandatory and
 * staleness beyond the daily cadence is a typed failure.
 *
 * Expected normalized port payload for resource 'dealer-file-lookup':
 *   { fileAsOf: string, found: boolean, dealer?: { name, licenseNumber, status } }
 */

import type { RegistryAnswer } from '../types'
import type { AdapterContext, RegistryAdapter, RegistryQuery } from './adapter'
import { mapStatus, portFreshness, unavailableAnswer } from './adapter'
import { TX_STATUS_SEMANTICS } from './tx-dmv-dealer'

interface TxFilePayload {
  fileAsOf?: string
  found: boolean
  dealer?: { name: string; licenseNumber: string; status: string }
}

export const txDmvSpreadsheet: RegistryAdapter = {
  id: 'tx-dmv-spreadsheet',
  issuer: 'Texas Department of Motor Vehicles',
  mode: 'registry',
  sourceClass: 'bulk-ingest',
  cadence: { kind: 'daily' },
  status: 'real',

  async lookup(query: RegistryQuery, ctx: AdapterContext): Promise<RegistryAnswer> {
    const licenseNumber = query.credential.licenseNumber ?? query.credential.registrationNumber
    const result = await ctx.port.fetch({
      source: 'tx-dmv-spreadsheet',
      resource: 'dealer-file-lookup',
      params: { ...(licenseNumber ? { licenseNumber } : {}) },
      freshness: portFreshness(ctx.effectClass),
    })
    if (!result.ok) return unavailableAnswer('tx-dmv-spreadsheet', result)

    const payload = result.data as TxFilePayload
    const asOf = payload.fileAsOf ?? result.asOf
    if (!asOf) {
      return {
        verdict: 'unverifiable-by-registry',
        reason: 'TX dealer spreadsheet answer carried no file asOf — freshness cannot be certified',
        cure: {
          action: 'refresh-bulk-file',
          channel: 'tx-dmv-spreadsheet',
          note: 'Re-ingest the latest daily TX DMV dealer download with its publication date',
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
      ...mapStatus(d.status, TX_STATUS_SEMANTICS),
      holder: { name: d.name, kind: 'organization', id: d.licenseNumber, jurisdiction: 'TX' },
      reps: [],
      asOf,
      fromCache: result.fromCache,
    }
  },
}
