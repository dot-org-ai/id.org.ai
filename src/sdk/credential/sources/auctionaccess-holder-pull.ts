/**
 * auctionaccess-holder-pull — the dealer entity's OWN authenticated
 * AuctionACCESS portal session exporting its standing + rep-card roster.
 * Class: partner-interim · Status: REAL-interim · Cadence: unknown (the
 * export speaks as of the holder's session, not a registry publication).
 *
 * Honest but self-reported-with-registry-artifacts: the verdict is ALWAYS
 * `holder-attested`, never `registry-verified` — and holder-attested never
 * satisfies an act-class predicate (ADR 0018 R4 + open item (b)). The
 * export is supplied by the caller from the holder's held-fact store; this
 * adapter never reaches the registry at all.
 */

import type { RegistryAnswer, RepRecord } from '../types'
import type { AdapterContext, RegistryAdapter, RegistryQuery } from './adapter'
import { mapStatus } from './adapter'

const AA_STATUS_SEMANTICS = {
  Active: { live: true, goodStanding: true },
  Suspended: { live: true, goodStanding: false },
  Revoked: { live: false, goodStanding: false },
  Expired: { live: false, goodStanding: false },
} as const

export const auctionAccessHolderPull: RegistryAdapter = {
  id: 'auctionaccess-holder-pull',
  issuer: 'AutoTec, LLC (AuctionACCESS) — holder portal export',
  mode: 'partner',
  sourceClass: 'partner-interim',
  cadence: { kind: 'unknown' },
  status: 'real-interim',

  async lookup(query: RegistryQuery, _ctx: AdapterContext): Promise<RegistryAnswer> {
    const exported = query.holderAttested
    if (!exported) {
      return {
        verdict: 'unverifiable-by-registry',
        reason: 'No holder portal export was presented — the interim tier needs the dealer to pull its own AuctionACCESS standing',
        cure: {
          action: 'holder-pull',
          channel: 'auctionaccess-holder-pull',
          note: 'Have the holder export its AuctionACCESS standing and rep-card roster from its own authenticated portal session',
        },
      }
    }

    const reps: RepRecord[] = exported.repCards.map((r) => ({
      registry: 'auction_access_rep',
      workerId: r.repCardId,
      ...(r.name ? { name: r.name } : {}),
      standing: r.status,
    }))

    return {
      verdict: 'holder-attested',
      attestedBy: exported.exportedBy,
      ...mapStatus(exported.membership.status, AA_STATUS_SEMANTICS),
      holder: { name: exported.exportedBy, kind: 'organization', id: exported.membership.id },
      reps,
      asOf: exported.exportedAt,
      fromCache: false,
    }
  },
}
