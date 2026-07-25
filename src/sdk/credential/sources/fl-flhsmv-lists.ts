/**
 * fl-flhsmv-lists — Florida FLHSMV published dealer lists.
 * Class: bulk-ingest · Status: HONEST STUB · Cadence: unknown.
 *
 * Published lists exist, but their format and cadence are unconfirmed
 * (ADR 0018 Consequences, open item (c)). Until that hands-on confirmation
 * lands, this adapter refuses with a typed `unverifiable-by-registry` and a
 * confirm-source cure — it never guesses at a payload contract and never
 * fake-passes.
 */

import type { RegistryAnswer } from '../types'
import type { RegistryAdapter } from './adapter'
import { stubAnswer } from './adapter'

export const flFlhsmvLists: RegistryAdapter = {
  id: 'fl-flhsmv-lists',
  issuer: 'Florida Department of Highway Safety and Motor Vehicles',
  mode: 'registry',
  sourceClass: 'bulk-ingest',
  cadence: { kind: 'unknown' },
  status: 'stub',

  async lookup(): Promise<RegistryAnswer> {
    return stubAnswer(
      'FLHSMV publishes dealer lists, but their format and cadence are unconfirmed — the payload contract is not frozen',
      {
        action: 'confirm-source',
        channel: 'fl-flhsmv-lists',
        note: 'Confirm the FLHSMV list format and publication cadence hands-on, then freeze the contract and promote this adapter to real',
      },
    )
  },
}
