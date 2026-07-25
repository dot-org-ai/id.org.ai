/**
 * nipr-pdb — NIPR Producer Database (PDB Detail/Batch/Company-Appointment
 * reports + Gateway API + PDB Alerts).
 * Class: sanctioned-aggregator · Status: HONEST STUB until the subscription
 * lands · Cadence: per-query (Gateway), bounded by each state DOI's
 * reporting lag into PDB.
 *
 * The only source where predicate (3)'s carrier-appointment leg AND
 * predicate (2)'s carrier-producer worker-ID leg are machine-checkable —
 * covers entity license, NPN, and carrier appointments. START THE
 * SUBSCRIPTION APPLICATION NOW: the lead time gates the whole Phase-2
 * agency cell (design §4).
 */

import type { RegistryAnswer } from '../types'
import type { RegistryAdapter } from './adapter'
import { stubAnswer } from './adapter'

export const niprPdb: RegistryAdapter = {
  id: 'nipr-pdb',
  issuer: 'National Insurance Producer Registry',
  mode: 'registry',
  sourceClass: 'sanctioned-aggregator',
  cadence: { kind: 'per-query' },
  status: 'stub',

  async lookup(): Promise<RegistryAnswer> {
    return stubAnswer(
      'NIPR PDB subscription has not landed — producer-entity licenses, NPNs, and carrier appointments are not yet machine-checkable',
      {
        action: 'subscribe',
        channel: 'nipr-pdb',
        note: 'Complete the NIPR PDB subscription application (Gateway API + PDB reports + Alerts) — lead time gates the Phase-2 agency cell',
      },
    )
  },
}
