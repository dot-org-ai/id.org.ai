/**
 * Registry adapters — the §4 adapter table of the three-part-process-check
 * build design, behind the one src.do-contract port (beads id-vy7).
 *
 * Real where the registry research found public lookups or bulk files;
 * honest typed stubs everywhere else. A stub's `unverifiable-by-registry`
 * verdict plus cure is the answer — the caller must surface it, never
 * paper over it.
 */

import type { RegistryAdapter } from './adapter'
import { deepFreeze } from '../types'
import { mnDvsDealer } from './mn-dvs-dealer'
import { txDmvDealer } from './tx-dmv-dealer'
import { caDmvOlsis } from './ca-dmv-olsis'
import { azMvdDealerReport } from './az-mvd-dealer-report'
import { txDmvSpreadsheet } from './tx-dmv-spreadsheet'
import { flFlhsmvLists } from './fl-flhsmv-lists'
import { niprPdb } from './nipr-pdb'
import { nmlsB2b } from './nmls-b2b'
import { auctionAccess } from './auctionaccess'
import { auctionAccessHolderPull } from './auctionaccess-holder-pull'
import { usptoOed } from './uspto-oed'

export type { AdapterContext, RegistryAdapter, RegistryDescriptor, RegistryQuery } from './adapter'
export { mapStatus, portFreshness, stubAnswer, unavailableAnswer } from './adapter'
export type { SourcePort, SourceRequest, SourceResult } from './port'
export { unconnectedSourcePort } from './port'

export {
  mnDvsDealer,
  txDmvDealer,
  caDmvOlsis,
  azMvdDealerReport,
  txDmvSpreadsheet,
  flFlhsmvLists,
  niprPdb,
  nmlsB2b,
  auctionAccess,
  auctionAccessHolderPull,
  usptoOed,
}

/** Adapter registry, keyed by adapter id. */
export const REGISTRY_ADAPTERS: Readonly<Record<string, RegistryAdapter>> = Object.freeze({
  [mnDvsDealer.id]: mnDvsDealer,
  [txDmvDealer.id]: txDmvDealer,
  [caDmvOlsis.id]: caDmvOlsis,
  [azMvdDealerReport.id]: azMvdDealerReport,
  [txDmvSpreadsheet.id]: txDmvSpreadsheet,
  [flFlhsmvLists.id]: flFlhsmvLists,
  [niprPdb.id]: niprPdb,
  [nmlsB2b.id]: nmlsB2b,
  [auctionAccess.id]: auctionAccess,
  [auctionAccessHolderPull.id]: auctionAccessHolderPull,
  [usptoOed.id]: usptoOed,
})

/**
 * Credential-type → registry-of-record map (versioned, frozen — a change is
 * a new version, never an edit).
 */
export const CREDENTIAL_TYPE_REGISTRY_V1: Readonly<Record<string, string>> = deepFreeze({
  'uspto-registered': 'uspto-oed',
  'mn-dealer-license': 'mn-dvs-dealer',
  'tx-dealer-license': 'tx-dmv-dealer',
  'ca-dealer-license': 'ca-dmv-olsis',
  'ca-vehicle-salesperson': 'ca-dmv-olsis',
  'az-dealer-license': 'az-mvd-dealer-report',
  'fl-dealer-license': 'fl-flhsmv-lists',
  'nipr-business-entity-producer': 'nipr-pdb',
  'carrier-appointment': 'nipr-pdb',
  'nmls-entity': 'nmls-b2b',
  'nmls-mlo': 'nmls-b2b',
  'auction-access-membership': 'auctionaccess',
  'auction-access-rep': 'auctionaccess',
  'auction-access-holder-attested': 'auctionaccess-holder-pull',
})

/** The registry of record for a credential type, or null when unratified. */
export function registryForCredentialType(type: string): string | null {
  return CREDENTIAL_TYPE_REGISTRY_V1[type] ?? null
}
