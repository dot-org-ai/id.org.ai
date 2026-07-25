/**
 * auctionaccess — AuctionACCESS (AutoTec) membership, rep cards ("100
 * Million Numbers"), and venue admissions.
 * Class: partner · Status: HONEST STUB · Cadence: per-query once the
 * partner channel exists.
 *
 * There is no open/self-serve AuctionACCESS API — this is ADR 0016 C5
 * mode 3 (sanctioned partner). The ACV and IAA integrations prove the
 * channel exists; the cure is the AutoTec partner/API application. Until it
 * answers, registry-grade verification is typed `unverifiable-by-registry`
 * — the interim holder-pull path (auctionaccess-holder-pull) yields only
 * the weaker `holder-attested` tier and never substitutes for this channel
 * on an act-class predicate.
 */

import type { RegistryAnswer } from '../types'
import type { RegistryAdapter } from './adapter'
import { stubAnswer } from './adapter'

export const auctionAccess: RegistryAdapter = {
  id: 'auctionaccess',
  issuer: 'AutoTec, LLC (AuctionACCESS)',
  mode: 'partner',
  sourceClass: 'partner',
  cadence: { kind: 'per-query' },
  status: 'stub',

  async lookup(): Promise<RegistryAnswer> {
    return stubAnswer(
      'No AuctionACCESS partner channel is in place — membership, rep-card, and admission liveness are not registry-checkable',
      {
        action: 'apply-partner',
        channel: 'auctionaccess-autotec',
        note: 'File the AutoTec partner/API application (the ACV and IAA integrations prove the channel exists); interim: the holder-attested portal pull via auctionaccess-holder-pull',
      },
    )
  },
}
