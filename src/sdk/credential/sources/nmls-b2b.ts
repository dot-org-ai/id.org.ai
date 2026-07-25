/**
 * nmls-b2b — NMLS entity records and sponsored-MLO numbers.
 * Class: subscription · Status: HONEST STUB · Cadence: unknown until the
 * B2B ACCESS channel's API-vs-web-page nature is confirmed.
 *
 * NMLS Consumer Access is CAPTCHA-gated — scraping it is an explicit NO.
 * Bulk redistribution of NMLS data is contractually barred. Until an NMLS
 * B2B ACCESS subscription lands, every lookup answers
 * `unverifiable-by-registry` with the subscription as the cure (ADR 0018
 * R4: where no sanctioned channel exists, the cure IS the access
 * application — never fabricated liveness).
 */

import type { RegistryAnswer } from '../types'
import type { RegistryAdapter } from './adapter'
import { stubAnswer } from './adapter'

export const nmlsB2b: RegistryAdapter = {
  id: 'nmls-b2b',
  issuer: 'Nationwide Multistate Licensing System',
  mode: 'registry',
  sourceClass: 'subscription',
  cadence: { kind: 'unknown' },
  status: 'stub',

  async lookup(): Promise<RegistryAnswer> {
    return stubAnswer(
      'No sanctioned NMLS channel: Consumer Access is CAPTCHA-gated (do not scrape) and no B2B ACCESS subscription is in place',
      {
        action: 'subscribe',
        channel: 'nmls-b2b-access',
        note: 'Subscribe to NMLS B2B ACCESS — the only sanctioned machine channel for entity and sponsored-MLO liveness',
      },
    )
  },
}
