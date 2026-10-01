/**
 * Every gallery fixture, merged from one file per screen group (phase 3 adds
 * signin.ts, accounts.ts, authorize.ts, devices.ts, agents.ts, security.ts,
 * errors.ts and emails.ts).
 */
import type { FixtureGroup } from '../types'
import { smokeFixtures } from './smoke'

export const fixtures: FixtureGroup = {
  ...smokeFixtures,
}
