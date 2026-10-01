/**
 * Every gallery fixture, merged from one file per screen group
 * (docs/product-update/prompts/03-screens.md). Each group owns its file.
 */
import type { FixtureGroup } from '../types'
import { accountsFixtures } from './accounts'
import { agentsFixtures } from './agents'
import { authorizeFixtures } from './authorize'
import { deviceFixtures } from './devices'
import { emailsFixtures } from './emails'
import { errorsFixtures } from './errors'
import { securityFixtures } from './security'
import { signinFixtures } from './signin'

export const fixtures: FixtureGroup = {
  ...signinFixtures,
  ...accountsFixtures,
  ...authorizeFixtures,
  ...deviceFixtures,
  ...agentsFixtures,
  ...securityFixtures,
  ...errorsFixtures,
  ...emailsFixtures,
}
