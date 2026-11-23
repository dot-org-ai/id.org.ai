/**
 * Every gallery fixture, merged from one file per screen group
 * (docs/product-update/prompts/03-screens.md). Each group owns its file.
 */
import type { FixtureGroup } from '../types'
import { accountsFixtures } from './accounts'
import { agentsFixtures } from './agents'
import { agentsManageFixtures } from './agents-manage'
import { authorizeFixtures } from './authorize'
import { deviceFixtures } from './devices'
import { directoryFixtures } from './directory'
import { emailsFixtures } from './emails'
import { errorsFixtures } from './errors'
import { securityFixtures } from './security'
import { setupFixtures } from './setup'
import { setupEmailsFixtures } from './setup-emails'
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
  // Agent setup, payments and connect (docs/agent-setup)
  ...setupFixtures,
  ...agentsManageFixtures,
  ...setupEmailsFixtures,
  ...directoryFixtures,
}
