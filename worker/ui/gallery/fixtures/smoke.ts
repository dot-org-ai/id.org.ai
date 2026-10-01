/**
 * Temporary smoke fixture (phase 1): the page shell plus an empty card, proving
 * fonts, CSS and headers end to end. Deleted in phase 3.
 */
import { SmokeScreen } from '../smoke-screen'
import { defineFixture, type FixtureGroup } from '../types'

export const smokeFixtures: FixtureGroup = {
  smoke: defineFixture({
    screen: SmokeScreen,
    title: () => 'Smoke · id.org.ai',
    default: {},
  }),
}
