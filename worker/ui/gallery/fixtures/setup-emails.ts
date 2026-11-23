/**
 * Agent emails (14a–14c, 23a–23c) fixtures: strings copied verbatim from
 * docs/agent-setup/screens. Each renders the whole preview document (inbox
 * frame + template), as 8a–8c do.
 */
import { AGENT_ROUTES as R } from '../../agent-setup/routes'
import {
  bankEmail,
  liveEmail,
  needsYouEmail,
  renewalFailedEmail,
  stalledEmail,
  usageAlertEmail,
  type BankEmailProps,
  type LiveEmailProps,
  type NeedsYouEmailProps,
  type RenewalFailedEmailProps,
  type StalledEmailProps,
  type UsageAlertEmailProps,
} from '../../emails/AgentEmails'
import type { EmailParts } from '../../emails/layout'
import { PreviewFrame } from '../../emails/PreviewFrame'
import { defineFixture, type BoundFixture, type FixtureGroup } from '../types'
import { SETUP_ID } from './setup'

const ORIGIN = 'https://id.org.ai'
const setupUrl = ORIGIN + R.setup(SETUP_ID)

const needsYou: NeedsYouEmailProps = { agent: 'Claude Code', product: 'Auto.dev', plan: 'Growth · $299/month', since: 'Nov 22, 2:16 PM EST', setupUrl }

const stalled: StalledEmailProps = {
  agent: 'Claude Code',
  product: 'Auto.dev',
  stoppedAt: 'the first call',
  quietFor: '10 minutes',
  prompt: 'Continue the Auto.dev setup. Read apis.ax/setup/su_8f2k and do what “next” says.',
  setupUrl,
}

const live: LiveEmailProps = {
  agent: 'Claude Code',
  product: 'Auto.dev',
  workspace: 'Drivly',
  planName: 'Growth',
  planPrice: '$299/month',
  spendLimit: '$500/month',
  keyLast4: '4f2a',
  took: '3 min 12 s',
  when: 'Nov 22, 2:17 PM EST',
  dashboardUrl: 'https://auto.dev/dashboard',
}

const bank: BankEmailProps = { agent: 'Claude Code', product: 'Auto.dev', planName: 'Growth', amount: '$299.00', amountShort: '$299', card: 'Visa ending 4417', confirmUrl: setupUrl }

const payFailed: RenewalFailedEmailProps = {
  agent: 'Claude Code',
  product: 'Auto.dev',
  workspace: 'Drivly',
  cardLast4: '4417',
  invoice: '$425.00',
  firstTry: 'Dec 22',
  nextTry: 'Dec 25',
  keyStops: 'Dec 29',
  updateUrl: `${ORIGIN}${R.spending}/renewals/auto.dev`,
}

const usage: UsageAlertEmailProps = {
  agent: 'Claude Code',
  product: 'Auto.dev',
  mark: '$500',
  plan: 'Growth · $299.00',
  feesSoFar: '$500.60 · 200,240 calls',
  nextMark: '$1,000',
  spendLimit: 'None',
  limitUrl: 'https://auto.dev/dashboard/spend',
}

/** The default props per email, shared with the templates' unit tests. */
export const setupEmailProps = { needsYou, stalled, live, bank, payFailed, usage }

/** A fixture: the template built from props, inside the mock's frame (board height `height`). */
function email<P>(build: (p: P) => EmailParts, height: number, props: P, derived?: Record<string, P>): BoundFixture {
  return defineFixture({ document: 'email', screen: (p: P) => PreviewFrame({ email: build(p), height }), title: (p) => build(p).subject, default: props, derived })
}

export const setupEmailsFixtures: FixtureGroup = {
  '14a-mail-needs-you': email(needsYouEmail, 640, needsYou),
  '14b-mail-stalled': email(stalledEmail, 600, stalled),
  '14c-mail-live': email(liveEmail, 640, live),
  '23a-mail-bank': email(bankEmail, 640, bank),
  '23b-mail-pay-failed': email(renewalFailedEmail, 640, payFailed),
  '23c-mail-usage': email(usageAlertEmail, 640, usage, {
    // Not drawn: the person has a limit and usage passed a mark below it.
    'with-limit': { ...usage, spendLimit: '$1,000/month' },
  }),
}
