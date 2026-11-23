/**
 * Agent setup (9a–9h, 11a–11f, 12a–12d) fixtures: strings copied verbatim
 * from docs/agent-setup/screens. Each setup is the contract a product would
 * post (agent-setup/types.ts); the page derives the rest.
 */
import { AGENT_ROUTES as R } from '../../agent-setup/routes'
import type { Product, Setup, SetupStep } from '../../agent-setup/types'
import type { TileContent } from '../../components'
import { AgentCard, type AgentCardProps } from '../../screens/agent-setup/AgentCard'
import { SetupApprove, type SetupApproveProps } from '../../screens/agent-setup/SetupApprove'
import { SetupPage, type SetupPageProps } from '../../screens/agent-setup/SetupPage'
import { defineFixture, type FixtureGroup } from '../types'

export const ORG: TileContent = { kind: 'org' }
export const CLAUDE_CODE = { name: 'Claude Code', tile: { kind: 'icon', icon: 'bot' } as TileContent }
export const PERSON = { name: 'Bryant Skarda', email: 'bryant@driv.ly' }
export const AGENT_ID = 'ag_7f3a'
export const SETUP_ID = 'su_8f2k'
export const VISA = 'Visa ending 4417'

export const AUTO_DEV: Product = {
  id: 'apis.ax',
  api: 'auto.dev',
  name: 'Auto.dev',
  tile: 'Ad',
  dashboard_url: 'https://auto.dev/dashboard',
  terms_url: 'https://www.auto.dev/terms',
  privacy_url: 'https://www.auto.dev/privacy',
}
/** Auto.dev with its own mark (worker/ui/static/brand/auto-dev.svg), for the `branded` gallery states. */
export const AUTO_DEV_LOGO = '/brand/auto-dev.svg'
export const AUTO_DEV_BRANDED: Product = { ...AUTO_DEV, logo_url: AUTO_DEV_LOGO }
/** The same screen with the product's own logo in its tile instead of its letters. */
export const branded = (p: SetupPageProps): SetupPageProps => ({ ...p, setup: { ...p.setup, product: { ...p.setup.product, logo_url: AUTO_DEV_LOGO } } })

const APIS_EMAIL: Product = { id: 'apis.ax', api: 'apis.email', name: 'apis.email', tile: '@', dashboard_url: 'https://apis.email/dashboard' }

/** A setup on Auto.dev for Drivly, in the given state with the given steps. */
export function autoDev(state: Setup['state'], steps: SetupStep[], product: Product = AUTO_DEV): Setup {
  return { setup_id: SETUP_ID, product, agent_id: AGENT_ID, workspace_id: 'ws_drivly', state, steps, next_for_person: null }
}

// ── The APIs.ax step list (HANDOFF.md section 4), in the states the screens draw ──

export const approved = (detail?: string): SetupStep => ({ id: 'approved', title: 'Agent approved', detail, state: 'done', at: '2026-11-22T19:14:02Z' })
export const testKey = (detail?: string): SetupStep => ({ id: 'test_key', title: 'Test key issued', detail, state: 'done', at: '2026-11-22T19:14:05Z' })
export const firstCallDone = (detail = 'GET /vin returned 200 in 212 ms.'): SetupStep => ({ id: 'first_call', title: 'First real call', detail, state: 'done', at: '2026-11-22T19:16:11Z' })
export const liveKeyTodo = (detail = 'Issued once a real call succeeds.'): SetupStep => ({ id: 'live_key', title: 'Live key', detail, state: 'todo' })
export const productionTodo = (name = 'Auto.dev'): SetupStep => ({ id: 'production', title: 'Ready for production', detail: `${name} checks that it backs off and retries.`, state: 'todo' })

const UP_TO_500 = 'Trusted in Drivly, up to $500/month.'
const CAPPED = 'Real endpoints, capped at [TEST ALLOWANCE].'
const VIN = '/vin/1HGCM82633A004352'
const removeAgent = { href: R.agentRemove(AGENT_ID), label: 'Remove it' }

const approve: SetupApproveProps = {
  agent: { ...CLAUDE_CODE, keyType: 'ed25519', fingerprint: '7f3a9e41b6d02c58e7a13f94d0b2c21d' },
  source: [
    { k: 'Host', v: 'bryant-mbp (macOS)' },
    { k: 'Asked', v: '2 min ago' },
    { k: 'Sent by', v: 'apis.ax' },
  ],
  title: 'Claude Code wants to set up Auto.dev for you',
  description: 'It gets its own identity, linked to you. Pause or remove it anytime.',
  account: PERSON,
  workspaces: [
    { value: 'ws_drivly', label: 'Drivly' },
    { value: 'ws_do', label: '.do Industries' },
    { value: 'ws_startups', label: 'Startups Studio' },
  ],
  selectedWorkspace: 'ws_drivly',
  permissions: [
    { icon: 'flask', title: 'Call Auto.dev with a test key', detail: 'Real endpoints, capped at [TEST ALLOWANCE]. Nothing is charged.', scope: 'autodev:test · resource https://api.auto.dev' },
    {
      icon: 'card',
      title: 'Subscribe to Auto.dev and get a live key',
      detail: 'Only after a real call succeeds on the test key. One subscription, on Drivly’s bill.',
      scope: 'autodev:subscribe · resource https://api.auto.dev',
      act: true,
      actNote: 'Spends real money, up to your limit.',
    },
    { icon: 'clock', title: 'Stay connected while you’re away', detail: 'Keeps working until it expires or you remove it in Agents.', scope: 'offline_access' },
  ],
  spendLimits: [
    { value: '50000', label: '$500/month' },
    { value: '0', label: '$0 — decide later' },
    { value: '100000', label: '$1,000/month' },
    { value: 'none', label: 'No limit' },
  ],
  selectedSpend: '50000',
  expiries: [
    { value: '30d', label: 'In 30 days' },
    { value: '7d', label: 'In 7 days' },
    { value: '90d', label: 'In 90 days' },
    { value: 'never', label: 'Never' },
  ],
  selectedExpiry: '30d',
  payMethod: VISA,
  foot: {
    secondary: { label: 'Reject', value: 'reject' },
    primary: { label: 'Approve agent', value: 'approve', busyLabel: 'Approving…' },
    note: 'Next, you watch each setup step as it happens.',
  },
  action: R.approve('WDJB-MJHT'),
  csrf: 'gallery',
}

const running: SetupPageProps = {
  setup: autoDev('running', [
    approved(UP_TO_500),
    testKey(CAPPED),
    {
      id: 'first_call',
      title: 'First real call',
      detail: 'Waiting for Claude Code to call Auto.dev with the test key.',
      state: 'now',
      evidence: { type: 'listening', key_last4: 'a91c', since: '2026-11-22T19:14:05Z', elapsed: '0:42', note: 'A call copied from the docs example doesn’t count.' },
    },
    liveKeyTodo(),
    productionTodo(),
  ]),
  agent: CLAUDE_CODE,
  title: 'Claude Code is setting up Auto.dev',
  description: 'Keep Claude Code running. Each step ticks when it happens.',
  sinceSeconds: 4,
  foot: { note: ['Not your agent? ', removeAgent] },
}

const needsYou: SetupPageProps = {
  setup: autoDev('needs_spend_approval', [
    approved('Trusted in Drivly. No spending yet.'),
    testKey(CAPPED),
    {
      ...firstCallDone('Auto.dev answered a real request.'),
      evidence: {
        type: 'call',
        method: 'GET',
        path: VIN,
        status: 200,
        ms: 212,
        rows: [
          ['Vehicle', '2003 Honda Accord Cpe'],
          ['Trim', 'EX Auto V6 w/Leather'],
          ['Engine', '3.0, V6 Cylinder Engine'],
        ],
        more_url: `${R.setup(SETUP_ID)}/calls/first`,
      },
    },
    {
      id: 'spend',
      title: 'Approve spending',
      detail: 'Growth is $299/month plus data fees. Claude Code subscribes inside the limit you set.',
      state: 'you',
      evidence: {
        type: 'field',
        label: 'Spend limit',
        options: [
          { value: '50000', label: '$500/month' },
          { value: '100000', label: '$1,000/month' },
          { value: 'none', label: 'No limit' },
        ],
        value: '50000',
      },
    },
    liveKeyTodo('Issued as soon as you approve.'),
    productionTodo(),
  ]),
  agent: CLAUDE_CODE,
  title: 'Claude Code needs your OK to go live',
  description: 'Auto.dev works on the test key. A live key needs a spend limit.',
  sinceSeconds: 12,
  payMethod: VISA,
  foot: {
    secondary: { label: 'Not now', value: 'later' },
    primary: { label: 'Approve $500/month', value: 'approve_spend', busyLabel: 'Approving…', follows: { control: 'answer_spend', template: 'Approve {label}' } },
    note: 'The test key keeps working until you decide.',
  },
  csrf: 'gallery',
}

const stalled: SetupPageProps = {
  setup: autoDev('stalled', [
    approved(UP_TO_500),
    testKey(CAPPED),
    {
      id: 'first_call',
      title: 'First real call',
      detail: 'No request has arrived on the test key.',
      state: 'you',
      label: 'Stalled',
      evidence: { type: 'prompt', label: 'Paste this to Claude Code', text: 'Continue the Auto.dev setup. Read apis.ax/setup/su_8f2k and do what “next” says.' },
    },
    liveKeyTodo(),
    productionTodo(),
  ]),
  agent: CLAUDE_CODE,
  title: 'Setup has stopped at the first call',
  description: 'Claude Code hasn’t called Auto.dev in 10 minutes. It may have stopped or declared itself done.',
  sinceSeconds: 600,
  foot: { note: ['Nothing is charged until a live key is issued. ', { href: R.setupCancel(SETUP_ID), label: 'Cancel setup' }] },
}

const live: SetupPageProps = {
  setup: autoDev('live', [
    approved(),
    testKey(),
    firstCallDone(),
    { id: 'live_key', title: 'Live key', detail: 'Subscribed to Growth. Shown once, to Claude Code.', state: 'done', at: '2026-11-22T19:17:02Z' },
    { id: 'production', title: 'Ready for production', detail: 'Backed off and retried after a 429 and a 500.', state: 'done', at: '2026-11-22T19:17:14Z' },
  ]),
  agent: CLAUDE_CODE,
  title: 'Auto.dev is live',
  description: 'Claude Code finished setup in 3 min 12 s. You can close this tab.',
  top: [
    {
      kind: 'well',
      items: [
        { k: 'Account', v: 'bryant@driv.ly' },
        { k: 'Workspace', v: 'Drivly' },
        { k: 'Plan', v: 'Growth · $299/month' },
        { k: 'Spend limit', v: '$500/month' },
        { k: 'Live key', v: 'Ends in 4f2a · held by Claude Code' },
      ],
    },
    { kind: 'line', text: ['Usage, logs and keys live in the Auto.dev developer dashboard. ', { href: 'https://auto.dev/dashboard/keys', label: 'Create a key for yourself' }] },
  ],
  foot: {
    secondary: { label: 'Manage agent', href: R.agents },
    primary: { label: 'Open developer dashboard', href: 'https://auto.dev/dashboard', icon: 'arrow_ur' },
    note: ['Wasn’t you? ', { href: R.agentRemove(AGENT_ID), label: 'Remove this agent' }],
  },
}

const callFailed: SetupPageProps = {
  setup: autoDev('call_failing', [
    approved(UP_TO_500),
    testKey(CAPPED),
    {
      id: 'first_call',
      title: 'First real call',
      detail: 'Last try 20 seconds ago.',
      state: 'you',
      label: 'Failing',
      evidence: {
        type: 'call',
        method: 'GET',
        path: '/vin/1HGCM8263',
        status: 400,
        ms: 38,
        rows: [
          ['Code', 'INVALID_VIN_FORMAT', 'mono'],
          ['Reason', 'VIN must be exactly 17 characters'],
        ],
        more_url: `${R.setup(SETUP_ID)}/calls`,
        more_label: 'View all 6 tries',
      },
    },
    liveKeyTodo(),
    productionTodo(),
  ]),
  agent: CLAUDE_CODE,
  title: 'The first call keeps failing',
  description: 'Claude Code has tried 6 times. Auto.dev answered each time, but not with a result.',
  sinceSeconds: 20,
  foot: { note: ['Claude Code can keep trying. Nothing is charged on a test key. ', { href: R.setupCancel(SETUP_ID), label: 'Cancel setup' }] },
}

const declined: SetupPageProps = {
  setup: autoDev('payment_declined', [
    approved(UP_TO_500),
    testKey(CAPPED),
    firstCallDone(),
    { id: 'live_key', title: 'Live key', detail: 'Drivly’s card ending 4417 was declined.', state: 'fail', label: 'Declined' },
    productionTodo(),
  ]),
  agent: CLAUDE_CODE,
  title: 'Payment was declined',
  description: 'Auto.dev couldn’t start Growth at $299/month. The test key still works.',
  sinceSeconds: 8,
  foot: {
    secondary: { label: 'Cancel setup', href: R.setupCancel(SETUP_ID) },
    primary: { label: 'Update payment method', href: R.paymentMethodNew },
    note: 'Claude Code picks up where it stopped once payment goes through.',
  },
}

const noCard: SetupPageProps = {
  setup: autoDev('needs_payment_method', [
    approved(UP_TO_500),
    testKey(CAPPED),
    firstCallDone(),
    { id: 'payment_method', title: 'Add a payment method', detail: 'Growth is $299/month, inside your $500 limit.', state: 'you' },
    liveKeyTodo('Issued as soon as a card is on file.'),
    productionTodo(),
  ]),
  agent: CLAUDE_CODE,
  title: 'Add a payment method to go live',
  description: 'Drivly has no card on file. Claude Code is waiting with a working test key.',
  sinceSeconds: 12,
  foot: {
    secondary: { label: 'Not now', value: 'later' },
    primary: { label: 'Add payment method', href: R.paymentMethodNew },
    note: 'The card fields are Stripe’s. id.org.ai never sees the number.',
  },
  csrf: 'gallery',
}

const liveWarn: SetupPageProps = {
  setup: autoDev('live_with_warning', [
    approved(),
    testKey(),
    firstCallDone(),
    { id: 'live_key', title: 'Live key', detail: 'Subscribed to Growth. Shown once, to Claude Code.', state: 'done', at: '2026-11-22T19:17:02Z' },
    {
      id: 'production',
      title: 'Ready for production',
      detail: 'It got a 429 and gave up. Under load, calls will fail the same way.',
      state: 'you',
      label: 'Needs a fix',
      evidence: { type: 'prompt', label: 'Paste this to Claude Code', text: 'Auto.dev returned 429. Back off and retry, then check apis.ax/setup/su_8f2k.' },
    },
  ]),
  agent: CLAUDE_CODE,
  title: 'Auto.dev is live, with one thing to fix',
  description: 'The live key works. Claude Code stopped at a rate limit instead of retrying.',
  foot: {
    secondary: { label: 'Manage agent', href: R.agents },
    primary: { label: 'Open developer dashboard', href: 'https://auto.dev/dashboard', icon: 'arrow_ur' },
    note: 'This doesn’t hold back the live key.',
  },
}

const rejected: AgentCardProps = {
  tiles: { left: ORG, right: CLAUDE_CODE.tile, connector: 'fail' },
  title: 'You rejected Claude Code',
  description: 'It has no identity and no keys. Nothing was set up or charged.',
  blocks: [
    {
      kind: 'well',
      items: [
        { k: 'Asked to', v: 'Set up Auto.dev' },
        { k: 'From', v: 'bryant-mbp (macOS)' },
        { k: 'Rejected', v: '2:14 PM' },
      ],
    },
  ],
  foot: { note: 'Changed your mind? Ask Claude Code to start again.' },
}

const cancelled: SetupPageProps = {
  setup: autoDev('cancelled', []),
  agent: CLAUDE_CODE,
  title: 'Setup cancelled',
  description: 'The test key is revoked. Nothing was charged.',
  top: [
    {
      kind: 'well',
      items: [
        { k: 'Agent', v: 'Claude Code · still approved' },
        { k: 'Test key', v: 'Revoked' },
        { k: 'Stopped at', v: 'First real call' },
        { k: 'Charged', v: '$0' },
      ],
    },
  ],
  foot: { note: ['Claude Code can start again without a new approval. ', removeAgent] },
}

const second: SetupPageProps = {
  setup: autoDev(
    'running',
    [
      { id: 'approved', title: 'Already approved', detail: 'Trusted in Drivly. $299 of $500 used this month.', state: 'done', label: 'Nov 22' },
      { id: 'test_key', title: 'Test key issued', detail: CAPPED, state: 'done', at: '2026-11-25T15:02:10Z' },
      {
        id: 'first_call',
        title: 'First real call',
        detail: 'Waiting for Claude Code to call apis.email with the test key.',
        state: 'now',
        evidence: { type: 'listening', key_last4: '7c3e', elapsed: '0:09', note: 'A call copied from the docs example doesn’t count.' },
      },
      liveKeyTodo(),
      productionTodo('apis.email'),
    ],
    APIS_EMAIL,
  ),
  agent: CLAUDE_CODE,
  title: 'Claude Code is adding apis.email',
  description: 'No approval needed. Same agent, inside your $500 limit.',
  sinceSeconds: 4,
  foot: { note: ['Not expecting this? ', { href: R.agentPause(AGENT_ID), label: 'Pause Claude Code' }] },
}

const limitRaise: AgentCardProps = {
  tiles: { left: CLAUDE_CODE.tile, right: ORG, connector: 'idle' },
  secondsLeft: 272,
  title: 'Claude Code wants a higher limit',
  description: 'Trusted agent · Drivly',
  blocks: [
    {
      kind: 'well',
      tight: true,
      items: [
        { k: 'Now', v: '$500/month' },
        { k: 'Asking for', v: '$1,000/month' },
        { k: 'Spent this month', v: '$299' },
      ],
      excerpt: 'To add apis.email next to Auto.dev and leave room for usage.',
    },
    {
      kind: 'select',
      id: 'limit-new',
      name: 'limit',
      label: 'New limit',
      options: [
        { value: '100000', label: '$1,000/month', short: '$1,000' },
        { value: '75000', label: '$750/month', short: '$750' },
        { value: 'none', label: 'No limit', short: 'no limit' },
      ],
      selected: '100000',
    },
  ],
  foot: {
    secondary: { label: 'Deny', value: 'deny' },
    primary: { label: 'Raise to $1,000', value: 'raise', busyLabel: 'Raising…', follows: { control: 'limit', template: 'Raise to {label}' } },
    note: 'Auto.dev keeps working either way.',
  },
  action: `${R.agents}/${AGENT_ID}/limit`,
  csrf: 'gallery',
}

const expiring: AgentCardProps = {
  tiles: { left: ORG, right: CLAUDE_CODE.tile, connector: 'hold' },
  title: 'Claude Code expires in 3 days',
  description: 'After Dec 22 its keys stop working until you approve it again.',
  blocks: [
    {
      kind: 'well',
      items: [
        { k: 'Connected to', v: 'Auto.dev, apis.email' },
        { k: 'Spend limit', v: '$500/month' },
        { k: 'Approved', v: 'Nov 22' },
      ],
    },
    {
      kind: 'select',
      id: 'extend-for',
      name: 'extend',
      label: 'Extend for',
      options: [
        { value: '30d', label: '30 days' },
        { value: '90d', label: '90 days' },
        { value: 'never', label: 'Until I remove it' },
      ],
      selected: '30d',
    },
  ],
  foot: {
    secondary: { label: 'Let it expire', value: 'expire' },
    primary: { label: 'Extend', value: 'extend', busyLabel: 'Extending…' },
    note: ['You can change this anytime in ', { href: R.agents, label: 'Agents' }, '.'],
  },
  action: `${R.agents}/${AGENT_ID}/expiry`,
  csrf: 'gallery',
}

const paused: SetupPageProps = {
  setup: autoDev('paused', [
    approved(UP_TO_500),
    testKey(CAPPED),
    { id: 'first_call', title: 'First real call', detail: 'Calls are refused while it’s paused.', state: 'held' },
    liveKeyTodo(),
    productionTodo(),
  ]),
  agent: CLAUDE_CODE,
  title: 'Claude Code is paused',
  description: 'You paused it at 2:15 PM. Setup is held at the first real call.',
  foot: {
    secondary: { label: 'Remove agent', href: R.agentRemove(AGENT_ID) },
    primary: { label: 'Resume', value: 'resume', icon: 'play', busyLabel: 'Resuming…' },
    note: 'A paused agent can’t call anything or spend.',
  },
  csrf: 'gallery',
}

/** The default props per screen, shared with the screens' unit tests. */
export const setupProps = { approve, running, needsYou, stalled, live, callFailed, declined, noCard, liveWarn, rejected, cancelled, second, limitRaise, expiring, paused }

const page = (props: SetupPageProps, scripts: ('ago.js' | 'copy.js' | 'follow.js' | 'disclose.js' | 'terms.js' | 'logo.js')[] = ['ago.js'], derived?: Record<string, SetupPageProps>) =>
  defineFixture({ screen: SetupPage, title: (p) => `${p.title} · id.org.ai`, scripts, default: props, derived })
const card = (props: AgentCardProps, scripts: ('countdown.js' | 'follow.js')[] = []) => defineFixture({ screen: AgentCard, title: (p) => `${p.title} · id.org.ai`, scripts, default: props })

export const setupFixtures: FixtureGroup = {
  '9a-setup-approve': defineFixture({
    screen: SetupApprove,
    title: (p) => `${p.title} · id.org.ai`,
    scripts: ['copy.js'],
    default: approve,
    derived: {
      copied: { ...approve, copied: true },
      // No card on file: the pays-with line offers to add one (HANDOFF.md section 5, PayLine).
      'no-card': { ...approve, payMethod: undefined },
    },
  }),
  // `branded`: the product sends its logo, so its tile carries it (not drawn; the drawings use letters).
  '9b-setup-running': page(running, ['ago.js', 'logo.js'], { branded: branded(running) }),
  '9c-setup-needs-you': page(needsYou, ['ago.js', 'follow.js']),
  '9d-setup-stalled': page(stalled, ['ago.js', 'copy.js']),
  '9e-setup-live': page(live, ['logo.js'], { branded: branded(live) }),
  '11a-setup-call-failed': page(callFailed),
  '11b-setup-declined': page(declined),
  '11c-setup-no-card': page(noCard),
  '11d-setup-live-warn': page(liveWarn, ['copy.js']),
  '11e-setup-rejected': card(rejected),
  '11f-setup-cancelled': page(cancelled, []),
  '12a-setup-second': page(second),
  '12b-limit-raise': card(limitRaise, ['countdown.js', 'follow.js']),
  '12c-agent-expiring': card(expiring),
  '12d-setup-paused': page(paused, []),
}
