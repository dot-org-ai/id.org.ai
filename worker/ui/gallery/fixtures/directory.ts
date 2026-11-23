/**
 * Adding an API on apis.directory (15a–15e) fixtures: strings copied verbatim
 * from docs/agent-setup/screens. The same setup page, with the directory's steps.
 */
import { AGENT_ROUTES as R } from '../../agent-setup/routes'
import type { Product, Setup, SetupStep } from '../../agent-setup/types'
import { SetupPage, type SetupPageProps } from '../../screens/agent-setup/SetupPage'
import { defineFixture, type FixtureGroup } from '../types'
import { AGENT_ID, CLAUDE_CODE } from './setup'

const DIRECTORY: Product = { id: 'apis.directory', name: 'apis.directory', tile: 'Di', dashboard_url: 'https://apis.directory/api/[your-api]' }
const ADD_ID = 'su_dir1'

const run = (state: Setup['state'], steps: SetupStep[]): Setup => ({ setup_id: ADD_ID, product: DIRECTORY, agent_id: AGENT_ID, workspace_id: 'ws_drivly', state, steps, next_for_person: null })

const NO_SPEND = 'Trusted in Drivly. No spending yet.'
const approved = (detail?: string): SetupStep => ({ id: 'approved', title: 'Agent approved', detail, state: 'done', at: '2026-11-22T19:14:02Z' })
const domain = (detail?: string): SetupStep => ({ id: 'domain', title: 'Domain proved', detail, state: 'done', at: '2026-11-22T19:15:10Z' })
const facts = (detail?: string): SetupStep => ({ id: 'facts', title: 'Facts sent', detail, state: 'done', at: '2026-11-22T19:15:40Z' })
const called = (detail?: string): SetupStep => ({ id: 'called', title: 'Called by the directory', detail, state: 'done', at: '2026-11-22T19:16:20Z' })
const reviewTodo: SetupStep = { id: 'review', title: 'Review', detail: 'Free, or $100 one time for a faster one.', state: 'todo' }
const listedTodo: SetupStep = { id: 'listed', title: 'Listed', detail: 'At apis.directory/api/[your-api].', state: 'todo' }

const running: SetupPageProps = {
  setup: run('running', [
    approved(NO_SPEND),
    domain('DNS record found on [YOUR DOMAIN].'),
    facts('Five facts, four with a source.'),
    {
      id: 'called',
      title: 'Called by the directory',
      detail: 'apis.directory is calling your API itself.',
      state: 'now',
      evidence: { type: 'listening', text: 'Calling [YOUR API]', elapsed: '0:06', note: 'What the directory reads itself is marked Verified.' },
    },
    reviewTodo,
    listedTodo,
  ]),
  agent: CLAUDE_CODE,
  title: 'Claude Code is listing your API',
  description: 'On apis.directory. Each step ticks when it happens.',
  sinceSeconds: 4,
  foot: { note: ['Not your agent? ', { href: R.agentRemove(AGENT_ID), label: 'Remove it' }] },
}

const pickReview: SetupPageProps = {
  setup: run('needs_person', [
    approved(NO_SPEND),
    domain('DNS record found on [YOUR DOMAIN].'),
    facts('Five facts, four with a source.'),
    {
      ...called('A real request got a real answer.'),
      evidence: {
        type: 'call',
        method: 'GET',
        path: '[YOUR ENDPOINT]',
        status: 200,
        ms: '[MS]',
        rows: [
          ['Docs', 'Read by the directory · Verified'],
          ['OpenAPI file', 'Read by the directory · Verified'],
          ['Price', 'From your pricing page · Reported'],
        ],
      },
    },
    {
      id: 'review',
      title: 'Pick the review',
      detail: 'The same review either way. Only the wait differs.',
      state: 'you',
      evidence: {
        type: 'rows',
        rows: [
          ['Free', 'Reviewed in [FREE REVIEW TIME]'],
          ['Fast, $100 one time', 'Reviewed in [PRIORITY REVIEW TIME]'],
        ],
      },
    },
    listedTodo,
  ]),
  agent: CLAUDE_CODE,
  title: 'Pick how fast it gets reviewed',
  description: 'The directory called your API and it answered. A person reads the listing next.',
  sinceSeconds: 12,
  foot: {
    secondary: { label: 'Keep it free', value: 'free' },
    primary: { label: 'Pay $100', value: 'fast', busyLabel: 'Paying…' },
    note: 'Paying changes the wait, never a score.',
  },
  csrf: 'gallery',
}

const domainFailed: SetupPageProps = {
  setup: run('call_failing', [
    approved(NO_SPEND),
    {
      id: 'domain',
      title: 'Domain proved',
      detail: 'Looked 4 times in 10 minutes.',
      state: 'you',
      label: 'Not found',
      evidence: {
        type: 'prompt',
        label: 'Paste this to Claude Code',
        text: 'The DNS record for apis.directory is not visible on [YOUR DOMAIN]. Add it, or use the file method, then read apis.directory/add/WDJB-MJHT again.',
      },
    },
    { id: 'facts', title: 'Facts sent', detail: 'Name, maker, jobs, price and access, each with a source.', state: 'todo' },
    { id: 'called', title: 'Called by the directory', detail: 'The directory calls your API itself.', state: 'todo' },
    reviewTodo,
    listedTodo,
  ]),
  agent: CLAUDE_CODE,
  title: 'The directory can’t find your domain record',
  description: 'Claude Code said it added one. apis.directory looked, and it isn’t there yet.',
  sinceSeconds: 30,
  foot: { note: ['A new DNS record can take a while to show. The directory keeps looking. ', { href: R.setupCancel(ADD_ID), label: 'Cancel' }] },
}

const inReview: SetupPageProps = {
  setup: run('in_review', [
    approved(),
    domain(),
    facts(),
    called('A real request got a real answer.'),
    { id: 'review', title: 'Review', detail: 'Fast review, $100 paid by Claude Code. Due in [PRIORITY REVIEW TIME].', state: 'now', label: 'In review' },
    listedTodo,
  ]),
  agent: CLAUDE_CODE,
  title: 'Your API is in review',
  description: 'A person at apis.directory is reading the listing. Nothing more is needed from you.',
  foot: { note: 'You get an email when it is listed. You can close this tab.' },
}

const listed: SetupPageProps = {
  setup: run('live', [
    approved(),
    domain(),
    facts(),
    called(),
    { id: 'review', title: 'Review', detail: 'Read by a person at apis.directory.', state: 'done', label: 'Nov 23' },
    { id: 'listed', title: 'Listed', state: 'done', label: 'Nov 23' },
  ]),
  agent: CLAUDE_CODE,
  title: 'Your API is listed',
  description: 'Claude Code finished. The listing is public now.',
  top: [
    {
      kind: 'well',
      items: [
        { k: 'Listing', v: 'apis.directory/api/[your-api]' },
        { k: 'Review', v: 'Fast · $100 one time' },
        { k: 'Facts', v: '4 verified, 1 unverified' },
        { k: 'Paid by', v: 'Claude Code, inside your limit' },
      ],
    },
  ],
  foot: {
    secondary: { label: 'Manage agent', href: R.agents },
    primary: { label: 'Open listing', href: 'https://apis.directory/api/[your-api]', icon: 'arrow_ur' },
    note: 'An unverified fact is shown as unverified. Add a source to change it.',
  },
}

/** The default props per screen, shared with the screens' unit tests. */
export const directoryProps = { running, pickReview, domainFailed, inReview, listed }

const page = (props: SetupPageProps, scripts: ('ago.js' | 'copy.js')[] = ['ago.js']) => defineFixture({ screen: SetupPage, title: (p) => `${p.title} · id.org.ai`, scripts, default: props })

export const directoryFixtures: FixtureGroup = {
  '15a-add-running': page(running),
  '15b-add-pick-review': page(pickReview),
  '15c-add-domain-failed': page(domainFailed, ['ago.js', 'copy.js']),
  '15d-add-in-review': page(inReview, []),
  '15e-add-listed': page(listed, []),
}
