/**
 * Workflows on the setup page (16a–18c) fixtures: strings copied verbatim from
 * docs/agent-setup/screens. No new page: each is a different step list posted
 * by the product (a migration, one job across three APIs, headless SaaS setup).
 */
import { AGENT_ROUTES as R } from '../../agent-setup/routes'
import type { Product, Setup, SetupStep } from '../../agent-setup/types'
import { SetupApprove, type SetupApproveProps } from '../../screens/agent-setup/SetupApprove'
import { SetupPage, type SetupPageProps } from '../../screens/agent-setup/SetupPage'
import { defineFixture, type FixtureGroup } from '../types'
import { AGENT_ID, AUTO_DEV, CLAUDE_CODE, setupPage, setupProps } from './setup'

const at = (hhmm: string) => `2026-11-22T19:${hhmm}:00Z`
const done = (id: string, title: string, minute: string, detail?: string, tag?: string): SetupStep => ({ id, title, detail, tag, state: 'done', at: at(minute) })
const todo = (id: string, title: string, detail?: string, tag?: string): SetupStep => ({ id, title, detail, tag, state: 'todo' })
const run = (id: string, product: Product, state: Setup['state'], steps: SetupStep[]): Setup => ({ setup_id: id, product, agent_id: AGENT_ID, workspace_id: 'ws_drivly', state, steps, next_for_person: null })

const UP_TO_500 = 'Trusted in Drivly, up to $500/month.'
const removeIt = { href: R.agentRemove(AGENT_ID), label: 'Remove it' }
const liveFoot = (dashboard: string): SetupPageProps['foot'] => ({
  secondary: { label: 'Manage agent', href: R.agents },
  primary: { label: 'Open developer dashboard', href: dashboard, icon: 'arrow_ur' },
  note: ['Wasn’t you? ', { href: R.agentRemove(AGENT_ID), label: 'Remove this agent' }],
})

// ── 16 · Migration: MarketCheck to Auto.dev ──────────────────────────────────

const MIG = 'su_mig4'
const switchTodo = todo('switch', 'Switch over', 'Your code points at Auto.dev. Only when you say.')
const retireTodo = todo('retire', 'Old key retired', 'MarketCheck keeps working until then.')

const migRunning: SetupPageProps = {
  setup: run(MIG, AUTO_DEV, 'running', [
    done('approved', 'Agent approved', '14', UP_TO_500),
    done('found', 'Old calls found', '15', '14 MarketCheck calls in 6 files.'),
    done('mapped', 'Calls mapped', '16', '12 map straight across. 2 stay on MarketCheck, as you chose.'),
    {
      id: 'side_by_side',
      title: 'Side by side',
      detail: 'Running both on your real requests and comparing the answers.',
      state: 'now',
      evidence: {
        type: 'compare',
        rows: [
          { name: 'Decode a VIN', matched: 250, of: 250, state: 'ok' },
          { name: 'Search listings', matched: 181, of: 250, state: 'running' },
        ],
        note: 'A difference stops the switch and shows you both answers.',
      },
    },
    switchTodo,
    retireTodo,
  ]),
  agent: CLAUDE_CODE,
  title: 'Claude Code is moving you to Auto.dev',
  description: 'From MarketCheck. Nothing switches until both give the same answers.',
  sinceSeconds: 4,
  foot: { note: ['MarketCheck is untouched while this runs. ', { href: R.agentPause(AGENT_ID), label: 'Pause' }] },
}

const migDecide: SetupPageProps = {
  setup: run(MIG, AUTO_DEV, 'needs_person', [
    done('approved', 'Agent approved', '14'),
    done('found', 'Old calls found', '15', '14 MarketCheck calls in 6 files.'),
    {
      id: 'mapped',
      title: 'Calls mapped',
      detail: '12 of 14 map straight across.',
      state: 'you',
      evidence: {
        type: 'choice',
        items: [
          ['[OLD CALL A]', 'No equivalent yet'],
          ['[OLD CALL B]', 'No equivalent yet'],
        ],
        options: [
          { id: 'keep', title: 'Keep these two on MarketCheck', detail: 'Everything else moves. You run both for now.' },
          { id: 'replace', title: 'Have Claude Code replace them', detail: 'It builds each from other Auto.dev calls and proves it side by side.' },
        ],
        value: 'keep',
      },
    },
    todo('side_by_side', 'Side by side', 'Both run on your real requests.'),
    switchTodo,
    retireTodo,
  ]),
  agent: CLAUDE_CODE,
  title: 'Two calls have no match on Auto.dev',
  description: 'Claude Code mapped what it could. These two need your call.',
  sinceSeconds: 12,
  foot: {
    secondary: { label: 'Pause', href: R.agentPause(AGENT_ID) },
    primary: { label: 'Continue', value: 'answer', busyLabel: 'Continuing…' },
    note: 'Nothing has changed in your code yet.',
  },
  csrf: 'gallery',
}

const bothMatch = {
  type: 'compare',
  rows: [
    { name: 'Decode a VIN', matched: 250, of: 250, state: 'ok' },
    { name: 'Search listings', matched: 250, of: 250, state: 'ok' },
  ],
  note: 'Same requests, sent to both.',
} as const

const migSwitch: SetupPageProps = {
  setup: run(MIG, AUTO_DEV, 'needs_person', [
    done('approved', 'Agent approved', '14'),
    done('found', 'Old calls found', '15'),
    done('mapped', 'Calls mapped', '16'),
    { ...done('side_by_side', 'Side by side', '31', '500 of 500 answers match.'), evidence: { ...bothMatch, rows: [...bothMatch.rows] } },
    { id: 'switch', title: 'Switch over', detail: 'Claude Code changes 12 calls in 6 files and opens a pull request.', state: 'you' },
    retireTodo,
  ]),
  agent: CLAUDE_CODE,
  title: 'Ready to switch to Auto.dev',
  description: 'Both gave the same answers on 500 real requests. Your code still points at MarketCheck.',
  sinceSeconds: 8,
  foot: {
    secondary: { label: 'Not yet', value: 'later' },
    primary: { label: 'Switch to Auto.dev', value: 'switch', busyLabel: 'Switching…' },
    note: 'Growth is $299/month, inside your $500 limit.',
  },
  csrf: 'gallery',
}

const migDone: SetupPageProps = {
  setup: run(MIG, AUTO_DEV, 'live', [
    done('approved', 'Agent approved', '14'),
    done('found', 'Old calls found', '15'),
    done('mapped', 'Calls mapped', '16'),
    done('side_by_side', 'Side by side', '31', '500 of 500 answers match.'),
    done('switch', 'Switch over', '40', 'Pull request merged.'),
    // The old key is the person's to retire: the product never ticks this for them.
    todo('retire', 'Old key retired', 'Yours to do, in MarketCheck.'),
  ]),
  agent: CLAUDE_CODE,
  title: 'You’re on Auto.dev',
  description: 'Claude Code moved 12 calls. 2 stay on MarketCheck, as you chose.',
  top: [
    {
      kind: 'well',
      items: [
        { k: 'Moved', v: '12 calls in 6 files' },
        { k: 'Kept on MarketCheck', v: '2 calls' },
        { k: 'Plan', v: 'Growth · $299/month' },
        { k: 'Old key', v: 'Still active. Retire it when you’re ready.' },
      ],
    },
  ],
  foot: liveFoot('https://auto.dev/dashboard'),
}

// ── 17 · One job across three APIs ───────────────────────────────────────────

const JOB = 'su_job7'
const OUTBOUND: Product = { id: 'apis.ax', name: 'Outbound email', tile: 'Ax', dashboard_url: 'https://apis.email/dashboard' }
const LAYERS = { kind: 'icon', icon: 'layers' } as const
const DOMAIN_API = '[YOUR DOMAIN API]'

const jobApprove: SetupApproveProps = {
  ...setupProps.approve,
  title: 'Claude Code wants to set up outbound email for you',
  description: 'One approval covers three APIs. Pause or remove it anytime.',
  permissions: [
    {
      icon: 'globe',
      title: 'Register a domain',
      detail: 'With [YOUR DOMAIN API]. It shows you the name and the price first.',
      scope: 'domains:register · resource [YOUR DOMAIN API]',
      act: true,
      actNote: 'Spends real money, up to your limit.',
    },
    { icon: 'key', title: 'Add DNS records to that domain', detail: 'Only the records apis.email asks for.', scope: 'domains:dns · resource [YOUR DOMAIN API]' },
    {
      icon: 'mail',
      title: 'Send email through apis.email',
      detail: 'Subscribes only after a real email has arrived.',
      scope: 'email:subscribe · resource apis.email',
      act: true,
      actNote: 'Spends real money, up to your limit.',
    },
    { icon: 'clock', title: 'Stay connected while you’re away', detail: 'Keeps working until it expires or you remove it in Agents.', scope: 'offline_access' },
  ],
  spendLabel: 'Spend limit, all three',
  payLine: false,
  foot: { ...setupProps.approve.foot, note: 'One limit covers all three. You watch each step next.' },
}

const jobRunning: SetupPageProps = {
  setup: run(JOB, OUTBOUND, 'running', [
    done('approved', 'Agent approved', '14', UP_TO_500),
    done('domain', 'Domain registered', '16', '[YOUR DOMAIN], [PRICE] a year.', DOMAIN_API),
    done('dns', 'DNS records added', '16', 'Three records, as apis.email asked.', DOMAIN_API),
    {
      id: 'proved',
      title: 'Sending domain proved',
      detail: 'apis.email is looking for the records.',
      tag: 'apis.email',
      state: 'now',
      evidence: { type: 'listening', text: 'Looking up [YOUR DOMAIN]', elapsed: '1:20', note: 'New records can take a while to show.' },
    },
    todo('first_email', 'First real email', 'One has to arrive before the live key.', 'apis.email'),
    todo('live', 'Live', 'All three, on one bill.'),
  ]),
  agent: CLAUDE_CODE,
  rightTile: LAYERS,
  title: 'Claude Code is setting up outbound email',
  description: 'Three APIs, one after another. Each step ticks when it happens.',
  sinceSeconds: 4,
  foot: { note: ['Not your agent? ', removeIt] },
}

const jobDone: SetupPageProps = {
  setup: run(JOB, OUTBOUND, 'live', [
    done('approved', 'Agent approved', '14'),
    done('domain', 'Domain registered', '16'),
    done('dns', 'DNS records added', '16'),
    done('proved', 'Sending domain proved', '22'),
    done('first_email', 'First real email', '24', 'Delivered in 4 s.'),
    done('live', 'Live', '25'),
  ]),
  agent: CLAUDE_CODE,
  rightTile: LAYERS,
  title: 'Outbound email is live',
  description: 'Claude Code finished in 11 min. Three APIs, one bill.',
  top: [
    {
      kind: 'well',
      items: [
        { k: 'Domain', v: '[YOUR DOMAIN]' },
        { k: '[YOUR DOMAIN API]', v: '[PRICE] a year' },
        { k: 'apis.email', v: '[PRICE PER 1,000]' },
        { k: 'This month', v: '[TOTAL] of $500' },
      ],
    },
  ],
  foot: liveFoot('https://apis.email/dashboard'),
}

// ── 18 · Headless SaaS setup: a CRM on headless.ly ───────────────────────────

const CRM = 'su_crm2'
const HEADLESS: Product = { id: 'headless.ly', name: 'headless.ly', tile: 'h', dashboard_url: 'https://headless.ly/dashboard' }

const saasMap: SetupPageProps = {
  setup: run(CRM, HEADLESS, 'needs_person', [
    done('approved', 'Agent approved', '14'),
    done('workspace', 'Workspace created', '15', 'A CRM for Drivly on headless.ly.'),
    {
      id: 'import',
      title: 'Contacts imported',
      detail: '1,240 rows read from contacts.csv. Nothing is saved yet.',
      state: 'you',
      evidence: {
        type: 'field_map',
        rows: [
          { column: 'lead_src', options: ['Source', 'A new field: lead_src', 'Skip this column'], value: 'Source' },
          { column: 'acct_mgr', options: ['Owner', 'A new field: acct_mgr', 'Skip this column'], value: 'Owner' },
        ],
      },
    },
    todo('first_event', 'First real event', 'A change in the CRM has to reach your webhook.'),
    todo('live', 'Live'),
  ]),
  agent: CLAUDE_CODE,
  title: 'Two columns need a home',
  description: 'Claude Code is setting up your CRM on headless.ly. It matched 9 of 11 columns.',
  sinceSeconds: 12,
  foot: {
    secondary: { label: 'Skip both', value: 'skip' },
    primary: { label: 'Import 1,240 contacts', value: 'answer', busyLabel: 'Importing…' },
    note: 'You can change a mapping later in the developer dashboard.',
  },
  csrf: 'gallery',
}

const saasRunning: SetupPageProps = {
  setup: run(CRM, HEADLESS, 'running', [
    done('approved', 'Agent approved', '14', UP_TO_500),
    done('workspace', 'Workspace created', '15', 'A CRM for Drivly on headless.ly.'),
    {
      ...done('import', 'Contacts imported', '19', '1,228 saved. 12 skipped.'),
      evidence: {
        type: 'rows',
        rows: [
          ['Saved', '1,228 contacts'],
          ['Skipped', '12, no email address'],
          ['Columns matched', '11 of 11'],
        ],
      },
    },
    {
      id: 'first_event',
      title: 'First real event',
      detail: 'Waiting for a change in the CRM to reach your webhook.',
      state: 'now',
      // The gate is a real event: one the agent sends itself doesn't count.
      evidence: { type: 'listening', text: 'Listening on [YOUR WEBHOOK URL]', elapsed: '0:18', note: 'A test event sent by the agent doesn’t count.' },
    },
    todo('live', 'Live'),
  ]),
  agent: CLAUDE_CODE,
  title: 'Claude Code is setting up your CRM',
  description: 'On headless.ly. Each step ticks when it happens.',
  sinceSeconds: 4,
  foot: { note: ['Not your agent? ', removeIt] },
}

const saasLive: SetupPageProps = {
  setup: run(CRM, HEADLESS, 'live', [
    done('approved', 'Agent approved', '14'),
    done('workspace', 'Workspace created', '15'),
    done('import', 'Contacts imported', '19', '1,228 saved. 12 skipped.'),
    done('first_event', 'First real event', '21', 'contact.updated reached your webhook.'),
    done('live', 'Live', '21'),
  ]),
  agent: CLAUDE_CODE,
  title: 'Your CRM is live',
  description: 'Claude Code finished in 7 min. It is on headless.ly, with no screens to click through.',
  top: [
    {
      kind: 'well',
      items: [
        { k: 'Contacts', v: '1,228' },
        { k: 'Webhook', v: 'Receiving events' },
        { k: 'Plan', v: '[PRICE]/month' },
        { k: 'Live key', v: 'Ends in 9d1b · held by Claude Code' },
      ],
    },
  ],
  foot: liveFoot('https://headless.ly/dashboard'),
}

/** The default props per screen, shared with the screens' unit tests. */
export const workflowProps = { migRunning, migDecide, migSwitch, migDone, jobApprove, jobRunning, jobDone, saasMap, saasRunning, saasLive }

const page = setupPage

export const workflowFixtures: FixtureGroup = {
  '16a-mig-running': page(migRunning),
  '16b-mig-decide': page(migDecide),
  '16c-mig-switch': page(migSwitch),
  '16d-mig-done': page(migDone, []),
  '17a-job-approve': defineFixture({ screen: SetupApprove, title: (p) => `${p.title} · id.org.ai`, scripts: ['copy.js'], default: jobApprove }),
  '17b-job-running': page(jobRunning),
  '17c-job-done': page(jobDone, []),
  '18a-saas-map': page(saasMap),
  '18b-saas-running': page(saasRunning),
  '18c-saas-live': page(saasLive, []),
}
