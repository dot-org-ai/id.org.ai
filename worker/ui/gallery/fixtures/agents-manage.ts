/** Agents and policy (10a–10e, 13a, 13b) fixtures: strings copied verbatim from docs/agent-setup/screens. */
import { AGENT_ROUTES as R } from '../../agent-setup/routes'
import type { TileContent } from '../../components'
import { AgentCard, type AgentCardProps } from '../../screens/agent-setup/AgentCard'
import { defineFixture, type FixtureGroup } from '../types'
import { AGENT_ID, CLAUDE_CODE, ORG, PERSON, SETUP_ID } from './setup'

const BOT: TileContent = CLAUDE_CODE.tile
const who = { kind: 'who', name: PERSON.name, sub: PERSON.email } as const
const DRIVLY = { em: 'Drivly' }

const agents: AgentCardProps = {
  tiles: { single: BOT },
  title: 'Your agents',
  description: ['Three agents can act for you in ', DRIVLY, '.'],
  blocks: [
    { kind: 'dotted' },
    who,
    {
      kind: 'agents',
      agents: [
        {
          tile: { kind: 'icon', icon: 'bot' },
          name: 'Claude Code',
          line: 'Trusted · active 2 min ago',
          open: true,
          facts: [
            { k: 'Identity', v: 'ed25519 · 7f3a…c21d', mono: true },
            { k: 'Host', v: 'bryant-mbp (macOS)' },
            { k: 'Spent this month', v: '$299 of $500' },
            { k: 'Expires', v: 'Dec 22' },
          ],
          connections: [
            { name: 'Auto.dev', state: 'Live · key ends in 4f2a', link: { href: 'https://auto.dev/dashboard', label: 'Open dashboard' } },
            { name: 'apis.email', state: 'Setting up · first real call', link: { href: R.setup(SETUP_ID), label: 'Watch' } },
          ],
          pauseHref: R.agentPause(AGENT_ID),
          removeHref: R.agentRemove(AGENT_ID),
          links: [
            { href: R.agentActivity(AGENT_ID), label: 'View activity' },
            { href: R.spending, label: 'Spending' },
          ],
        },
        { tile: { kind: 'monogram', text: 'Cx' }, name: 'Codex', chip: 'Setting up', line: 'Sandboxed · this computer' },
        { tile: { kind: 'monogram', text: 'Su' }, name: 'Susan', chip: 'Paused', line: 'Trusted · headless.ly' },
      ],
    },
  ],
  foot: { note: 'Remove an agent and its keys stop working right away.' },
}

const remove: AgentCardProps = {
  tiles: { left: ORG, right: BOT, connector: 'idle' },
  title: 'Remove Claude Code?',
  description: 'It stops right away. To bring it back, you approve it again.',
  blocks: [
    {
      kind: 'well',
      label: 'What stops',
      items: [
        { k: 'Agent identity', v: 'ed25519 · 7f3a…c21d', mono: true },
        { k: 'Auto.dev live key', v: 'Ends in 4f2a' },
        { k: 'apis.email setup', v: 'Cancelled at the first real call' },
      ],
    },
    // Open decision 4: whether removing an agent cancels its subscriptions. Drawn as an unchecked choice.
    { kind: 'checkbox', id: 'remove-cancel-sub', name: 'cancel_subscription', label: 'Also cancel the Auto.dev subscription', detail: 'Left on, Growth keeps billing Drivly at $299/month.' },
  ],
  foot: {
    secondary: { label: 'Cancel', href: R.agents },
    primary: { label: 'Remove agent', value: 'remove', busyLabel: 'Removing…' },
    note: ['Not sure? ', { href: R.agentPause(AGENT_ID), label: 'Pause it instead' }],
  },
  action: R.agentRemove(AGENT_ID),
  csrf: 'gallery',
}

const empty: AgentCardProps = {
  tiles: { single: BOT },
  title: 'No agents yet',
  description: ['Agents you approve for ', DRIVLY, ' show up here.'],
  blocks: [{ kind: 'dotted' }, who, { kind: 'prompt', label: 'Give this to your agent', text: 'Set up Auto.dev through apis.ax. Follow [AGENT GUIDE URL].' }],
  foot: { note: 'Nothing can act for you until you approve it.' },
}

const pause: AgentCardProps = {
  tiles: { left: ORG, right: BOT, connector: 'idle' },
  title: 'Pause Claude Code?',
  description: 'It keeps its identity and keys. Nothing works until you resume it.',
  blocks: [
    {
      kind: 'well',
      label: 'While it’s paused',
      items: [
        { k: 'Auto.dev live key', v: 'Calls are refused' },
        { k: 'apis.email setup', v: 'Held at the first real call' },
        { k: 'Growth subscription', v: 'Keeps billing at $299/month' },
      ],
    },
    {
      kind: 'select',
      id: 'pause-resume',
      name: 'resume',
      label: 'Resume',
      options: [
        { value: 'manual', label: 'When I resume it' },
        { value: '1h', label: 'In 1 hour' },
        { value: 'tomorrow', label: 'Tomorrow at 9:00 AM' },
      ],
      selected: 'manual',
    },
  ],
  foot: {
    secondary: { label: 'Cancel', href: R.agents },
    primary: { label: 'Pause agent', value: 'pause', icon: 'pause', busyLabel: 'Pausing…' },
    note: ['Want it gone for good? ', { href: R.agentRemove(AGENT_ID), label: 'Remove it' }],
  },
  action: R.agentPause(AGENT_ID),
  csrf: 'gallery',
}

const activity: AgentCardProps = {
  tiles: { single: BOT },
  title: 'Claude Code activity',
  description: ['Everything it did for you in ', DRIVLY, ', newest first.'],
  blocks: [
    { kind: 'dotted' },
    {
      kind: 'activity',
      label: 'Today',
      rows: [
        { icon: 'shield_check', text: 'Passed the production check on Auto.dev', when: '2:17 PM' },
        { icon: 'card', text: 'Subscribed to Growth at $299/month', more: 'Spent money, inside your $500 limit.', money: true, when: '2:17 PM' },
        { icon: 'key', text: 'Got a live key for Auto.dev', when: '2:17 PM' },
        { icon: 'zap', text: 'Made its first real call to Auto.dev', more: 'GET /vin/1HGCM82633A004352 · 200', mono: true, when: '2:16 PM' },
        { icon: 'flask', text: 'Got a test key for Auto.dev', when: '2:14 PM' },
        { icon: 'user', text: 'Approved by you as Trusted', when: '2:14 PM' },
      ],
    },
  ],
  foot: {
    secondary: { label: 'Back to agents', href: R.agents },
    // Open decision 7: what Export produces. Drawn as a second quiet action.
    primary: { label: 'Export', value: 'export', quiet: true },
  },
  action: R.agentActivity(AGENT_ID),
  csrf: 'gallery',
}

const blocked: AgentCardProps = {
  // Blocked by workspace policy: the X, as on 7c.
  tiles: { left: ORG, right: BOT, connector: 'fail' },
  title: 'Drivly doesn’t let agents spend yet',
  description: 'Your workspace needs an admin to approve any agent with a spend limit.',
  blocks: [
    {
      kind: 'well',
      items: [
        { k: 'Agent', v: 'Claude Code' },
        { k: 'Asked to', v: 'Set up Auto.dev' },
        { k: 'Spend limit', v: '$500/month' },
      ],
    },
    { kind: 'textarea', id: 'blocked-note', name: 'note', label: 'Note to your admins (optional)', placeholder: 'Why it needs to spend' },
  ],
  foot: {
    secondary: { label: 'Continue without spending', href: R.setup(SETUP_ID) },
    primary: { label: 'Request approval', value: 'request', busyLabel: 'Sending…' },
    note: 'Admins get an email and can approve in one click.',
    noteIcon: 'send',
  },
  action: `${R.agents}/${AGENT_ID}/request`,
  csrf: 'gallery',
}

const adminApprove: AgentCardProps = {
  tiles: { left: ORG, right: BOT, connector: 'idle' },
  title: 'Let Claude Code spend for Drivly?',
  description: [{ em: 'Alex Rivera' }, ' asked to give their agent a spend limit.'],
  blocks: [
    { kind: 'dotted' },
    { kind: 'who', name: 'Nathan Clevenger', sub: 'nathan@do.industries · Drivly admin', switchHref: null },
    { kind: 'quote', text: '“Setting up Auto.dev for the pricing page rebuild.”' },
    {
      kind: 'permissions',
      heading: 'It asked to',
      items: [
        {
          icon: 'card',
          title: 'Subscribe to Auto.dev and get a live key',
          detail: 'One subscription on Drivly’s bill. Growth is $299/month.',
          scope: 'autodev:subscribe · resource https://api.auto.dev',
          act: true,
          actNote: 'Spends Drivly’s money, up to the limit.',
        },
      ],
    },
    {
      kind: 'select',
      id: 'admin-spend',
      name: 'spend_limit',
      label: 'Spend limit',
      options: [
        { value: '50000', label: '$500/month' },
        { value: '29900', label: '$299/month' },
        { value: '100000', label: '$1,000/month' },
      ],
      selected: '50000',
    },
    {
      kind: 'radios',
      legend: 'Approve for',
      name: 'approve_for',
      options: [
        { value: 'agent', title: 'This agent only', description: 'Alex’s other agents still need to ask.' },
        { value: 'person', title: 'Any agent Alex approves', description: 'Each one gets this limit.' },
      ],
      selected: 'agent',
    },
  ],
  foot: {
    secondary: { label: 'Decline', value: 'decline' },
    primary: { label: 'Approve', value: 'approve', busyLabel: 'Approving…' },
  },
  action: `${R.agents}/${AGENT_ID}/admin`,
  csrf: 'gallery',
}

/** The default props per screen, shared with the screens' unit tests. */
export const agentsManageProps = { agents, remove, empty, pause, activity, blocked, adminApprove }

const card = (props: AgentCardProps, scripts: 'copy.js'[] = []) => defineFixture({ screen: AgentCard, title: (p) => `${p.title} · id.org.ai`, scripts, default: props })

export const agentsManageFixtures: FixtureGroup = {
  '10a-agents': card(agents),
  '10b-agent-remove': card(remove),
  '10c-agents-empty': card(empty, ['copy.js']),
  '10d-agent-pause': card(pause),
  '10e-agent-activity': card(activity),
  '13a-agent-blocked': card(blocked),
  '13b-agent-admin-approve': card(adminApprove),
}
