/** Agents (5a–5d) group fixtures: strings copied verbatim from the mocks. */
import { ActionApproval, type ActionApprovalProps } from '../../screens/ActionApproval'
import { AgentApprove, type AgentApproveProps } from '../../screens/AgentApprove'
import { Claim, type ClaimProps } from '../../screens/Claim'
import { ClaimRepo, type ClaimRepoProps } from '../../screens/ClaimRepo'
import { defineFixture, type FixtureGroup } from '../types'

const approve: AgentApproveProps = {
  agent: {
    name: 'Claude Code',
    tile: { kind: 'icon', icon: 'bot' },
    host: 'bryant-mbp',
    os: 'macOS',
    askedAgo: '2 min ago',
    keyType: 'ed25519',
    fingerprint: '7f3a9e41b6d02c58e7a13f94d0b2c21d',
  },
  workspace: 'Drivly',
  trustLevels: [
    { value: 'sandboxed', title: 'Sandboxed', description: 'Works on sandbox copies. Can’t touch live data, send anything or spend.' },
    { value: 'trusted', title: 'Trusted', description: 'Reads and acts in Drivly. Asks you before it sends, deletes or spends.' },
    { value: 'privileged', title: 'Privileged', description: 'Acts without asking. You confirm with a passkey every 7 days.', accent: true },
  ],
  selectedTrust: 'trusted',
  spendLimits: [
    { value: '50', label: '$50 a month' },
    { value: '0', label: '$0 — no spending' },
    { value: '250', label: '$250 a month' },
    { value: 'none', label: 'No limit' },
  ],
  selectedSpend: '50',
  expiries: [
    { value: '30d', label: 'In 30 days' },
    { value: '7d', label: 'In 7 days' },
    { value: '90d', label: 'In 90 days' },
    { value: 'never', label: 'Never' },
  ],
  selectedExpiry: '30d',
  manageHref: '/account/agents',
  action: '/agents/approve/agt_7f3ac21d',
  csrf: 'gallery',
}

const action: ActionApprovalProps = {
  agent: { name: 'Susan', role: 'Support agent', app: 'headless.ly', workspace: 'Drivly', tile: { kind: 'monogram', text: 'Su' } },
  action: {
    kind: 'email',
    to: '412 customers in Q3 renewals',
    from: 'support@driv.ly',
    subject: 'Your renewal is coming up',
    excerpt: 'Hi Maria, your auto.dev plan renews on the 15th. Nothing changes unless you want it to — reply here with any questions.',
    viewHref: '/approvals/apr_q3renewals/preview',
  },
  secondsLeft: 272,
  alwaysAllowLabel: 'Always allow Susan to send renewal emails',
  formAction: '/approvals/apr_q3renewals',
  csrf: 'gallery',
}

const claim: ClaimProps = {
  agent: { name: 'Claude', tile: { kind: 'icon', icon: 'bot' } },
  app: 'headless.ly',
  stats: [
    { n: '47', label: 'contacts' },
    { n: '12', label: 'deals' },
    { n: '3', label: 'workflows' },
  ],
  sandboxEndsIn: '18 hours',
  account: { name: 'Bryant Skarda', email: 'bryant@driv.ly' },
  switchHref: '/account/choose',
  workspaces: [
    { value: 'org_drivly', label: 'Drivly' },
    { value: 'org_do', label: '.do Industries' },
    { value: 'new', label: 'New workspace…' },
  ],
  selectedWorkspace: 'org_drivly',
  repoHref: '/claim/clm_7Kx9m2/repo',
  action: '/claim/clm_7Kx9m2',
  csrf: 'gallery',
}

const repo: ClaimRepoProps = {
  command: 'npx id.org.ai claim clm_7Kx9m2',
  workflowPath: '.github/workflows/id.yml',
  workflowYaml: 'on: [push]\njobs:\n  identity:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: dot-org-ai/id@v1\n        with:\n          tenant: clm_7Kx9m2',
  repo: 'dot-do/headless-crm',
  statusUrl: '/api/claim/clm_7Kx9m2/status',
  claimHref: '/claim/clm_7Kx9m2',
}

/** The default props per screen, shared with the screens' unit tests. */
export const agentsProps = { approve, action, claim, repo }

export const agentsFixtures: FixtureGroup = {
  '5a-agent-approve': defineFixture({
    screen: AgentApprove,
    title: (p) => `Approve ${p.agent.name} · id.org.ai`,
    scripts: ['copy.js', 'submit.js'],
    default: approve,
    states: {
      copied: { ...approve, copied: true },
    },
    derived: {
      approved: { ...approve, state: 'approved' },
      rejected: { ...approve, state: 'rejected' },
    },
  }),
  '5b-action-approval': defineFixture({
    screen: ActionApproval,
    title: (p) => `Approve ${p.agent.name}’s request · id.org.ai`,
    scripts: ['countdown.js', 'submit.js'],
    default: action,
    derived: {
      expired: { ...action, state: 'expired', secondsLeft: 0 },
    },
  }),
  '5c-claim': defineFixture({
    screen: Claim,
    title: (p) => `Claim ${p.app} · id.org.ai`,
    scripts: ['submit.js'],
    default: claim,
  }),
  '5d-claim-repo': defineFixture({
    screen: ClaimRepo,
    title: () => 'Claim from a repository · id.org.ai',
    scripts: ['copy.js', 'claim-status.js'],
    default: repo,
    states: {
      copied: { ...repo, copied: true },
    },
    derived: {
      pending: { ...repo, status: 'pending' },
      claimed: { ...repo, status: 'claimed' },
    },
  }),
}
