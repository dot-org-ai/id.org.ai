/**
 * Paying (19a–22c) fixtures: strings copied verbatim from
 * docs/agent-setup/screens. UI only: nothing here calls Stripe. STRIPE.md says
 * what would back each screen.
 */
import { AGENT_ROUTES as R } from '../../agent-setup/routes'
import type { Product, Setup, SetupStep } from '../../agent-setup/types'
import type { TileContent } from '../../components'
import { AgentCard, type AgentCardProps } from '../../screens/agent-setup/AgentCard'
import { SetupPage, type SetupPageProps } from '../../screens/agent-setup/SetupPage'
import { defineFixture, type FixtureGroup } from '../types'
import { AGENT_ID, approved, AUTO_DEV, autoDev, CLAUDE_CODE, firstCallDone, liveKeyTodo, ORG, productionTodo, SETUP_ID, testKey, VISA } from './setup'

const BOT = CLAUDE_CODE.tile
const CARD: TileContent = { kind: 'icon', icon: 'card' }
const AD: TileContent = { kind: 'monogram', text: 'Ad' }
const DRIVLY = { em: 'Drivly' }
const MARKS = [10000, 50000, 100000, 200000, 500000]
const CAPPED = 'Real endpoints, capped at [TEST ALLOWANCE].'
const UP_TO_500 = 'Trusted in Drivly, up to $500/month.'
const removeThis = { href: R.agentRemove(AGENT_ID), label: 'Remove this agent' }
const run = (id: string, product: Product, state: Setup['state'], steps: SetupStep[]): Setup => ({ setup_id: id, product, agent_id: AGENT_ID, workspace_id: 'ws_drivly', state, steps, next_for_person: null })
const at = (hhmm: string) => `2026-11-22T19:${hhmm}:00Z`

// ── 19 · Paying ──────────────────────────────────────────────────────────────

const payAdd: AgentCardProps = {
  tiles: { left: ORG, right: CARD, connector: 'idle' },
  title: 'Add a payment method',
  description: ['For ', DRIVLY, '. Agents you approve charge it, inside the limits you set.'],
  blocks: [
    { kind: 'dotted' },
    // Stripe's Payment Element mounts here and draws its own Card, Bank account and Link tabs.
    // No key in the gallery, so it shows the picture.
    { kind: 'stripe' },
    { kind: 'dotted' },
    { kind: 'checkbox', id: 'pay-agents', name: 'agents_can_charge', label: 'Agents can charge this', detail: 'Only agents you approved, and only inside their limit.', checked: true },
  ],
  foot: {
    secondary: { label: 'Cancel', href: R.paymentMethods },
    primary: { label: 'Save payment method', value: 'save', busyLabel: 'Saving…' },
    // The consent for charging later without the person present. Never shortened or removed.
    note: 'By saving, you let agents you approve for Drivly charge this card inside the limits you set. Remove it anytime.',
    // Whose fields these are, said once, quietly, outside Stripe's part of the page (owner direction, 2026-11-23).
    secure: 'The card fields are Stripe’s. id.org.ai never sees the number.',
  },
  action: R.paymentMethodNew,
  csrf: 'gallery',
}

const autoDevTerms = { id: 'plan-terms', product: 'Auto.dev', termsHref: AUTO_DEV.terms_url as string, privacyHref: AUTO_DEV.privacy_url as string }

const planUsage: SetupPageProps = {
  setup: autoDev('needs_plan_approval', [
    approved('Trusted in Drivly. No spending yet.'),
    testKey(),
    firstCallDone(),
    {
      id: 'plan',
      title: 'Approve the plan',
      detail: 'A fixed $299/month, then a data fee on every call. Auto.dev sets no ceiling.',
      state: 'you',
      evidence: {
        type: 'plan',
        plan: 'Growth',
        price: '$299/month',
        rates: [
          ['Global VIN Decode', '$0.0025/call'],
          ['Vehicle Listings', '$0.0015/call'],
          ['OEM Build Data', '$0.10/call'],
        ],
        more_url: 'https://www.auto.dev/pricing',
        more_label: 'All 9 data fees',
      },
    },
    liveKeyTodo('Issued as soon as you approve.'),
    productionTodo(),
  ]),
  agent: CLAUDE_CODE,
  title: 'Growth is a plan plus what it uses',
  description: 'Auto.dev works on the test key. Claude Code is ready to subscribe for you.',
  sinceSeconds: 12,
  payMethod: VISA,
  // Open decision 17: the default spend limit for a plan plus usage. Drawn as "No limit" with alerts on.
  spend: { id: 'plan', planPrice: '$299', limit: { options: [null, ...MARKS], value: null }, alerts: { marks: MARKS, on: true } },
  foot: {
    // The drawing shows the line ticked so the button reads as active; it loads unticked (the `unticked` state).
    terms: { ...autoDevTerms, checked: true },
    secondary: { label: 'Not now', value: 'later' },
    primary: { label: 'Approve Growth', value: 'approve_plan', busyLabel: 'Approving…' },
    note: 'Stripe bills the plan and the month’s data fees together, on one invoice.',
  },
  csrf: 'gallery',
}

const payOnce: AgentCardProps = {
  tiles: { left: BOT, right: ORG, connector: 'idle' },
  secondsLeft: 272,
  title: 'Claude Code wants to buy a domain',
  description: 'One time · Trusted agent · Drivly',
  blocks: [
    {
      kind: 'well',
      tight: true,
      items: [
        { k: 'Buying', v: '[YOUR DOMAIN], one year' },
        { k: 'From', v: '[YOUR DOMAIN API]' },
        { k: 'Price', v: '[PRICE]' },
        { k: 'Left this month', v: '$201 of $500' },
      ],
      excerpt: 'Part of the outbound email setup you approved.',
    },
    { kind: 'payline', method: VISA },
    // Off by default.
    { kind: 'checkbox', id: 'once-always', name: 'always_allow', label: 'Stop asking for purchases like this', detail: 'From [YOUR DOMAIN API], up to this price.' },
  ],
  foot: {
    secondary: { label: 'Deny', value: 'deny' },
    primary: { label: 'Approve purchase', value: 'approve', busyLabel: 'Approving…' },
    note: 'Drivly asks you before any single charge over $50.',
  },
  action: `${R.spending}/purchases/pur_3k1`,
  csrf: 'gallery',
}

const stepUp: AgentCardProps = {
  tiles: { left: ORG, right: { kind: 'icon', icon: 'fingerprint' }, connector: 'idle' },
  secondsLeft: 250,
  title: 'Confirm it’s you',
  description: 'Raising Claude Code to $1,000/month needs your passkey.',
  blocks: [
    {
      kind: 'well',
      items: [
        { k: 'Agent', v: 'Claude Code' },
        { k: 'New limit', v: '$1,000/month' },
        { k: 'Was', v: '$500/month' },
        { k: 'Pays with', v: VISA },
      ],
    },
  ],
  foot: {
    secondary: { label: 'Cancel', value: 'cancel' },
    primary: { label: 'Use passkey', value: 'passkey', icon: 'key', busyLabel: 'Checking…' },
    note: 'Drivly asks for a passkey on any limit over $500/month.',
  },
  action: `${R.agents}/${AGENT_ID}/limit/confirm`,
  csrf: 'gallery',
}

const confirmBank: SetupPageProps = {
  setup: autoDev('needs_bank_confirmation', [
    approved(UP_TO_500),
    testKey(CAPPED),
    firstCallDone(),
    { id: 'bank', title: 'Confirm with your bank', detail: 'Visa ending 4417 needs you to approve $299 to Auto.dev.', state: 'you' },
    liveKeyTodo('Issued as soon as the payment goes through.'),
    productionTodo(),
  ]),
  agent: CLAUDE_CODE,
  title: 'Your bank wants to confirm this payment',
  description: 'Claude Code can’t answer for you. It is waiting with a working test key.',
  sinceSeconds: 8,
  foot: {
    secondary: { label: 'Use another card', href: R.paymentMethodNew },
    primary: { label: 'Confirm with your bank', value: 'confirm_bank', icon: 'arrow_ur', busyLabel: 'Opening your bank…' },
    note: 'Opens your bank’s own screen, through Stripe. Nothing is charged until you confirm.',
  },
  csrf: 'gallery',
}

const renewalFailed: SetupPageProps = {
  // Account-level (renewal_failed): the setup itself is live, and the key keeps working until the stop date.
  setup: autoDev('live', [
    { id: 'first_try', title: 'First try', detail: 'Declined by your bank.', state: 'fail', label: 'Dec 22' },
    { id: 'second_try', title: 'Second try', detail: 'Dec 25, on the same card unless you change it.', state: 'todo' },
    { id: 'key_stops', title: 'Live key stops', detail: 'Dec 29, if the invoice is still unpaid.', state: 'todo' },
  ]),
  connector: 'hold',
  agent: CLAUDE_CODE,
  title: 'The Auto.dev renewal didn’t go through',
  description: 'Drivly’s card ending 4417 was declined. The live key keeps working for now.',
  top: [
    {
      kind: 'well',
      items: [
        { k: 'Invoice', v: 'Growth, $299.00 · data fees, $126.00' },
        { k: 'Total', v: '$425.00' },
        { k: 'Agent', v: 'Claude Code' },
      ],
    },
  ],
  foot: {
    secondary: { label: 'Cancel Growth', value: 'cancel_plan' },
    primary: { label: 'Update payment method', href: R.paymentMethodNew },
    note: 'Claude Code keeps working until Dec 29.',
  },
  csrf: 'gallery',
}

const limitReached: AgentCardProps = {
  tiles: { left: BOT, right: ORG, connector: 'hold' },
  title: 'Claude Code reached its $500 limit',
  description: 'Paid calls are refused until Dec 1, or until you raise it. Plans already running keep running.',
  blocks: [
    {
      kind: 'limit',
      label: 'November',
      amount: '$500.00',
      of: '$500',
      percent: 100,
      lines: [
        { k: 'Auto.dev · Growth', v: '$299.00' },
        { k: 'Auto.dev · data fees, 50,400 calls', v: '$126.00' },
        { k: 'apis.email', v: '$75.00' },
      ],
    },
    {
      kind: 'select',
      id: 'limit-new',
      name: 'limit',
      label: 'New limit',
      options: [
        { value: '75000', label: '$750/month', short: '$750' },
        { value: '100000', label: '$1,000/month', short: '$1,000' },
        { value: 'none', label: 'No limit', short: 'no limit' },
      ],
      selected: '75000',
    },
  ],
  foot: {
    secondary: { label: 'Keep $500', value: 'keep' },
    primary: { label: 'Raise to $750', value: 'raise', busyLabel: 'Raising…', follows: { control: 'limit', template: 'Raise to {label}' } },
    note: 'Test keys keep working either way.',
  },
  action: `${R.agents}/${AGENT_ID}/limit`,
  csrf: 'gallery',
}

// ── 20 · Money views ─────────────────────────────────────────────────────────

const CHARGE = 'ch_9a2f'

const spending: AgentCardProps = {
  tiles: { single: CARD },
  title: 'Spending',
  description: ['What your agents spent for ', DRIVLY, ' in November.'],
  blocks: [
    { kind: 'dotted' },
    { kind: 'total', amount: '$441.20', note: 'of $850 your agents may spend · $41.20 still running' },
    {
      kind: 'spendrows',
      label: 'By agent',
      rows: [
        { tile: { kind: 'icon', icon: 'bot' }, name: 'Claude Code', amount: '$340.20', limit: '$500', percent: 68, line: 'Auto.dev', href: R.agents },
        { tile: { kind: 'monogram', text: 'Su' }, name: 'Susan', amount: '$100.00', limit: '$250', percent: 40, line: 'headless.ly · paused', href: R.agents },
        { tile: { kind: 'monogram', text: 'Cx' }, name: 'Codex', amount: '$0.00', limit: '$100', percent: 0, line: 'Setting up · nothing spent', href: R.agents },
      ],
    },
    {
      kind: 'charges',
      label: 'This month',
      rows: [
        // "Running" is usage not yet billed: the amount and the call count come from the product.
        { name: 'Auto.dev · data fees', chip: 'Running', line: '16,480 calls so far · billed Dec 22', amount: '$41.20', href: R.charge('usage_autodev') },
        { name: 'Auto.dev · Growth', line: 'Nov 22 · Claude Code', amount: '$299.00', href: R.charge(CHARGE) },
        { name: 'headless.ly', line: 'Nov 14 · Susan', amount: '$100.00', href: R.charge('ch_7c1d') },
      ],
    },
  ],
  foot: {
    secondary: { label: 'Payment methods', href: R.paymentMethods },
    primary: { label: 'Spending rules', href: R.spendRules, quiet: true },
    note: 'Calls and logs for each API live in its developer dashboard.',
  },
}

const payMethods: AgentCardProps = {
  tiles: { single: CARD },
  title: 'Payment methods',
  description: ['What agents can charge for ', DRIVLY, '.'],
  blocks: [
    { kind: 'dotted' },
    {
      kind: 'methods',
      methods: [
        { icon: 'card', title: 'Visa ending 4417', chip: 'Default', sub: 'Expires 08/28 · charged by 3 agents', link: { href: R.paymentMethodNew, label: 'Replace' } },
        { icon: 'bank', title: 'Bank account ending 2210', sub: 'Agents can’t charge this', link: { href: `${R.paymentMethods}/pm_2210/agents`, label: 'Allow agents' } },
      ],
    },
    {
      kind: 'well',
      label: 'Billing details',
      items: [
        { k: 'Billed to', v: 'Drivly, Inc.' },
        { k: 'Receipts go to', v: 'bryant@driv.ly' },
        { k: 'Tax ID', v: '[TAX ID]' },
      ],
    },
  ],
  foot: {
    // Invoices and tax details live in Stripe's billing portal, not here.
    secondary: { label: 'Invoices', value: 'portal', icon: 'arrow_ur' },
    primary: { label: 'Add payment method', href: R.paymentMethodNew },
    note: 'Invoices and tax details open in Stripe’s billing portal.',
  },
  action: R.paymentMethods,
  csrf: 'gallery',
}

const charge: AgentCardProps = {
  tiles: { left: BOT, right: AD, connector: 'ok' },
  title: '$299.00 to Auto.dev',
  description: 'Charged by Claude Code on Nov 22 at 2:17 PM.',
  blocks: [
    {
      kind: 'well',
      items: [
        { k: 'For', v: 'Growth · Nov 22 to Dec 22' },
        { k: 'Paid with', v: VISA },
        { k: 'Workspace', v: 'Drivly' },
        { k: 'On your statement', v: '[STATEMENT NAME]' },
      ],
    },
    {
      kind: 'well',
      label: 'Allowed by',
      items: [
        { k: 'Your approval', v: 'Nov 22, 2:14 PM' },
        { k: 'Limit then', v: '$500/month' },
        { k: 'Used after this charge', v: '$299 of $500' },
      ],
    },
  ],
  foot: {
    // One action for now (owner direction, 2026-11-23). The drawing also has "Ask for a refund" on the
    // left; who decides a refund is still open (decision 14), so it isn't offered. To bring it back:
    // secondary: { label: 'Ask for a refund', value: 'refund' },
    primary: { label: 'View receipt', value: 'receipt', icon: 'arrow_ur' },
    note: ['Didn’t expect this? ', { href: R.agentPause(AGENT_ID), label: 'Pause Claude Code' }],
  },
  action: R.charge(CHARGE),
  csrf: 'gallery',
}

const spendRules: AgentCardProps = {
  tiles: { single: { kind: 'icon', icon: 'shield_check' } },
  title: 'Spending rules',
  description: ['How agents may spend for ', DRIVLY, '.'],
  blocks: [
    { kind: 'dotted' },
    {
      kind: 'select',
      id: 'rule-start',
      name: 'new_agent_limit',
      label: 'A new agent starts with',
      options: [
        { value: '50000', label: '$500/month' },
        { value: '0', label: '$0, ask every time' },
        { value: '10000', label: '$100/month' },
        { value: '100000', label: '$1,000/month' },
      ],
      selected: '50000',
    },
    {
      kind: 'select',
      id: 'rule-ask',
      name: 'ask_over',
      label: 'Ask me before any single charge over',
      options: [
        { value: '5000', label: '$50' },
        { value: '10000', label: '$100' },
        { value: '30000', label: '$300' },
        { value: 'never', label: 'Never, inside the limit' },
      ],
      selected: '5000',
    },
    {
      kind: 'select',
      id: 'rule-passkey',
      name: 'passkey_over',
      label: 'Ask for my passkey on any limit over',
      options: [
        { value: '50000', label: '$500/month' },
        { value: '100000', label: '$1,000/month' },
        { value: 'always', label: 'Every limit' },
        { value: 'never', label: 'Never' },
      ],
      selected: '50000',
    },
    {
      kind: 'select',
      id: 'rule-who',
      name: 'who_approves',
      label: 'Who can approve an agent that spends',
      options: [
        { value: 'admins', label: 'Admins only' },
        { value: 'members_100', label: 'Any member, up to $100/month' },
        { value: 'members', label: 'Any member' },
      ],
      selected: 'admins',
    },
    { kind: 'toggle', id: 'rule-receipts', name: 'email_receipts', title: 'Email a receipt for every charge', sub: 'Sent to bryant@driv.ly.', checked: true },
  ],
  foot: {
    secondary: { label: 'Cancel', href: R.spending },
    primary: { label: 'Save rules', value: 'save', busyLabel: 'Saving…' },
    note: 'An agent’s own limit can be lower than these, never higher.',
  },
  action: R.spendRules,
  csrf: 'gallery',
}

// ── 21 · Alternate endings of the setup run ──────────────────────────────────

const APIS_EMAIL: Product = { id: 'apis.ax', api: 'apis.email', name: 'apis.email', tile: '@', dashboard_url: 'https://apis.email/dashboard' }

const payPerCall: SetupPageProps = {
  // Pay per call: no plan to pick. Calls are counted and billed monthly, on the saved method (owner
  // direction, 2026-11-23). Nothing is charged per call, so the card minimum never comes into it.
  setup: run('su_ppc3', APIS_EMAIL, 'live', [
    { id: 'approved', title: 'Agent approved', detail: UP_TO_500, state: 'done', at: at('14') },
    { id: 'first_paid_call', title: 'First paid call', detail: 'Counted toward this month’s bill. 200 in 180 ms.', state: 'done', at: at('15') },
    { id: 'production', title: 'Ready for production', detail: 'Backed off and retried after a 429.', state: 'done', at: at('16') },
  ]),
  agent: CLAUDE_CODE,
  title: 'apis.email is live, paying per call',
  description: 'No plan to pick. Claude Code pays only for the calls it makes, billed monthly.',
  top: [
    {
      kind: 'well',
      items: [
        { k: 'Price', v: '[PRICE]/call' },
        { k: 'Billed', v: 'Monthly, for the calls made' },
        { k: 'Pays with', v: VISA },
        { k: 'Spend limit', v: '$500/month' },
      ],
    },
  ],
  foot: {
    secondary: { label: 'Manage agent', href: R.agents },
    primary: { label: 'Open developer dashboard', href: 'https://apis.email/dashboard', icon: 'arrow_ur' },
    note: ['Wasn’t you? ', removeThis],
  },
}

// 21b: Link asks the person, on Link's own site or app, at the approval URL Link returns. A request
// lasts 30 minutes (docs.stripe.com/agentic-commerce/agents/link-agent-wallet). Link agent payments
// are for US and Canadian customers, so this ending only appears for them.
const LINK_APPROVAL = 'https://app.link.com/activity/approve/lsrq_gallery'
const walletSteps = (wallet: SetupStep): SetupStep[] => [approved('Trusted in Drivly. No card on file here.'), testKey(CAPPED), firstCallDone(), wallet, liveKeyTodo('Issued as soon as Link says yes.'), productionTodo()]
const useCardInstead = { label: 'Use a card here instead', href: R.paymentMethodNew }

const payWallet: SetupPageProps = {
  setup: autoDev('needs_wallet_approval', walletSteps({ id: 'wallet', title: 'Approve in Link', detail: 'Link is asking you to approve $299. The request runs out at 2:46 PM.', state: 'you' })),
  agent: CLAUDE_CODE,
  title: 'Approve this in Link',
  description: 'Claude Code is paying from your Link wallet, so Link asks you, not id.org.ai.',
  sinceSeconds: 12,
  foot: {
    secondary: useCardInstead,
    primary: { label: 'Open Link', href: LINK_APPROVAL, icon: 'arrow_ur', newTab: true },
    note: 'A wallet keeps its own limits. id.org.ai still shows every charge.',
  },
}

/** Link's other answers (its spend request statuses: denied, expired, requires_action). Not drawn. */
const walletDenied: SetupPageProps = {
  ...payWallet,
  setup: autoDev('payment_declined', walletSteps({ id: 'wallet', title: 'Approve in Link', detail: 'You said no in Link. Nothing was charged.', state: 'fail', label: 'Denied' })),
  title: 'You denied this in Link',
  description: 'Claude Code can’t go live on Auto.dev without a way to pay. The test key still works.',
  sinceSeconds: 8,
  foot: { secondary: useCardInstead, primary: { label: 'Ask Link again', value: 'retry_wallet', busyLabel: 'Asking…' }, note: 'Nothing is charged until you approve.' },
  csrf: 'gallery',
}
const walletExpired: SetupPageProps = {
  ...payWallet,
  setup: autoDev('needs_wallet_approval', walletSteps({ id: 'wallet', title: 'Approve in Link', detail: 'Link’s request ran out after 30 minutes without an answer.', state: 'you', label: 'Ran out' })),
  title: 'Link’s request ran out',
  description: 'Claude Code is still waiting with a working test key. Ask again when you’re ready.',
  sinceSeconds: 60,
  foot: { secondary: useCardInstead, primary: { label: 'Ask Link again', value: 'retry_wallet', busyLabel: 'Asking…' }, note: 'Nothing was charged.' },
  csrf: 'gallery',
}
const walletNeedsAction: SetupPageProps = {
  ...payWallet,
  // Link says what it needs, in its own words (`next_action.display_message`), shown as written.
  setup: autoDev('needs_wallet_approval', walletSteps({ id: 'wallet', title: 'Approve in Link', detail: 'Verify your identity in Link to finish this payment.', state: 'you', label: 'Link needs you' })),
  title: 'Link needs one more thing',
  description: 'Only you can do this. Claude Code can’t answer Link for you.',
  foot: { secondary: useCardInstead, primary: { label: 'Open Link', href: LINK_APPROVAL, icon: 'arrow_ur', newTab: true }, note: 'A wallet keeps its own limits. id.org.ai still shows every charge.' },
}

// ── 22 · Seller payouts ──────────────────────────────────────────────────────

const APIS_AX: Product = { id: 'apis.ax', name: 'APIs.ax', tile: 'Ax', dashboard_url: 'https://apis.ax/dashboard/payouts' }
const SELL = 'su_sell5'
const sellerDone: SetupStep[] = [
  { id: 'approved', title: 'Agent approved', state: 'done', at: at('14') },
  { id: 'listed', title: 'Listed', state: 'done', label: 'Nov 23' },
  { id: 'prices', title: 'Prices sent', state: 'done', at: at('15') },
]
const firstPaidTodo: SetupStep = { id: 'first_paid_call', title: 'First paid call', detail: 'An agent pays for one real call.', state: 'todo' }
const sellingTodo: SetupStep = { id: 'selling', title: 'Selling', detail: 'On APIs.ax, paid out by Stripe.', state: 'todo' }

const payoutSetup: SetupPageProps = {
  setup: run(SELL, APIS_AX, 'needs_person', [
    { ...sellerDone[0]!, detail: 'Trusted in Drivly. No spending.' },
    { ...sellerDone[1]!, detail: 'At apis.directory/api/[your-api].' },
    { ...sellerDone[2]!, detail: '[PRICE]/call, as Claude Code set it.' },
    {
      id: 'payouts',
      title: 'Payouts set up',
      detail: 'Stripe asks about your business, its owner and a bank account.',
      state: 'you',
      evidence: {
        type: 'rows',
        rows: [
          ['Asked by', 'Stripe, for APIs.ax'],
          ['Have ready', 'Business details, an ID, a bank account'],
          ['Takes about', '[TIME]'],
        ],
      },
    },
    firstPaidTodo,
    sellingTodo,
  ]),
  agent: CLAUDE_CODE,
  title: 'Set up payouts to start selling',
  description: 'Claude Code did the rest. Stripe has to hear who gets paid from a person.',
  sinceSeconds: 12,
  foot: {
    secondary: { label: 'Not now', value: 'later' },
    primary: { label: 'Continue to Stripe', value: 'stripe_onboarding', icon: 'arrow_ur', busyLabel: 'Opening Stripe…' },
    note: 'The listing stays up either way. You only need this to charge.',
  },
  csrf: 'gallery',
}

const payoutMore: SetupPageProps = {
  setup: run(SELL, APIS_AX, 'needs_person', [
    ...sellerDone,
    { id: 'payouts', title: 'Payouts set up', detail: 'A document that shows the address of [BUSINESS NAME].', state: 'you', label: 'Due [DATE]' },
    firstPaidTodo,
    sellingTodo,
  ]),
  agent: CLAUDE_CODE,
  title: 'Stripe needs one more thing',
  description: 'Payouts are on hold until Stripe has it. An agent can’t send it for you.',
  sinceSeconds: 60,
  foot: {
    secondary: { label: 'Email me the link', value: 'email_link' },
    primary: { label: 'Continue to Stripe', value: 'stripe_onboarding', icon: 'arrow_ur', busyLabel: 'Opening Stripe…' },
    note: 'Only Stripe sees the document.',
  },
  csrf: 'gallery',
}

const payoutOn: SetupPageProps = {
  setup: run(SELL, APIS_AX, 'live', [
    ...sellerDone,
    { id: 'payouts', title: 'Payouts set up', detail: 'Stripe confirmed [BUSINESS NAME].', state: 'done', label: 'Nov 24' },
    { id: 'first_paid_call', title: 'First paid call', detail: 'An agent paid for one real call.', state: 'done', label: 'Nov 24' },
    { id: 'selling', title: 'Selling', state: 'done', label: 'Nov 24' },
  ]),
  agent: CLAUDE_CODE,
  title: 'Your API is selling on APIs.ax',
  description: 'Agents can pay for it now, and Stripe pays you out.',
  top: [
    {
      kind: 'well',
      items: [
        { k: 'Paid out to', v: 'Bank account ending 2210' },
        { k: 'Payouts', v: '[PAYOUT SCHEDULE]' },
        { k: 'APIs.ax keeps', v: '[FEE]' },
        { k: 'First paid call', v: '[PRICE], from an agent' },
      ],
    },
  ],
  foot: {
    secondary: { label: 'Manage agent', href: R.agents },
    primary: { label: 'Open payouts', href: 'https://apis.ax/dashboard/payouts', icon: 'arrow_ur' },
    note: 'Balance, payouts and tax forms live in Stripe.',
  },
}

/** The default props per screen, shared with the screens' unit tests. */
export const paymentProps = { payAdd, planUsage, payOnce, stepUp, confirmBank, renewalFailed, limitReached, spending, payMethods, charge, spendRules, payPerCall, payWallet, payoutSetup, payoutMore, payoutOn, setupId: SETUP_ID }

type Script = 'ago.js' | 'countdown.js' | 'follow.js' | 'disclose.js' | 'terms.js' | 'stripe-fields.js'
const page = (props: SetupPageProps, scripts: Script[] = ['ago.js'], derived?: Record<string, SetupPageProps>) => defineFixture({ screen: SetupPage, title: (p) => `${p.title} · id.org.ai`, scripts, default: props, derived })
const card = (props: AgentCardProps, scripts: Script[] = []) => defineFixture({ screen: AgentCard, title: (p) => `${p.title} · id.org.ai`, scripts, default: props })

export const paymentFixtures: FixtureGroup = {
  '19a-pay-add': card(payAdd, ['stripe-fields.js']),
  '19b-pay-plan-usage': page(planUsage, ['ago.js', 'disclose.js', 'terms.js'], {
    // Not drawn: how the page loads. The terms line is unticked and the primary action is disabled.
    unticked: { ...planUsage, foot: { ...planUsage.foot, terms: autoDevTerms } },
    // Not drawn: an API that offers alerts but no limit, and one that offers a limit but no alerts.
    'alerts-only': { ...planUsage, spend: { id: 'plan', alerts: { marks: MARKS, on: true, open: true } } },
    'limit-only': { ...planUsage, spend: { id: 'plan', planPrice: '$299', limit: { options: [null, ...MARKS], value: null } } },
    // Not drawn: no payment method on file, so the pays-with line offers to add one.
    'no-card': { ...planUsage, payMethod: undefined },
  }),
  '19c-pay-once': defineFixture({
    screen: AgentCard,
    title: (p) => `${p.title} · id.org.ai`,
    scripts: ['countdown.js'],
    default: payOnce,
    derived: {
      // Not drawn: a purchase with tax, as Stripe's checkout totals carry it (subtotal, tax, total).
      'with-tax': {
        ...payOnce,
        blocks: payOnce.blocks.map((b) =>
          b.kind === 'well'
            ? { ...b, items: [{ k: 'Buying', v: '[YOUR DOMAIN], one year' }, { k: 'From', v: '[YOUR DOMAIN API]' }, { k: 'Price', v: '[PRICE]' }, { k: 'Tax', v: '[TAX]' }, { k: 'Total', v: '[TOTAL]' }, { k: 'Left this month', v: '$201 of $500' }] }
            : b,
        ),
      },
    },
  }),
  '19d-pay-step-up': card(stepUp, ['countdown.js']),
  '19e-pay-confirm-bank': page(confirmBank),
  '19f-pay-renewal-failed': page(renewalFailed, []),
  '19g-pay-limit-reached': card(limitReached, ['follow.js']),
  '20a-spending': card(spending),
  '20b-pay-methods': card(payMethods),
  '20c-charge': card(charge),
  '20d-spend-rules': card(spendRules),
  '21a-pay-per-call': page(payPerCall, []),
  '21b-pay-wallet': page(payWallet, ['ago.js'], { denied: walletDenied, expired: walletExpired, 'needs-action': walletNeedsAction }),
  '22a-payout-setup': page(payoutSetup),
  '22b-payout-more': page(payoutMore),
  '22c-payout-on': page(payoutOn, []),
}
