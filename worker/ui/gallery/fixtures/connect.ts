/**
 * Connect from Claude (24a–24c) fixtures: strings copied verbatim from
 * docs/agent-setup/screens. The plans are Auto.dev's real ones (HANDOFF.md
 * section 8), as the Pricing contract a product would send.
 */
import { AGENT_ROUTES as R } from '../../agent-setup/routes'
import type { PlanOffer, Pricing } from '../../agent-setup/types'
import { AgentCard, type AgentCardProps } from '../../screens/agent-setup/AgentCard'
import { ConnectPay, ConnectPlan, type ConnectClient, type ConnectPayProps, type ConnectPlanProps } from '../../screens/agent-setup/Connect'
import { defineFixture, type FixtureGroup } from '../types'
import { AUTO_DEV, AUTO_DEV_BRANDED, AUTO_DEV_LOGO, PERSON, VISA } from './setup'

const CLAUDE: ConnectClient = { id: 'claude', name: 'Claude', tile: 'Cl' }
const MARKS = [10000, 50000, 100000, 200000, 500000]
const TRIAL = { days: 7, price: 100 }

const growth: PlanOffer = {
  id: 'growth',
  name: 'Growth',
  recommended: true,
  price: { monthly: 29900, yearly_per_month: 24900 },
  price_note: '/month + data fees',
  summary: 'Unlimited calls · 10 requests a second',
  included: [
    { label: 'Global VIN Decode', value: '$0.0025/call' },
    { label: 'Vehicle Listings', value: '$0.0015' },
    { label: 'Vehicle Photos', value: '$0.0009' },
    { label: 'Specifications', value: '$0.0015' },
    { label: 'OEM Build Data', value: '$0.10' },
    { label: 'Interest Rates', value: '$0.005' },
    { label: 'Vehicle Payments', value: '$0.005' },
    { label: 'Vehicle Recalls', value: '$0.01' },
    { label: 'Total Cost of Ownership', value: '$0.06' },
    { label: 'MCP server, CLI and SDK' },
    { label: 'Priority email support' },
  ],
  trial: TRIAL,
}

/** Auto.dev's plans, read from auto.dev/pricing on Nov 22, 2026. */
export const AUTO_DEV_PRICING: Pricing = {
  plans: [
    {
      id: 'free',
      name: 'Free',
      price: { monthly: 0 },
      summary: '1,000 calls a month · 5 requests a second',
      included: [{ label: 'Global VIN Decode', value: 'Included' }, { label: 'Vehicle Listings', value: 'Included' }, { label: 'Vehicle Photos', value: 'Included' }, { label: 'MCP server, CLI and SDK' }],
    },
    growth,
    {
      id: 'scale',
      name: 'Scale',
      price: { monthly: 59900, yearly_per_month: 49900 },
      price_note: '/month + data fees',
      summary: 'Unlimited calls · 50 requests a second',
      // Listed without their fees: two published prices for Plate-to-VIN disagree (HANDOFF.md section 8).
      included: [{ label: 'Everything in Growth, at lower data fees' }, { label: 'Plate-to-VIN' }, { label: 'Open Recalls' }, { label: 'Taxes and Fees' }],
      trial: TRIAL,
    },
  ],
  spend: {
    basis: 'usage_on_top_of_plan',
    limit: { options: [null, ...MARKS], default: null },
    alerts: { marks: MARKS, default_on: true },
  },
}

const plan: ConnectPlanProps = { client: CLAUDE, product: AUTO_DEV, account: PERSON, pricing: AUTO_DEV_PRICING, action: R.connectPlan(CLAUDE.id), csrf: 'gallery' }

const pay: ConnectPayProps = {
  client: CLAUDE,
  product: AUTO_DEV,
  workspace: 'Drivly',
  plan: growth,
  // Open decision 12: whether connectors get the $1 trial. Drawn with it here and on 24c.
  trialEnds: 'Nov 29',
  feesNote: 'Per call, billed monthly',
  spend: AUTO_DEV_PRICING.spend,
  payMethod: VISA,
  permissions: [
    { icon: 'zap', title: 'Call Auto.dev for you', detail: 'Each call counts toward your plan and adds its data fee.', scope: 'autodev:call · resource https://api.auto.dev', act: true, actNote: 'Spends real money as it’s used.' },
    { icon: 'clock', title: 'Stay connected', detail: 'Until you disconnect it in Agents.', scope: 'offline_access' },
  ],
  // The drawing shows the line ticked so the button reads as active; it loads unticked (the `unticked` state).
  termsChecked: true,
  action: R.connectPay(CLAUDE.id),
  csrf: 'gallery',
}

const done: AgentCardProps = {
  tiles: { left: { kind: 'monogram', text: 'Cl' }, right: { kind: 'monogram', text: 'Ad' }, connector: 'ok' },
  title: 'Auto.dev is connected to Claude',
  description: 'Head back to Claude. This tab can close.',
  blocks: [
    {
      kind: 'well',
      items: [
        { k: 'Plan', v: 'Growth · $299/month + data fees' },
        { k: 'Trial', v: '7 days for $1, ends Nov 29' },
        { k: 'Pays with', v: VISA },
        { k: 'Spend limit', v: 'None' },
        { k: 'Spend alerts', v: 'On, from $100' },
      ],
    },
  ],
  foot: {
    // "Back to Claude" performs the redirect to Claude's OAuth callback with the code: the connection isn't
    // complete until then. The dashboard opens in a new tab so this tab can still finish (open decision 11).
    secondary: { label: 'Back to Claude', href: 'https://claude.ai/api/mcp/auth_callback?code=gallery&state=gallery' },
    primary: { label: 'Open developer dashboard', href: 'https://auto.dev/dashboard', icon: 'arrow_ur', newTab: true },
    note: ['Change the plan or disconnect in ', { href: R.agents, label: 'Agents' }, '.'],
  },
}

/** The default props per screen, shared with the screens' unit tests. */
export const connectProps = { plan, pay, done }

export const connectFixtures: FixtureGroup = {
  '24a-connect-plan': defineFixture({
    screen: ConnectPlan,
    title: (p) => `Pick an ${p.product.name} plan · id.org.ai`,
    scripts: ['disclose.js', 'follow.js', 'logo.js'],
    default: plan,
    derived: {
      // Not drawn (HANDOFF.md section 10): the yearly prices from section 8.
      yearly: { ...plan, billing: 'yearly' },
      // Not drawn: the product sends its logo, so its tile carries it.
      branded: { ...plan, product: AUTO_DEV_BRANDED },
      // Not drawn: a product with no trial has no footer line, and one with no yearly price has no billing toggle.
      'no-trial': { ...plan, pricing: { ...AUTO_DEV_PRICING, plans: AUTO_DEV_PRICING.plans.map(({ trial: _trial, ...p }) => ({ ...p, price: { monthly: p.price.monthly } })) } },
    },
  }),
  '24b-connect-pay': defineFixture({
    screen: ConnectPay,
    title: (p) => `Subscribe and connect ${p.client.name} · id.org.ai`,
    scripts: ['disclose.js', 'terms.js', 'logo.js'],
    default: pay,
    derived: {
      // Not drawn: how the page loads. The terms line is unticked and the primary action is disabled.
      unticked: { ...pay, termsChecked: false },
      branded: { ...pay, product: AUTO_DEV_BRANDED },
      // HANDOFF.md section 6: without a trial the summary is "Today $299.00 / Data fees".
      'no-trial': { ...pay, plan: { ...growth, trial: undefined }, trialEnds: undefined },
      // Not drawn: the seller charges tax, so the summary says what it comes to before the person agrees.
      'with-tax': { ...pay, tax: '$24.67/month, Florida sales tax' },
    },
  }),
  '24c-connect-done': defineFixture({
    screen: AgentCard,
    title: (p) => `${p.title} · id.org.ai`,
    scripts: ['logo.js'],
    default: done,
    derived: { branded: { ...done, tiles: { left: { kind: 'monogram', text: 'Cl' }, right: { kind: 'logo', src: AUTO_DEV_LOGO, monogram: 'Ad' }, connector: 'ok' } } },
  }),
}
