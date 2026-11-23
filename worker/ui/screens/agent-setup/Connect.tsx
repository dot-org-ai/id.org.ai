/**
 * 24 · Connect from Claude (docs/agent-setup/HANDOFF.md sections 3 and 6).
 *
 * A person clicks Connect on a product in Claude's connector directory; Claude
 * opens id.org.ai's authorize URL. After sign-in: 24a pick a plan, 24b
 * subscribe and connect, 24c connected, then the redirect to Claude's OAuth
 * callback with the code. The person is present for the whole pass, so there
 * is no test key, no first-call wait and no step list.
 *
 * Plans, prices, included items, the spend limit and the alert marks all come
 * from the product (the Pricing contract in agent-setup/types.ts). If the
 * person leaves at 24a or 24b, nothing is charged and no token is issued.
 */
import type { JSX } from 'hono/jsx/jsx-runtime'
import { listAnd, usd, usdExact } from '../../agent-setup/format'
import { rich, type Rich } from '../../agent-setup/rich'
import { AGENT_ROUTES } from '../../agent-setup/routes'
import { productTile } from '../../agent-setup/tiles'
import type { PlanOffer, Pricing, Product, SpendOffer } from '../../agent-setup/types'
import {
  Card,
  CardFoot,
  CardHead,
  Connector,
  Dotted,
  KeyValue,
  Link,
  Page,
  PayLine,
  PermissionList,
  PlanPicker,
  Spend,
  Well,
  Who,
  type PermissionItem,
  type PlanCardProps,
  type TileContent,
} from '../../components'
import { Foot } from './blocks'

/** The app the person is connecting: letter tile only, no real logos. */
export interface ConnectClient {
  /** The registered client's slug, for the routes: "claude". */
  id: string
  name: string
  tile: string
  /** The app's own mark, when it has one (its registered logo). The letters stand in otherwise. */
  logoUrl?: string
}

const tiles = (client: ConnectClient, product: Product): { left: TileContent; right: TileContent } => ({ left: productTile({ tile: client.tile, logo_url: client.logoUrl }), right: productTile(product) })

/** "Growth and Scale start with 7 days for $1." Only when the product has a trial; null otherwise. */
export function trialLine(plans: PlanOffer[]): string | null {
  const withTrial = plans.filter((p) => p.trial)
  const trial = withTrial[0]?.trial
  if (!trial) return null
  const verb = withTrial.length === 1 ? 'starts' : 'start'
  return `${listAnd(withTrial.map((p) => p.name))} ${verb} with ${trial.days} days for ${usd(trial.price)}.`
}

/** A plan offer as a card: the recommended plan is selected and open, the rest closed. */
export function planCards(plans: PlanOffer[], selected?: string): PlanCardProps[] {
  const pick = selected ?? plans.find((p) => p.recommended)?.id ?? plans[0]?.id
  return plans.map((p) => ({
    id: p.id,
    name: p.name,
    price: usd(p.price.monthly),
    priceYearly: p.price.yearly_per_month !== undefined ? usd(p.price.yearly_per_month) : undefined,
    priceNote: p.price_note,
    summary: p.summary,
    included: p.included,
    selected: p.id === pick,
    open: p.id === pick,
  }))
}

// ── 24a · pick a plan ────────────────────────────────────────────────────────

export interface ConnectPlanProps {
  client: ConnectClient
  product: Product
  account: { name: string; email: string }
  pricing: Pricing
  /** The plan already picked (coming back from 24b). Default: the product's recommended plan. */
  selected?: string
  /** Default Monthly. */
  billing?: 'monthly' | 'yearly'
  /** `/connect/:client/plan` */
  action: string
  csrf: string
}

export function ConnectPlan(p: ConnectPlanProps): JSX.Element {
  const cards = planCards(p.pricing.plans, p.selected)
  const picked = cards.find((c) => c.selected)
  const trial = trialLine(p.pricing.plans)
  const yearly = p.pricing.plans.some((pl) => pl.price.yearly_per_month !== undefined)
  return (
    <Page>
      <form class="id-form" method="post" action={p.action}>
        <input type="hidden" name="csrf" value={p.csrf} />
        <Card
          foot={
            <CardFoot>
              <Foot
                secondary={{ label: 'Cancel', value: 'cancel' }}
                primary={{ label: `Continue with ${picked?.name ?? ''}`, value: 'continue', follows: { control: 'plan', template: 'Continue with {label}' } }}
                note={trial ?? undefined}
              />
            </CardFoot>
          }
        >
          <CardHead connector={<Connector {...tiles(p.client, p.product)} state="idle" />} title={`Pick an ${p.product.name} plan`} description={`${p.client.name} is connecting to ${p.product.name} for you. Change plans anytime.`} />
          <Dotted />
          <Who name={p.account.name} sub={p.account.email} right={<Link href={AGENT_ROUTES.switchAccount}>Switch</Link>} />
          <PlanPicker name="plan" plans={cards} billing={p.billing} yearly={yearly} />
        </Card>
      </form>
    </Page>
  )
}

// ── 24b · subscribe and connect ──────────────────────────────────────────────

export interface ConnectPayProps {
  client: ConnectClient
  product: Product
  /** "Drivly": who is billed. */
  workspace: string
  plan: PlanOffer
  billing?: 'monthly' | 'yearly'
  /** "Nov 29": when the trial ends and the plan price starts. Needed when the plan has a trial. */
  trialEnds?: string
  /** "Per call, billed monthly": how the product bills usage. */
  feesNote: string
  /** Tax on the plan, as the seller (through Stripe) computes it: "$24.67/month, Florida sales tax". Omitted when there is none. */
  tax?: string
  spend: SpendOffer
  /** "Visa ending 4417". None: the line offers to add one (the flow sends the person to 19a first). */
  payMethod?: string
  /** What the client may do; the row that spends as it is used comes first, in amber. */
  permissions: PermissionItem[]
  /** Unticked on load. The drawing shows it ticked so the button reads as active. */
  termsChecked?: boolean
  /** `/connect/:client/pay` */
  action: string
  csrf: string
}

/** 24b's charge summary: with a trial, today's trial price and what follows; without, today's price. */
export function chargeSummary(p: Pick<ConnectPayProps, 'plan' | 'billing' | 'trialEnds' | 'feesNote' | 'tax'>): [string, string][] {
  const yearly = p.billing === 'yearly' && p.plan.price.yearly_per_month !== undefined
  const price = yearly ? `${usdExact(p.plan.price.yearly_per_month as number)}/month, billed yearly` : `${usdExact(p.plan.price.monthly)}/month`
  const after: [string, string][] = [['Data fees', p.feesNote], ...(p.tax ? [['Tax', p.tax] as [string, string]] : [])]
  if (p.plan.trial && p.trialEnds) {
    return [['Today', `${usdExact(p.plan.trial.price)} for ${p.plan.trial.days} days`], [`From ${p.trialEnds}`, price], ...after]
  }
  return [['Today', yearly ? price : usdExact(p.plan.price.monthly)], ...after]
}

export function ConnectPay(p: ConnectPayProps): JSX.Element {
  const description: Rich = [`${p.plan.name} on ${p.product.name}, billed to `, { em: p.workspace }, '.']
  return (
    <Page>
      <form class="id-form" method="post" action={p.action}>
        <input type="hidden" name="csrf" value={p.csrf} />
        <input type="hidden" name="plan" value={p.plan.id} />
        <input type="hidden" name="billing" value={p.billing ?? 'monthly'} />
        <Card
          foot={
            <CardFoot>
              <Foot
                terms={{ id: 'connect-terms', product: p.product.name, termsHref: p.product.terms_url ?? '', privacyHref: p.product.privacy_url ?? '', checked: p.termsChecked }}
                secondary={{ label: 'Back', href: AGENT_ROUTES.connectPlan(p.client.id) }}
                primary={{ label: 'Subscribe and connect', value: 'subscribe', busyLabel: 'Subscribing…' }}
                note="Cancel anytime. Calls made before you cancel are still billed."
              />
            </CardFoot>
          }
        >
          <CardHead connector={<Connector {...tiles(p.client, p.product)} state="idle" />} title={`Subscribe and connect ${p.client.name}`} description={rich(description)} />
          <Dotted />
          <Well>
            {chargeSummary(p).map(([k, v]) => (
              <KeyValue k={k} v={v} />
            ))}
          </Well>
          <PayLine method={p.payMethod} href={AGENT_ROUTES.paymentMethods} addHref={AGENT_ROUTES.paymentMethodNew} />
          <Spend
            id="connect"
            planPrice={usd(p.plan.price.monthly)}
            limit={p.spend.limit ? { options: p.spend.limit.options, value: p.spend.limit.default } : undefined}
            alerts={p.spend.alerts ? { marks: p.spend.alerts.marks, on: p.spend.alerts.default_on } : undefined}
          />
          <PermissionList heading={`${p.client.name} would like to`} items={p.permissions} />
        </Card>
      </form>
    </Page>
  )
}
