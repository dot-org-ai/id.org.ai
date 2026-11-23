/**
 * The agent setup data contract (docs/agent-setup/HANDOFF.md section 7).
 *
 * A proposal, not confirmed: the minimum the screens need. The product posts a
 * Setup on every change; id.org.ai renders whatever steps it sends and knows
 * nothing about APIs, keys or calls beyond what an event says. Amounts are cents.
 */

export type SetupState =
  | 'awaiting_approval'
  | 'rejected'
  | 'running'
  | 'needs_spend_approval'
  | 'needs_plan_approval'
  | 'needs_person'
  | 'needs_payment_method'
  | 'needs_bank_confirmation'
  | 'needs_wallet_approval'
  | 'payment_declined'
  | 'call_failing'
  | 'stalled'
  | 'paused'
  | 'in_review'
  | 'cancelled'
  | 'live'
  | 'live_with_warning'

/** Account-level states, shown outside a setup run. */
export type AccountState = 'needs_purchase_approval' | 'needs_step_up' | 'renewal_failed' | 'limit_reached'

export type StepState = 'done' | 'now' | 'you' | 'fail' | 'held' | 'todo'

export interface Product {
  /** "apis.ax" */
  id: string
  /** "auto.dev" */
  api?: string
  /** "Auto.dev" */
  name: string
  /** The letter tile: "Ad", "@", "Di". No real product logos. */
  tile: string
  dashboard_url?: string
  terms_url?: string
  privacy_url?: string
}

export type Evidence =
  | { type: 'listening'; text?: string; key_last4?: string; since?: string; elapsed?: string; note?: string }
  | { type: 'call'; method: string; path: string; status: number; ms?: number; code?: string; rows?: ([string, string] | [string, string, 'mono'])[]; more_url?: string; more_label?: string }
  | { type: 'prompt'; label: string; text: string }
  | { type: 'rows'; rows: [string, string][] }
  | { type: 'compare'; rows: { name: string; matched: number; of: number; state: 'ok' | 'running' }[]; note?: string }
  | { type: 'choice'; items: [string, string][]; options: { id: string; title: string; detail: string }[]; value: string }
  | { type: 'field_map'; rows: { column: string; options: string[]; value: string }[] }
  | { type: 'field'; label: string; options: { value: string; label: string }[]; value: string }
  | { type: 'plan'; plan: string; price: string; rates: [string, string][]; more_url?: string; more_label?: string }

export interface SetupStep {
  id: string
  title: string
  detail?: string
  state: StepState
  /** ISO time the product reported the step. */
  at?: string
  /** The right-hand label when it isn't a time: "Waiting on you", "Stalled", "Due [DATE]". */
  label?: string
  /** The API a step belongs to, on a job across several (17b). */
  tag?: string
  evidence?: Evidence
}

export interface Setup {
  setup_id: string
  product: Product
  agent_id: string
  workspace_id: string
  state: SetupState
  steps: SetupStep[]
  next_for_person: string | null
}

export interface PlanOffer {
  id: string
  name: string
  recommended?: boolean
  /** Cents a month. `yearly_per_month` is the monthly price when billed yearly. */
  price: { monthly: number; yearly_per_month?: number }
  /** "a month + data fees". Omitted on a free plan. */
  price_note?: string
  summary: string
  included: { label: string; value?: string }[]
  trial?: { days: number; price: number }
}

export interface SpendOffer {
  basis: 'usage_on_top_of_plan'
  /** null is "No limit". Omitted when the API offers no limit. */
  limit?: { options: (number | null)[]; default: number | null }
  /** Omitted when the API offers no alerts. */
  alerts?: { marks: number[]; default_on: boolean }
}

export interface Pricing {
  plans: PlanOffer[]
  spend: SpendOffer
}

/** Money events, product → id.org.ai (20a, 20c). */
export type MoneyEvent = 'charge.succeeded' | 'charge.failed' | 'charge.needs_person' | 'charge.refunded' | 'usage.running' | 'alert.passed'

/** What `authorize(agent_id, product, amount, kind)` answers before any charge. */
export type AuthorizeAnswer = 'allow' | 'ask_person' | 'refuse'
