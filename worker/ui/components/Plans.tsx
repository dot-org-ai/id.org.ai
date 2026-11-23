import type { JSX } from 'hono/jsx/jsx-runtime'
import { Icon } from '../icons'

export interface PlanCardProps {
  id: string
  /** "Growth" */
  name: string
  /** "$299": the monthly price. */
  price: string
  /** "$249": the price per month when billed yearly. Falls back to `price`. */
  priceYearly?: string
  /** "a month + data fees". Omitted on Free. */
  priceNote?: string
  /** "Unlimited calls · 10 requests a second" */
  summary: string
  /** The rows behind the chevron. */
  included: { label: string; value?: string }[]
  selected: boolean
  open: boolean
}

/** Monthly or Yearly: a small pill, right-aligned on the "Plan" label row. Switching swaps every card's price (CSS). */
export function BillingToggle({ name, value = 'monthly' }: { name: string; value?: 'monthly' | 'yearly' }): JSX.Element {
  const cell = (v: 'monthly' | 'yearly', label: string) => (
    <label class="id-billing__cell" for={`${name}-${v}`}>
      <input class="id-hidden-input" type="radio" id={`${name}-${v}`} name={name} value={v} checked={v === value ? true : undefined} data-billing={v} />
      {label}
    </label>
  )
  return (
    <fieldset class="id-fieldset">
      <legend class="id-sr">Billing</legend>
      <div class="id-billing">
        {cell('monthly', 'Monthly')}
        {cell('yearly', 'Yearly')}
      </div>
    </fieldset>
  )
}

/**
 * One plan (docs/agent-setup/HANDOFF.md section 5, PlanCard). The row is a
 * radio: one plan at a time. The chevron is a separate button that shows or
 * hides what the plan includes, and never changes the selection.
 */
export function PlanCard({ name: group, plan }: { name: string; plan: PlanCardProps }): JSX.Element {
  const inputId = `${group}-${plan.id}`
  const panelId = `${inputId}-included`
  return (
    <div class="id-plan">
      <div class="id-plan__head">
        <label class="id-plan__pick" for={inputId}>
          <input class="id-hidden-input" type="radio" id={inputId} name={group} value={plan.id} checked={plan.selected ? true : undefined} data-short={plan.name} />
          <span class="id-radio__ring" aria-hidden="true">
            <span class="id-radio__dot"></span>
          </span>
          <span class="id-plan__text">
            <span class="id-plan__title">
              <span>{plan.name}</span>
              <span class="id-plan__price">
                <span data-price="monthly">{plan.price}</span>
                <span data-price="yearly">{plan.priceYearly ?? plan.price}</span>
              </span>
              {plan.priceNote ? <span class="id-plan__note">{plan.priceNote}</span> : null}
            </span>
            <span class="id-help">{plan.summary}</span>
          </span>
        </label>
        <button type="button" class="id-chevbtn id-chevbtn--d id-plan__more" data-js="disclose" aria-expanded={plan.open ? 'true' : 'false'} aria-controls={panelId} aria-label={`What ${plan.name} includes`}>
          <Icon name="chev_d" size={16} />
        </button>
      </div>
      <div class="id-plan__panel" id={panelId} hidden={plan.open ? undefined : true}>
        {plan.included.map((row) => (
          <div class="id-plan__item">
            <span class="id-plan__label">
              <Icon name="check" size={14} />
              {row.label}
            </span>
            {row.value ? <span class="id-plan__value">{row.value}</span> : null}
          </div>
        ))}
      </div>
    </div>
  )
}

/**
 * The plan picker (24a): the "Plan" label with the billing toggle, then one
 * card per plan as a radio group. follow.ts keeps the primary action's label
 * ("Continue with {label}") in step with the selection.
 */
export function PlanPicker({ name, plans, billing = 'monthly', yearly = true }: { name: string; plans: PlanCardProps[]; billing?: 'monthly' | 'yearly'; yearly?: boolean }): JSX.Element {
  return (
    <div class="id-plans">
      <div class="id-plans__head">
        <div class="id-group-label" aria-hidden="true">
          Plan
        </div>
        {yearly ? <BillingToggle name={`${name}-billing`} value={billing} /> : null}
      </div>
      <fieldset class="id-plans__list">
        <legend class="id-sr">Plan</legend>
        {plans.map((plan) => (
          <PlanCard name={name} plan={plan} />
        ))}
      </fieldset>
    </div>
  )
}
