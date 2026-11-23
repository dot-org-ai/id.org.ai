import type { JSX } from 'hono/jsx/jsx-runtime'
import { alertsSentence, limitLabel } from '../agent-setup/format'
import { Icon } from '../icons'
import { Field, Select } from './Field'
import { Toggle } from './Toggle'

export interface SpendProps {
  /** Prefix for the control ids and names, so two blocks can share a page. */
  id: string
  /** "$299": the plan price the helper line names. */
  planPrice?: string
  /** Cents; null is "No limit". Omitted when the API offers no limit. */
  limit?: { options: (number | null)[]; value: number | null }
  /** Cents. Omitted when the API offers no alerts. */
  alerts?: { marks: number[]; on: boolean; open?: boolean }
}

/** The per-API spend limit: a select, default "No limit", with its helper line. */
export function SpendLimit({ id, planPrice, limit }: { id: string; planPrice?: string; limit: NonNullable<SpendProps['limit']> }): JSX.Element {
  const value = (c: number | null) => (c === null ? 'none' : String(c))
  return (
    <div class="id-stack id-stack--6">
      <Field id={`${id}-limit`} label="Spend limit">
        <Select id={`${id}-limit`} name="spend_limit" options={limit.options.map((c) => ({ value: value(c), label: limitLabel(c) }))} selected={value(limit.value)} describedBy={`${id}-limit-help`} />
      </Field>
      <span class="id-help" id={`${id}-limit-help`}>
        {planPrice ? `On top of the ${planPrice} plan. ` : ''}Past a limit, calls are refused until next month.
      </span>
    </div>
  )
}

/**
 * Spend alerts: built like a permission row, but the switch and the chevron
 * are separate controls. The switch turns the emails on or off; the chevron
 * shows which amounts send one. Flipping the switch never opens the row.
 */
export function SpendAlerts({ id, alerts }: { id: string; alerts: NonNullable<SpendProps['alerts']> }): JSX.Element {
  const panel = `${id}-alerts-marks`
  return (
    <div class="id-alerts">
      <div class="id-alerts__row">
        <span class="id-perm__icon">
          <Icon name="bell" size={16} />
        </span>
        <label class="id-alerts__title" id={`${id}-alerts-label`} for={`${id}-alerts`}>
          Spend alerts
        </label>
        <Toggle id={`${id}-alerts`} name="spend_alerts" checked={alerts.on} labelledBy={`${id}-alerts-label`} />
        <button type="button" class="id-chevbtn id-chevbtn--r" data-js="disclose" aria-expanded={alerts.open ? 'true' : 'false'} aria-controls={panel} aria-label="Alert amounts">
          <Icon name="chev_r" size={14} />
        </button>
      </div>
      <div class="id-alerts__panel" id={panel} hidden={alerts.open ? undefined : true}>
        {alertsSentence(alerts.marks)}
      </div>
    </div>
  )
}

/** The spend block (19b, 24b): the limit, the alerts, or both, depending on what the API offers. */
export function Spend({ id, planPrice, limit, alerts }: SpendProps): JSX.Element {
  return (
    <>
      {limit ? <SpendLimit id={id} planPrice={planPrice} limit={limit} /> : null}
      {alerts ? <SpendAlerts id={id} alerts={alerts} /> : null}
    </>
  )
}
