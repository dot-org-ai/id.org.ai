import type { Child } from 'hono/jsx'
import type { JSX } from 'hono/jsx/jsx-runtime'

export interface RadioCardProps {
  id: string
  name: string
  value: string
  checked?: boolean
  title: Child
  description?: Child
  /** A 6px accent dot after the title, for elevated choices. */
  accent?: boolean
}

/** A <label> wrapping a visually hidden radio (components.md#radio-card). */
export function RadioCard({ id, name, value, checked, title, description, accent }: RadioCardProps): JSX.Element {
  return (
    <label class="id-radio" for={id}>
      <input class="id-hidden-input" type="radio" id={id} name={name} value={value} checked={checked ? true : undefined} />
      <span class="id-radio__ring" aria-hidden="true">
        <span class="id-radio__dot"></span>
      </span>
      <span class="id-radio__text">
        <span class="id-radio__title">
          {title}
          {accent ? <span class="id-accent-dot"></span> : null}
        </span>
        {description ? <span class="id-radio__desc">{description}</span> : null}
      </span>
    </label>
  )
}

/**
 * Radio cards under a group label, in a fieldset with a visually hidden
 * legend (accessibility.md#structure). `row` puts them side by side (consent's
 * access levels); `stack` is the vertical list.
 */
export function RadioGroup({ legend, layout, hideLabel, children }: { legend: string; layout: 'row' | 'stack'; hideLabel?: boolean; children: Child }): JSX.Element {
  return (
    <fieldset class="id-fieldset">
      <legend class="id-sr">{legend}</legend>
      {/* Some screens (2b, 6b) show no group label: the legend alone names the group. */}
      {hideLabel ? null : (
        <div class="id-group-label" aria-hidden="true">
          {legend}
        </div>
      )}
      {layout === 'row' ? <div class="id-radios--row">{children}</div> : children}
    </fieldset>
  )
}
