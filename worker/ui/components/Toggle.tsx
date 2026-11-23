import type { Child } from 'hono/jsx'
import type { JSX } from 'hono/jsx/jsx-runtime'

function Track(): JSX.Element {
  return (
    <span class="id-toggle__track" aria-hidden="true">
      <span class="id-toggle__knob"></span>
    </span>
  )
}

/**
 * A switch: 36×22 track, 18px knob, a real checkbox with role="switch". Name
 * it with `labelledBy` (an element that shows the name) or `label`.
 */
export function Toggle({ id, name, checked, label, labelledBy }: { id: string; name: string; checked?: boolean; label?: string; labelledBy?: string }): JSX.Element {
  return (
    <label class="id-toggle" for={id}>
      <input class="id-hidden-input" type="checkbox" role="switch" id={id} name={name} value="1" checked={checked ? true : undefined} aria-label={label} aria-labelledby={labelledBy} />
      <Track />
    </label>
  )
}

/** A labelled switch row (20d): the title and one line on the left, the switch on the right. */
export function ToggleRow({ id, name, checked, title, sub }: { id: string; name: string; checked?: boolean; title: string; sub?: Child }): JSX.Element {
  return (
    <label class="id-togglerow id-toggle" for={id}>
      <span class="id-stack id-stack--2">
        <span class="id-line14">{title}</span>
        {sub ? <span class="id-help">{sub}</span> : null}
      </span>
      <input class="id-hidden-input" type="checkbox" role="switch" id={id} name={name} value="1" checked={checked ? true : undefined} />
      <Track />
    </label>
  )
}
