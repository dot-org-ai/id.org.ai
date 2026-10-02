import type { Child } from 'hono/jsx'
import type { JSX } from 'hono/jsx/jsx-runtime'
import { Icon } from '../icons'

/** Checkbox (components.md#checkbox): the real input stays focusable, visually hidden. */
export function Checkbox({ id, name, value, checked, children }: { id: string; name: string; value?: string; checked?: boolean; children: Child }): JSX.Element {
  return (
    <label class="id-check" for={id}>
      <input class="id-hidden-input" type="checkbox" id={id} name={name} value={value ?? '1'} checked={checked ? true : undefined} />
      <span class="id-check__box" aria-hidden="true">
        <span class="id-check__tick">
          <Icon name="check" size={12} />
        </span>
      </span>
      <span>{children}</span>
    </label>
  )
}
