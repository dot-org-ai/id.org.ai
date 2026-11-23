import type { Child } from 'hono/jsx'
import type { JSX } from 'hono/jsx/jsx-runtime'
import { Icon } from '../icons'

/**
 * Checkbox (components.md#checkbox): the real input stays focusable, visually hidden.
 * `detail` adds a second, dimmer line (10b, 19a, 19c); the box then sits on the first line.
 */
export function Checkbox({ id, name, value, checked, detail, children }: { id: string; name: string; value?: string; checked?: boolean; detail?: Child; children: Child }): JSX.Element {
  return (
    <label class={detail ? 'id-check id-check--top' : 'id-check'} for={id}>
      <input class="id-hidden-input" type="checkbox" id={id} name={name} value={value ?? '1'} checked={checked ? true : undefined} />
      <span class="id-check__box" aria-hidden="true">
        <span class="id-check__tick">
          <Icon name="check" size={12} />
        </span>
      </span>
      {detail ? (
        <span class="id-check__lines">
          <span class="id-fg">{children}</span>
          <span class="id-check__sub">{detail}</span>
        </span>
      ) : (
        <span>{children}</span>
      )}
    </label>
  )
}
