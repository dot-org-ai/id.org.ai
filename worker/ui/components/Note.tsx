import type { Child } from 'hono/jsx'
import type { JSX } from 'hono/jsx/jsx-runtime'
import { Icon, type IconName } from '../icons'

/** Inline note (components.md#note-inline): optional 14px icon, 13/20 fg-3. */
export function Note({ icon, children }: { icon?: IconName; children: Child }): JSX.Element {
  return (
    <div class="id-note">
      {icon ? <Icon name={icon} size={14} class="id-note__icon" /> : null}
      <span class="id-note__text">{children}</span>
    </div>
  )
}
