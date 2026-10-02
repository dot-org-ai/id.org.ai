import type { JSX } from 'hono/jsx/jsx-runtime'
import { Icon, type IconName } from '../icons'

export interface PermissionItem {
  icon: IconName
  title: string
  detail: string
  /** The raw scope line, e.g. "sb:read · resource https://api.sb". */
  scope: string
  /** Act permissions: accent icon, weight 500, and the act note under the title. */
  act?: boolean
  actNote?: string
}

/** Expandable permission rows (components.md#permission-list-expandable). */
export function PermissionList({ heading, items }: { heading: string; items: PermissionItem[] }): JSX.Element {
  return (
    <div class="id-stack id-stack--4">
      <div class="id-group-label">{heading}</div>
      <div>
        {items.map((it) => (
          <details class="id-perm" data-x>
            <summary class="id-perm__summary">
              <span class={it.act ? 'id-perm__icon id-perm__icon--act' : 'id-perm__icon'}>
                <Icon name={it.icon} size={16} />
              </span>
              <span class="id-perm__text">
                <span class={it.act ? 'id-perm__title id-perm__title--act' : 'id-perm__title'}>{it.title}</span>
                {it.act && it.actNote ? <span class="id-perm__note">{it.actNote}</span> : null}
              </span>
              <span class="id-chev" data-chev>
                <Icon name="chev_r" size={14} />
              </span>
            </summary>
            <div class="id-perm__panel">
              <span class="id-perm__detail">{it.detail}</span>
              <code class="id-scope">{it.scope}</code>
            </div>
          </details>
        ))}
      </div>
    </div>
  )
}
