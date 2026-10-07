import type { JSX } from 'hono/jsx/jsx-runtime'
import { Icon } from '../icons'
import { Well } from './Well'

/** 5c's tenant stats in a well, with the sandbox-expiry line (components.md#stats-5c). */
export function Stats({ items, footer }: { items: { n: string; label: string }[]; footer: string }): JSX.Element {
  return (
    <Well variant="stats">
      <div class="id-stats">
        {items.map((s) => (
          <div class="id-stat">
            <div class="id-stat__num">{s.n}</div>
            <div class="id-stat__label">{s.label}</div>
          </div>
        ))}
      </div>
      <div class="id-stats__foot">
        <Icon name="clock" size={14} />
        <span>{footer}</span>
      </div>
    </Well>
  )
}
