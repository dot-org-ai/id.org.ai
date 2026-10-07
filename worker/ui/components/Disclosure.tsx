import type { Child } from 'hono/jsx'
import type { JSX } from 'hono/jsx/jsx-runtime'
import { Icon } from '../icons'

/** Developer details (components.md#disclosure-developer-details). */
export function Disclosure({ summary, open, children }: { summary: string; open?: boolean; children: Child }): JSX.Element {
  return (
    <details data-x open={open ? true : undefined}>
      <summary class="id-disclosure__summary">
        <span class="id-chev" data-chev>
          <Icon name="chev_r" size={14} />
        </span>
        {summary}
      </summary>
      <div class="id-disclosure__panel">{children}</div>
    </details>
  )
}

export function Pre({ children }: { children: string }): JSX.Element {
  return <pre class="id-pre">{children}</pre>
}
