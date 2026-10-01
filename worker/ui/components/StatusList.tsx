import type { JSX } from 'hono/jsx/jsx-runtime'

export interface StatusItem {
  title: string
  sub?: string
  current?: boolean
}

/** The claim status list (components.md#status-list-5d), announced politely. */
export function StatusList({ items }: { items: StatusItem[] }): JSX.Element {
  return (
    <div aria-live="polite" data-js="status-list">
      {items.map((it) => (
        <div class={it.current ? 'id-status id-status--current' : 'id-status'}>
          <span class="id-status__dot"></span>
          <span class="id-status__text">
            <span class="id-status__title">{it.title}</span>
            {it.sub ? <span class="id-status__sub">{it.sub}</span> : null}
          </span>
        </div>
      ))}
    </div>
  )
}
