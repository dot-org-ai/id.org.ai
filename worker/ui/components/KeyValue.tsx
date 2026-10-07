import type { Child } from 'hono/jsx'
import type { JSX } from 'hono/jsx/jsx-runtime'

export interface KV {
  k: string
  v: Child
  /** Codes, ids, URLs: 12px mono. */
  mono?: boolean
}

export function KeyValue({ k, v, mono }: KV): JSX.Element {
  return (
    <div class="id-kv">
      <span class="id-kv__key">{k}</span>
      <span class={mono ? 'id-kv__value id-kv__value--mono' : 'id-kv__value'}>{v}</span>
    </div>
  )
}

export function KeyValues({ items }: { items: KV[] }): JSX.Element {
  return <>{items.map((i) => <KeyValue {...i} />)}</>
}
