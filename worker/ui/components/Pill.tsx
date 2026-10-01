import type { Child } from 'hono/jsx'
import type { JSX } from 'hono/jsx/jsx-runtime'

/** A small pill: "Last used", "Last used here"; `accent` for exceptions. */
export function Pill({ children, accent, normalLine }: { children: Child; accent?: boolean; normalLine?: boolean }): JSX.Element {
  const cls = ['id-pill', accent ? 'id-pill--accent' : '', normalLine ? 'id-pill--normal' : ''].filter(Boolean).join(' ')
  return <span class={cls}>{children}</span>
}
