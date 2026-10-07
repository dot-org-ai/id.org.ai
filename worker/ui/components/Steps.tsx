import type { Child } from 'hono/jsx'
import type { JSX } from 'hono/jsx/jsx-runtime'

/** A numbered step (components.md#steps-5d). */
export function Step({ n, label, children }: { n: number; label: string; children: Child }): JSX.Element {
  return (
    <div class="id-step">
      <span class="id-step__num">{n}</span>
      <div class="id-step__body">
        <span class="id-namesub__name">{label}</span>
        {children}
      </div>
    </div>
  )
}
