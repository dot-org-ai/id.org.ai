import type { Child } from 'hono/jsx'
import type { JSX } from 'hono/jsx/jsx-runtime'

export type StackGap = 4 | 6 | 8 | 10 | 12 | 14 | 18 | 22

/** Layout glue: a column with one of the gaps the screens use. */
export function Stack({ gap, children, class: className }: { gap: StackGap; children: Child; class?: string }): JSX.Element {
  return <div class={`id-stack id-stack--${gap}${className ? ` ${className}` : ''}`}>{children}</div>
}
