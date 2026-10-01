import type { Child } from 'hono/jsx'
import type { JSX } from 'hono/jsx/jsx-runtime'

/** Inline link: 13px, fg-2, underlined in line-2. */
export function Link({ href, children, on }: { href: string; children: Child; on?: string }): JSX.Element {
  return (
    <a class="id-link" href={href} data-on={on}>
      {children}
    </a>
  )
}
