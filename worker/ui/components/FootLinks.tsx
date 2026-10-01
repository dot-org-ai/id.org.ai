import type { Child } from 'hono/jsx'
import type { JSX } from 'hono/jsx/jsx-runtime'

/**
 * Alternate links under a single foot action, centred with a 20px gap
 * (6d: "Use a passkey instead", "Use a recovery code"). Pass Link elements.
 */
export function FootLinks({ children }: { children: Child }): JSX.Element {
  return <div class="id-footlinks">{children}</div>
}
