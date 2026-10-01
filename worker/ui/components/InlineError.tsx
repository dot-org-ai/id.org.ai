import type { Child } from 'hono/jsx'
import type { JSX } from 'hono/jsx/jsx-runtime'

/**
 * An error line under a control that is not a Field (the code boxes on 6d):
 * 13/20, accent, centred. Link it from the control with aria-describedby
 * (CodeInput's errorId, which also sets aria-invalid).
 */
export function InlineError({ id, children }: { id: string; children: Child }): JSX.Element {
  return (
    <p class="id-inline-error" id={id}>
      {children}
    </p>
  )
}
