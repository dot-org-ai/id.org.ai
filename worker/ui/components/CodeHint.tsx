import type { Child } from 'hono/jsx'
import type { JSX } from 'hono/jsx/jsx-runtime'

/**
 * The centred line under a code input (4c: "Codes look like WDJB-MJHT and
 * last 30 minutes."): 13px fg-3. `error` swaps it for the error text in
 * accent; give it the id the CodeInput's `errorId` points at.
 */
export function CodeHint({ id, error, children }: { id?: string; error?: boolean; children: Child }): JSX.Element {
  return (
    <div class={error ? 'id-codehint id-codehint--error' : 'id-codehint'} id={id} role={error ? 'alert' : undefined}>
      {children}
    </div>
  )
}
