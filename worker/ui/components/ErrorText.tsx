import type { Child } from 'hono/jsx'
import type { JSX } from 'hono/jsx/jsx-runtime'

/**
 * An error line under a control that isn't a Field (the 1b code boxes): the
 * Field error's type (12/18, accent), centred under centred controls. Link the
 * control to it with aria-describedby={id}. role=alert, so a fresh render with
 * an error is announced.
 */
export function ErrorText({ id, center, children }: { id: string; center?: boolean; children: Child }): JSX.Element {
  return (
    <div class={center ? 'id-field__error id-errortext--center' : 'id-field__error'} id={id} role="alert">
      {children}
    </div>
  )
}
