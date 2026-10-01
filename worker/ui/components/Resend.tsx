import type { JSX } from 'hono/jsx/jsx-runtime'
import { formatCountdown } from './Countdown'

export interface ResendProps {
  /** Seconds until another code can be sent. 0 or less shows "Resend code" straight away. */
  availableIn: number
  /** When the wait ends (ISO 8601); countdown.ts ticks against it. */
  availableAt: string
  /** The id of the ResendForm the "Resend code" button submits. */
  form: string
}

/**
 * 1b's resend line (components.md#countdown-5b-header-right): "Didn’t get it?"
 * then "Resend in 0:42" in m:ss, always fg-3. countdown.ts ticks it and at 0
 * reveals the [data-countdown-done] sibling, the "Resend code" button.
 *
 * The button belongs to its own ResendForm (form=…), not to the code form it
 * sits in, so Enter in a code box still submits Verify (the code form's
 * default button) and never resends.
 */
export function Resend({ availableIn, availableAt, form }: ResendProps): JSX.Element {
  const ready = availableIn <= 0
  return (
    <div class="id-resend">
      <span>Didn’t get it?</span>
      {ready ? null : (
        <span data-js="countdown" data-expires-at={availableAt}>
          Resend in <span data-countdown-text>{formatCountdown(availableIn)}</span>
        </span>
      )}
      <button type="submit" form={form} class="id-link id-linkbtn" data-countdown-done hidden={ready ? undefined : true}>
        Resend code
      </button>
    </div>
  )
}

/**
 * The resend form: POST /login/code/:flow/resend with the CSRF field and
 * nothing visible. Render it outside the code form (forms can't nest); it
 * takes no space.
 */
export function ResendForm({ id, action, csrf }: { id: string; action: string; csrf: string }): JSX.Element {
  return (
    <form id={id} class="id-form" method="post" action={action}>
      <input type="hidden" name="csrf" value={csrf} />
    </form>
  )
}
