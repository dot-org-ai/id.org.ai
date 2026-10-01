import type { JSX } from 'hono/jsx/jsx-runtime'

export interface CodeInputProps {
  /** 6 for email and authenticator codes; 8 for device codes (shown XXXX-XXXX). */
  length: 6 | 8
  /** Prefill (for example from ?code=); never auto-submits. */
  value?: string
  /** Gallery only: draw this box focused without real focus (the mocks show one). */
  focusIndex?: number
  /** Accessible name of the group ("Enter the 6-digit code"). */
  label: string
  /** Links the error text. */
  errorId?: string
}

/**
 * One box per character (components.md#code-input). Every box is named `code`,
 * so without JS the form posts the characters in order and the server joins
 * them; code-input.ts adds auto-advance, backspace, arrows and paste-to-fill.
 */
export function CodeInput({ length, value = '', focusIndex, label, errorId }: CodeInputProps): JSX.Element {
  const device = length === 8
  const chars = value.replace(/[\s-]/g, '').toUpperCase().split('')
  const boxes: JSX.Element[] = []
  for (let i = 0; i < length; i++) {
    boxes.push(
      <input
        class={i === focusIndex ? 'id-code__box is-focused' : 'id-code__box'}
        name="code"
        value={chars[i] ?? undefined}
        maxlength={i === 0 ? undefined : 1}
        inputmode={device ? 'text' : 'numeric'}
        autocapitalize={device ? 'characters' : undefined}
        autocomplete={i === 0 ? 'one-time-code' : 'off'}
        spellcheck={false}
        aria-label={`Character ${i + 1} of ${length}`}
        aria-invalid={errorId ? 'true' : undefined}
        aria-describedby={errorId}
      />,
    )
    if (device && i === 3) boxes.push(<span class="id-code__sep" aria-hidden="true">–</span>)
  }
  return (
    <div class={device ? 'id-code id-code--device' : 'id-code'} role="group" aria-label={label} data-js="code-input" data-length={String(length)}>
      {boxes}
    </div>
  )
}
