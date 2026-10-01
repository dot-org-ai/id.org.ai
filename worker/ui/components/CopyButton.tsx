import type { JSX } from 'hono/jsx/jsx-runtime'
import { Icon } from '../icons'

export interface CopyButtonProps {
  /** The value copied: already visible on the page, never a secret (security.md#copy-button). */
  value: string
  /** The labelled variant ("Copy details") used on error pages. */
  labelled?: boolean
  /** Gallery only: render the copied state (copy.ts never resets a server-rendered one). */
  copied?: boolean
}

/**
 * Copy (components.md#copy-button): hidden without JS (the value stays visible
 * and selectable); copy.ts unhides it, writes the clipboard, shows the green
 * check for 1.5s and announces "Copied" through the status region next to it.
 */
export function CopyButton({ value, labelled, copied }: CopyButtonProps): JSX.Element {
  return (
    <>
    <button
      type="button"
      class={labelled ? 'id-copy id-copy--label' : 'id-copy'}
      data-js="copy"
      data-value={value}
      data-copied={copied ? '' : undefined}
      aria-label={labelled ? undefined : 'Copy'}
      hidden
    >
      <span class="id-copy__idle">
        <Icon name="copy" size={14} />
        {labelled ? <span>Copy details</span> : null}
      </span>
      <span class="id-copy__done" aria-hidden="true">
        <Icon name="check" size={14} class="id-copy__check" />
        {labelled ? <span>Copied</span> : null}
      </span>
    </button>
    {/* Out of flow (absolute), so it never takes a gap in the parent row. */}
    <span class="id-sr" role="status">
      {copied ? 'Copied' : ''}
    </span>
    </>
  )
}
