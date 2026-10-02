import type { Child } from 'hono/jsx'
import type { JSX } from 'hono/jsx/jsx-runtime'
import { Icon, type IconName } from '../icons'

/**
 * The action band's buttons (layout.md#actions). Two actions split the width,
 * secondary on the left and primary on the right; on phones they stack with
 * the primary on top (visual order only). One action fills the width and is
 * rendered on its own, so pass it directly instead.
 */
export function Actions({ children }: { children: Child }): JSX.Element {
  return (
    <div class="id-actions" data-actions>
      {children}
    </div>
  )
}

/** The centred safety line under the buttons: 14px icon plus 12/17 text. */
export function FootNote({ icon, children }: { icon?: IconName; children: Child }): JSX.Element {
  return (
    <div class="id-footnote">
      {icon ? <Icon name={icon} size={14} /> : null}
      <span>{children}</span>
    </div>
  )
}

/** A text-only foot line: 13/20, fg-3, centred. */
export function FootText({ children }: { children: Child }): JSX.Element {
  return <div class="id-foottext">{children}</div>
}
