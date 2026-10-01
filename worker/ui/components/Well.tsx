import type { Child } from 'hono/jsx'
import type { JSX } from 'hono/jsx/jsx-runtime'
import { Icon, type IconName } from '../icons'

export type WellVariant = 'default' | 'tight' | 'stats' | 'quote' | 'code'

/** A sunk box for read-only facts (components.md#well). */
export function Well({ variant = 'default', children }: { variant?: WellVariant; children: Child }): JSX.Element {
  return <div class={variant === 'default' ? 'id-well' : `id-well id-well--${variant}`}>{children}</div>
}

/** 4b's device code well: the code, then the device meta line. */
export function DeviceCodeWell({ code, meta }: { code: string; meta: string }): JSX.Element {
  return (
    <Well variant="code">
      <div class="id-devicecode">{code}</div>
      <div class="id-meta">
        <Icon name="laptop" size={14} />
        <span>{meta}</span>
      </div>
    </Well>
  )
}

/** 3d's quoted note from the requester. */
export function QuoteWell({ children }: { children: Child }): JSX.Element {
  return (
    <Well variant="quote">
      <div class="id-quote">
        <span class="id-quote__icon">
          <Icon name="send" size={14} />
        </span>
        <span class="id-quote__text">{children}</span>
      </div>
    </Well>
  )
}

/** A meta line: 14px icon plus 13px fg-3 text. */
export function Meta({ icon, children }: { icon: IconName; children: Child }): JSX.Element {
  return (
    <div class="id-meta">
      <Icon name={icon} size={14} />
      <span>{children}</span>
    </div>
  )
}

/** 5b's email preview excerpt, under its key/values. */
export function Excerpt({ children }: { children: Child }): JSX.Element {
  return <div class="id-excerpt">{children}</div>
}
