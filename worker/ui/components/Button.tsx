import type { Child } from 'hono/jsx'
import type { JSX } from 'hono/jsx/jsx-runtime'
import { Icon, type IconName } from '../icons'

export interface ButtonProps {
  variant: 'primary' | 'secondary' | 'ghost'
  size?: 'md' | 'sm'
  /** Renders an <a> (navigation). Otherwise a <button>. */
  href?: string
  type?: 'submit' | 'button'
  name?: string
  value?: string
  /** A 16px icon before the label. */
  icon?: IconName
  disabled?: boolean
  /** Busy: disabled, aria-busy, and the progressive label ("Confirming…"). */
  busy?: boolean
  /** The progressive label, used when busy and by submit.ts. */
  busyLabel?: string
  /** Fill the slot (the action band's cell, or a column on its own). */
  block?: boolean
  /** flex: 1 1 0, for a single action in a column. */
  grow?: boolean
  /** Hook for client scripts (data-on). */
  on?: string
  class?: string
  children: Child
}

export function buttonClass(p: Pick<ButtonProps, 'variant' | 'size' | 'block' | 'grow' | 'class'>): string {
  return [
    'id-btn',
    `id-btn--${p.variant}`,
    p.size === 'sm' ? 'id-btn--sm' : '',
    p.block ? 'id-btn--block' : '',
    p.grow ? 'id-btn--grow' : '',
    p.class ?? '',
  ]
    .filter(Boolean)
    .join(' ')
}

/** Button (components.md#button): primary, secondary or ghost; md or sm. Never a <div>. */
export function Button(p: ButtonProps): JSX.Element {
  const cls = buttonClass(p)
  const label = p.busy && p.busyLabel ? p.busyLabel : p.children
  const inner = (
    <>
      {p.icon ? <Icon name={p.icon} size={16} /> : null}
      <span>{label}</span>
    </>
  )
  if (p.href !== undefined) {
    return (
      <a class={cls} href={p.href} data-on={p.on} aria-disabled={p.disabled ? 'true' : undefined}>
        {inner}
      </a>
    )
  }
  return (
    <button
      type={p.type ?? 'submit'}
      class={cls}
      name={p.name}
      value={p.value}
      disabled={p.disabled || p.busy ? true : undefined}
      aria-busy={p.busy ? 'true' : undefined}
      data-busy-label={p.busyLabel}
      data-on={p.on}
    >
      {inner}
    </button>
  )
}
