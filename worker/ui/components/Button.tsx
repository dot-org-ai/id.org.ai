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
  /** A 16px icon before the label; the arrow on an action that leaves for another site (`arrow_ur`) goes after it instead (owner direction, 2026-11-23). */
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
  /** data-fetch forms: a cancel/deny action (broken at once, waits for the server). */
  deny?: boolean
  /** data-fetch forms: the template that swaps in when this action succeeds. */
  done?: string
  /** Disabled until the terms line is ticked (TermsAgree; terms.ts). */
  needsTerms?: boolean
  /** The label follows a choice: the control's name and a template, "Continue with {label}" (follow.ts). */
  follows?: { control: string; template: string }
  /** Links only: open in a new tab, so this page can still finish (24c's dashboard button). */
  newTab?: boolean
  class?: string
  children: Child
}

export function buttonClass(p: Pick<ButtonProps, 'variant' | 'size' | 'block' | 'grow' | 'class' | 'icon'>): string {
  return [
    'id-btn',
    `id-btn--${p.variant}`,
    p.size === 'sm' ? 'id-btn--sm' : '',
    p.block ? 'id-btn--block' : '',
    p.grow ? 'id-btn--grow' : '',
    p.icon === 'arrow_ur' ? 'id-btn--icon-end' : '',
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
      {p.follows ? (
        <span data-js="follow" data-follow={p.follows.control} data-template={p.follows.template}>
          {label}
        </span>
      ) : (
        <span>{label}</span>
      )}
    </>
  )
  if (p.href !== undefined) {
    return (
      <a class={cls} href={p.disabled ? undefined : p.href} data-on={p.on} aria-disabled={p.disabled ? 'true' : undefined} tabindex={p.disabled ? -1 : undefined} target={p.newTab ? '_blank' : undefined} rel={p.newTab ? 'noopener noreferrer' : undefined}>
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
      data-deny={p.deny ? '' : undefined}
      data-done={p.done}
      data-needs-terms={p.needsTerms ? '' : undefined}
    >
      {inner}
    </button>
  )
}
