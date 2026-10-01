import type { Child } from 'hono/jsx'
import type { JSX } from 'hono/jsx/jsx-runtime'
import { Icon } from '../icons'

/** The unverified-app warning (components.md#warning-callout). */
export function WarningCallout({ title, children }: { title: string; children: Child }): JSX.Element {
  return (
    <div class="id-warning" role="note">
      <span class="id-warning__icon">
        <Icon name="alert" size={16} />
      </span>
      <div class="id-stack id-stack--4">
        <span class="id-warning__title">{title}</span>
        <span class="id-radio__desc">{children}</span>
      </div>
    </div>
  )
}
