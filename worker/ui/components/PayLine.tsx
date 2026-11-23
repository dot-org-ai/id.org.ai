import type { JSX } from 'hono/jsx/jsx-runtime'
import { Icon } from '../icons'
import { Link } from './Link'

export interface PayLineProps {
  /** "Visa ending 4417". Without one, the line offers to add a method instead. */
  method?: string
  /** Where "Change" goes: payment methods (20b). */
  href: string
  /** Where "Add a payment method" goes when there is none (19a). */
  addHref: string
}

/** One 13px line: the card icon, "Pays with {method}", and a Change link. */
export function PayLine({ method, href, addHref }: PayLineProps): JSX.Element {
  return (
    <div class="id-payline">
      <span class="id-payline__method">
        <Icon name="card" size={14} />
        {method ? (
          <span>
            Pays with <span class="id-fg">{method}</span>
          </span>
        ) : (
          <span>No payment method yet</span>
        )}
      </span>
      {method ? <Link href={href}>Change</Link> : <Link href={addHref}>Add a payment method</Link>}
    </div>
  )
}
