import type { JSX } from 'hono/jsx/jsx-runtime'
import { Icon } from '../icons'
import { httpsOnly } from './url'

export interface TermsAgreeProps {
  id: string
  /** "Auto.dev" */
  product: string
  /** URLs the product sends (https only). */
  termsHref: string
  privacyHref: string
  /** Unticked on load. The mocks show it ticked so the button reads as active. */
  checked?: boolean
}

/**
 * The terms line at the top of the action band (19b, 24b). A checkbox, so it
 * can be unticked. The primary action (marked `needsTerms`) stays disabled
 * until it is ticked: the checkbox is required, CSS dims the button, and
 * terms.ts sets `disabled`.
 */
export function TermsAgree({ id, product, termsHref, privacyHref, checked }: TermsAgreeProps): JSX.Element {
  const link = (href: string, label: string) => (
    <a class="id-link" href={httpsOnly(href) ?? '#'} target="_blank" rel="noopener noreferrer">
      {label}
    </a>
  )
  return (
    <label class="id-check id-check--top id-check--terms" for={id}>
      <input class="id-hidden-input" type="checkbox" id={id} name="terms" value="1" checked={checked ? true : undefined} required data-terms data-js="terms" />
      <span class="id-check__box" aria-hidden="true">
        <span class="id-check__tick">
          <Icon name="check" size={12} />
        </span>
      </span>
      <span>
        I agree to {product}’s {link(termsHref, 'Terms of Service')} and {link(privacyHref, 'Privacy Policy')}.
      </span>
    </label>
  )
}
