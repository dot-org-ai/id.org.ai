import type { Child } from 'hono/jsx'
import type { JSX } from 'hono/jsx/jsx-runtime'
import { LINKS } from '../links'
import { OrgMark } from './OrgMark'

export interface FooterProps {
  /** `secured`: branded first-party sign-in (1g) swaps the links for "Secured by id.org.ai". */
  variant?: 'links' | 'secured'
  /** Replaces the footer's content entirely (rarely needed). */
  content?: Child
}

export function Footer({ variant = 'links', content }: FooterProps): JSX.Element {
  if (variant === 'secured') {
    return (
      <footer class="id-footer id-footer--secured">
        <span>Secured by</span>
        <span class="id-secured">
          <OrgMark size={14} />
          <span>id.org.ai</span>
        </span>
      </footer>
    )
  }
  return (
    <footer class="id-footer">
      {content ?? (
        <>
          <a class="id-footer__link" href={LINKS.privacy}>
            Privacy
          </a>
          <a class="id-footer__link" href={LINKS.terms}>
            Terms
          </a>
          <a class="id-footer__link" href={LINKS.status}>
            Status
          </a>
        </>
      )}
    </footer>
  )
}
