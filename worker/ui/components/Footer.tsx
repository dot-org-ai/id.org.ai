import type { Child } from 'hono/jsx'
import type { JSX } from 'hono/jsx/jsx-runtime'
import { LINKS } from '../links'

export interface FooterProps {
  /** Replaces the Privacy / Terms / Status links (branded sign-in uses "Secured by id.org.ai"). */
  content?: Child
}

export function Footer({ content }: FooterProps): JSX.Element {
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
