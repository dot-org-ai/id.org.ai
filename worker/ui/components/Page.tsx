import type { Child } from 'hono/jsx'
import type { JSX } from 'hono/jsx/jsx-runtime'
import { Footer } from './Footer'
import { Header } from './Header'

export interface PageProps {
  children: Child
  /** Branded first-party sign-in (1g): replaces the id.org.ai brand in the header. */
  brand?: Child
  /** Replaces the footer links (1g: "Secured by id.org.ai"). */
  footer?: Child
  /** Header right slot (5b countdown). */
  headerRight?: Child
  /** Pin the card to the top so its top edge stays still while the body changes height (4b). */
  pinTop?: boolean
}

/** The page shell every auth screen uses: header, centred 560px column, footer. */
export function Page({ children, brand, footer, headerRight, pinTop }: PageProps): JSX.Element {
  return (
    <div class="id-page">
      <Header brand={brand} right={headerRight} />
      <main class={pinTop ? 'id-main id-main--top' : 'id-main'}>
        <div class="id-column">{children}</div>
      </main>
      <Footer content={footer} />
    </div>
  )
}
