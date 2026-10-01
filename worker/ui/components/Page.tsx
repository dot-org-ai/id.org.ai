import type { Child } from 'hono/jsx'
import type { JSX } from 'hono/jsx/jsx-runtime'
import { Footer } from './Footer'
import { AppBrand, Header, type AppBrandProps } from './Header'

export interface PageProps {
  children: Child
  /**
   * Branded first-party sign-in (1g): the app's tile and name replace the
   * id.org.ai brand, and the footer reads "Secured by id.org.ai". Only for
   * listed first-party clients; an app can set its name and mark, nothing else.
   */
  branded?: AppBrandProps
  /** Header right slot (5b countdown). */
  headerRight?: Child
  /** Pin the card to the top so its top edge stays still while the body changes height (4b). */
  pinTop?: boolean
  /** The 440px column instead of 560px: sign-in (1a–1g), accounts (2a–2c, 2e) and security (6a–6d), by owner direction (2026-10-01). */
  narrow?: boolean
}

/** The page shell every auth screen uses: header, centred 560px (or narrow 440px) column, footer. */
export function Page({ children, branded, headerRight, pinTop, narrow }: PageProps): JSX.Element {
  return (
    <div class="id-page">
      <Header brand={branded ? <AppBrand {...branded} /> : undefined} right={headerRight} />
      <main class={pinTop ? 'id-main id-main--top' : 'id-main'}>
        <div class={narrow ? 'id-column id-column--narrow' : 'id-column'}>{children}</div>
      </main>
      <Footer variant={branded ? 'secured' : 'links'} />
    </div>
  )
}
