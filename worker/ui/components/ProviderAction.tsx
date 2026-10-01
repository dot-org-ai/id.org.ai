import type { Child } from 'hono/jsx'
import type { JSX } from 'hono/jsx/jsx-runtime'
import { buttonClass } from './Button'
import { PROVIDER_NAMES, type Provider } from './ProviderButton'

/**
 * A full-width action that signs in with one provider ("Continue with GitHub",
 * 1e): a Button whose leading slot is the provider's 18px mark instead of an
 * icon. Like ProviderButton, the official marks are an owner step (logos.md);
 * until then the dashed slot the mocks show marks where the mark goes.
 * Always navigation (GET /login?provider=…), so always an <a>.
 */
export function ProviderAction({
  provider,
  href,
  variant = 'primary',
  children,
}: {
  provider: Provider
  href: string
  variant?: 'primary' | 'secondary'
  children: Child
}): JSX.Element {
  return (
    <a class={buttonClass({ variant, block: true })} href={href}>
      <span class="id-provider__slot" aria-hidden="true" title={`${PROVIDER_NAMES[provider]} mark`}></span>
      <span>{children}</span>
    </a>
  )
}
