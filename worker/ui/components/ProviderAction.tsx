import type { Child } from 'hono/jsx'
import type { JSX } from 'hono/jsx/jsx-runtime'
import { buttonClass } from './Button'
import type { Provider } from './ProviderButton'
import { ProviderMark } from './ProviderMark'

/**
 * A full-width action that signs in with one provider ("Continue with GitHub",
 * 1e): a Button whose leading slot is the provider's 18px mark instead of an
 * icon.
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
      <ProviderMark provider={provider} />
      <span>{children}</span>
    </a>
  )
}
