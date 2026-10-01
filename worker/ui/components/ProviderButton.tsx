import type { JSX } from 'hono/jsx/jsx-runtime'
import { Pill } from './Pill'
import { ProviderMark } from './ProviderMark'

export type Provider = 'github' | 'google' | 'microsoft' | 'apple'

export const PROVIDER_NAMES: Record<Provider, string> = {
  github: 'GitHub',
  google: 'Google',
  microsoft: 'Microsoft',
  apple: 'Apple',
}

/**
 * A sign-in provider (components.md#provider-button): the provider's 18px mark
 * (ProviderMark, where the mocks show a dashed slot), its name, and the "Last
 * used" pill.
 */
export function ProviderButton({ provider, href, lastUsed }: { provider: Provider; href: string; lastUsed?: boolean }): JSX.Element {
  return (
    <a class="id-btn id-btn--secondary id-btn--provider" href={href}>
      <ProviderMark provider={provider} />
      <span class="id-provider__name">{PROVIDER_NAMES[provider]}</span>
      {lastUsed ? <Pill>Last used</Pill> : null}
    </a>
  )
}

export function Providers({ children }: { children: JSX.Element | JSX.Element[] }): JSX.Element {
  return <div class="id-providers">{children}</div>
}
