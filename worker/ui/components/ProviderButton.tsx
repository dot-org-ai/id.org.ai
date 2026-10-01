import type { JSX } from 'hono/jsx/jsx-runtime'
import { Pill } from './Pill'

export type Provider = 'github' | 'google' | 'microsoft' | 'apple'

export const PROVIDER_NAMES: Record<Provider, string> = {
  github: 'GitHub',
  google: 'Google',
  microsoft: 'Microsoft',
  apple: 'Apple',
}

/**
 * A sign-in provider (components.md#provider-button). The official marks are an
 * owner step (logos.md): until they're supplied, the dashed 18px slot the mocks
 * show marks where each goes.
 */
export function ProviderButton({ provider, href, lastUsed }: { provider: Provider; href: string; lastUsed?: boolean }): JSX.Element {
  return (
    <a class="id-btn id-btn--secondary id-btn--provider" href={href}>
      <span class="id-provider__slot" aria-hidden="true" title={`${PROVIDER_NAMES[provider]} mark`}></span>
      <span class="id-provider__name">{PROVIDER_NAMES[provider]}</span>
      {lastUsed ? <Pill>Last used</Pill> : null}
    </a>
  )
}

export function Providers({ children }: { children: JSX.Element | JSX.Element[] }): JSX.Element {
  return <div class="id-providers">{children}</div>
}
