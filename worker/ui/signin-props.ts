/**
 * GET /login without a provider → the sign-in screen's props (1a, or the
 * branded look for a listed resource: worker/utils/resource-brands.ts).
 *
 * Pure: the route (worker/routes/auth.ts) validates the continue URL, the
 * login_hint and the flow client, then calls this; tests build the same props
 * from the same inputs.
 *
 * Every choice is a link back to GET /login?provider=…, the flow the old
 * provider picker (worker/views/provider-picker.ts, removed) started. The
 * hrefs are built exactly as it built them, so a click goes where it always
 * went. Microsoft, Apple and email all hand off to hosted AuthKit until their
 * own paths exist (docs/product-update/prompts/07-sign-in.md).
 */
import type { ResourceBrand } from '../utils/resource-brands'
import type { SignInProps } from './screens/SignIn'

export interface SignInPageInput {
  /** The destination /login resolved (already validated). */
  continueUrl: string
  /** A sanitised login_hint, forwarded so the upstream page is prefilled. */
  loginHint?: string
  /** prompt=login arrived: each link keeps it, so choosing one signs in again. */
  promptLogin?: boolean
  /** The flow's client, only when it is what let the continue through. */
  clientId?: string
  /** A listed resource's brand, when the continue is its authorize request. */
  brand?: ResourceBrand
}

/**
 * One sign-in link. A continue of "/" is left off (GET /login then falls back
 * to its default), as the old picker did.
 */
export function loginLinkHref(provider: string, continueUrl: string, loginHint?: string, promptLogin = false, clientId?: string): string {
  return (
    `/login?provider=${provider}` +
    (continueUrl !== '/' ? '&continue=' + encodeURIComponent(continueUrl) : '') +
    (loginHint ? '&login_hint=' + encodeURIComponent(loginHint) : '') +
    (promptLogin ? '&prompt=login' : '') +
    (clientId ? '&client_id=' + encodeURIComponent(clientId) : '')
  )
}

export function signInPageProps(i: SignInPageInput): SignInProps {
  const href = (provider: string) => loginLinkHref(provider, i.continueUrl, i.loginHint, i.promptLogin, i.clientId)
  return {
    ...(i.brand && {
      brand: i.brand,
      resourceBrand: true,
      app: { name: i.brand.name, tile: { kind: 'logo', src: i.brand.markUrl, monogram: i.brand.monogram } },
    }),
    emailHref: href('authkit'),
    providers: [
      { provider: 'github', href: href('GitHubOAuth') },
      { provider: 'google', href: href('GoogleOAuth') },
      { provider: 'microsoft', href: href('authkit') },
      { provider: 'apple', href: href('authkit') },
    ],
  }
}

/** The document title, as the gallery words it for 1a and 1g. */
export function signInTitle(p: Pick<SignInProps, 'brand' | 'app'>): string {
  return p.brand && p.app ? `Sign in to ${p.app.name} · id.org.ai` : 'Sign in · id.org.ai'
}
