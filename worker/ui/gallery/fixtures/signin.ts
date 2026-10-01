/** Sign in (1a–1g) group fixtures: strings copied verbatim from the mocks. */
import { PROVIDER_NAMES, type TileContent } from '../../components'
import { EmailCode, type EmailCodeProps } from '../../screens/EmailCode'
import { FirstRun, type FirstRunProps } from '../../screens/FirstRun'
import { LinkAccount, type LinkAccountProps } from '../../screens/LinkAccount'
import { ProviderFallback, type ProviderFallbackProps } from '../../screens/ProviderFallback'
import { SignIn, type SignInProps } from '../../screens/SignIn'
import { Sso, type SsoProps } from '../../screens/Sso'
import { defineFixture, type FixtureGroup } from '../types'

const headlessly: { name: string; tile: TileContent } = { name: 'headless.ly', tile: { kind: 'monogram', text: 'h' } }
const CONTINUE = 'https://headless.ly/auth/callback'

const signIn: SignInProps = {
  app: headlessly,
  action: '/login/email',
  csrf: 'gallery',
  continueUrl: CONTINUE,
  providers: [
    { provider: 'github', href: '/login?provider=GitHubOAuth' },
    { provider: 'google', href: '/login?provider=GoogleOAuth' },
    { provider: 'microsoft', href: '/login?provider=authkit' },
    { provider: 'apple', href: '/login?provider=authkit' },
  ],
  lastUsedProvider: 'github',
  passkey: { href: '/login?provider=authkit' },
}

const emailCode: EmailCodeProps = {
  app: headlessly,
  email: 'bryant@driv.ly',
  expiresInMinutes: 10,
  action: '/login/code/flw_gallery',
  resendAction: '/login/code/flw_gallery/resend',
  csrf: 'gallery',
  differentEmailHref: '/login',
  code: '4829',
  resendIn: 42,
  focusIndex: 4,
}

const sso: SsoProps = {
  app: headlessly,
  email: 'bryant@northwind.co',
  org: { name: 'Northwind', domain: 'northwind.co' },
  idpName: 'Okta',
  enforced: true,
  continueHref: '/login/sso/start?organization_id=org_northwind',
  differentEmailHref: '/login',
}

const firstRun: FirstRunProps = {
  action: '/welcome',
  csrf: 'gallery',
  name: 'Bryant Skarda',
  workspaceName: 'Drivly',
  provider: 'GitHub',
  providerUsername: 'bryant22',
  notYouHref: '/signout?return_url=%2Flogin',
}

const linkAccount: LinkAccountProps = {
  app: headlessly,
  email: 'bryant@driv.ly',
  existingProvider: 'github',
  newProvider: 'google',
  identity: { name: 'Bryant Skarda', email: 'bryant@driv.ly' },
  continueHref: '/login?provider=GitHubOAuth&link=flw_gallery',
  differentEmailHref: '/login',
}

const fallback: ProviderFallbackProps = {
  app: headlessly,
  provider: 'microsoft',
  reason: 'Northwind’s sign-in policy blocks apps it hasn’t pre-approved.',
  email: 'bryant@northwind.co',
  emailLabel: 'Work email',
  action: '/login/email',
  csrf: 'gallery',
  continueUrl: CONTINUE,
  retryHref: '/login?provider=MicrosoftOAuth',
}

const signInTitle = (p: SignInProps) => (p.brand && p.app ? `Sign in to ${p.app.name} · id.org.ai` : 'Sign in · id.org.ai')

export const signinFixtures: FixtureGroup = {
  '1a-sign-in': defineFixture({
    screen: SignIn,
    title: signInTitle,
    scripts: ['submit.js'],
    default: signIn,
    derived: {
      'email-error': { ...signIn, email: 'bryant@driv', emailError: 'Enter a full email address, like you@company.com.' },
      'no-app': { ...signIn, app: undefined, continueUrl: undefined },
    },
  }),
  '1b-email-code': defineFixture({
    screen: EmailCode,
    title: () => 'Check your email · id.org.ai',
    scripts: ['submit.js', 'code-input.js', 'countdown.js'],
    default: emailCode,
    derived: {
      'wrong-code': { ...emailCode, error: 'wrong-code', focusIndex: 0 },
      'too-many-tries': { ...emailCode, error: 'too-many-tries', focusIndex: undefined },
      'resend-ready': { ...emailCode, resendIn: 0 },
    },
  }),
  '1c-sso': defineFixture({
    screen: Sso,
    title: (p) => `${p.org.name} uses single sign-on · id.org.ai`,
    default: sso,
    derived: {
      'not-enforced': { ...sso, enforced: false },
    },
  }),
  '1d-first-run': defineFixture({
    screen: FirstRun,
    title: (p) => (p.variant === 'new-workspace' ? 'Create a workspace · id.org.ai' : 'Create your identity · id.org.ai'),
    scripts: ['submit.js'],
    default: firstRun,
    derived: {
      'new-workspace': { variant: 'new-workspace', action: '/workspace/new', csrf: 'gallery', backHref: '/workspace/choose' },
      // Server-rendered validation errors: focus lands on the first invalid field.
      'name-error': { ...firstRun, name: '', nameError: 'Enter your name.' },
      'workspace-error': { ...firstRun, workspaceName: '', workspaceError: 'Enter a workspace name.' },
      'new-workspace-error': {
        variant: 'new-workspace',
        action: '/workspace/new',
        csrf: 'gallery',
        backHref: '/workspace/choose',
        workspaceError: 'Enter a workspace name.',
      },
    },
  }),
  '1e-link-account': defineFixture({
    screen: LinkAccount,
    title: () => 'You already have an account · id.org.ai',
    default: linkAccount,
  }),
  '1f-provider-fallback': defineFixture({
    screen: ProviderFallback,
    title: (p) => `${PROVIDER_NAMES[p.provider]} sign-in didn’t finish · id.org.ai`,
    scripts: ['submit.js', 'copy.js'],
    default: fallback,
    derived: {
      // The email form came back invalid: the field is marked, described and focused.
      'email-error': { ...fallback, email: 'bryant@northwind', emailError: 'Enter a full email address, like you@company.com.' },
      details: {
        ...fallback,
        details: {
          items: [
            { k: 'Error', v: 'access_denied', mono: true },
            { k: 'Provider', v: 'MicrosoftOAuth', mono: true },
            { k: 'Request', v: 'req_8f2c41d07a', mono: true },
          ],
          copy: 'error=access_denied provider=MicrosoftOAuth request=req_8f2c41d07a',
        },
      },
    },
  }),
  '1g-branded-sign-in': defineFixture({
    screen: SignIn,
    title: signInTitle,
    scripts: ['submit.js'],
    default: { ...signIn, brand: { name: 'headless.ly', monogram: 'h' } },
  }),
}
