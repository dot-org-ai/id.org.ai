/** Security (6a–6d) group fixtures: strings copied verbatim from the mocks. */
import { AddPasskey, type AddPasskeyProps } from '../../screens/AddPasskey'
import { SignOut, type SignOutProps } from '../../screens/SignOut'
import { StepUp, type StepUpProps } from '../../screens/StepUp'
import { TwoStep, type TwoStepProps } from '../../screens/TwoStep'
import { defineFixture, type FixtureGroup } from '../types'

const account = { name: 'Bryant Skarda', email: 'bryant@driv.ly' }

const stepUp: StepUpProps = {
  app: { name: 'Codex', tile: { kind: 'monogram', text: 'Cx' } },
  reason: 'act_permissions',
  account,
  lastConfirmedAgo: '3 hours ago',
  factors: { passkey: true, email: true },
  action: '/step-up?resume=rsm_4Tq8Lw2e&reason=act_permissions',
  csrf: 'gallery',
}

const signOut: SignOutProps = {
  app: { name: 'headless.ly', tile: { kind: 'monogram', text: 'h' } },
  account,
  scope: 'app',
  action: '/signout',
  csrf: 'gallery',
  clientId: 'headless.ly',
  returnUrl: 'https://headless.ly/',
  cancelHref: 'https://headless.ly/',
}

const addPasskey: AddPasskeyProps = {
  action: '/passkeys/new?continue=%2Foauth%2Fauthorize',
  csrf: 'gallery',
}

const twoStep: TwoStepProps = {
  workspace: 'Drivly',
  action: '/login/two-step/mfa_9Rk2Vd7p',
  csrf: 'gallery',
  value: '19',
  focusIndex: 2,
  passkeyHref: '/login/passkey?flow=mfa_9Rk2Vd7p',
  // Hidden in production until a recovery design exists (D8); the mock shows it.
  recoveryHref: '/login/two-step/mfa_9Rk2Vd7p/recovery',
}

export const securityFixtures: FixtureGroup = {
  '6a-step-up': defineFixture({
    screen: StepUp,
    title: () => 'Confirm it’s you · id.org.ai',
    scripts: ['submit.js'],
    default: stepUp,
    derived: {
      'email-only': { ...stepUp, factors: { passkey: false, email: true } },
    },
  }),
  '6b-sign-out': defineFixture({
    screen: SignOut,
    title: (p) => (p.state === 'signed-out' ? 'You’re signed out · id.org.ai' : 'Sign out · id.org.ai'),
    scripts: ['fetch-form.js'],
    default: signOut,
    derived: {
      everywhere: { ...signOut, scope: 'everywhere' },
      busy: { ...signOut, busy: true },
      'no-app': { ...signOut, app: undefined, clientId: undefined, scope: undefined },
      // The result (the template's content, and the no-JS page), named for each scope.
      'signed-out': { ...signOut, state: 'signed-out' },
      'signed-out-browser': { ...signOut, state: 'signed-out', scope: 'browser' },
      'signed-out-everywhere': { ...signOut, state: 'signed-out', scope: 'everywhere' },
      // No app and no return_url: nothing to continue to.
      'signed-out-no-app': { ...signOut, state: 'signed-out', app: undefined, clientId: undefined, scope: 'browser', returnUrl: undefined, cancelHref: '/' },
    },
  }),
  '6c-add-passkey': defineFixture({
    screen: AddPasskey,
    title: () => 'Add a passkey · id.org.ai',
    scripts: ['submit.js'],
    default: addPasskey,
    derived: {
      busy: { ...addPasskey, busy: true },
    },
  }),
  '6d-two-step': defineFixture({
    screen: TwoStep,
    title: () => 'Two-step verification · id.org.ai',
    scripts: ['code-input.js', 'submit.js'],
    default: twoStep,
    derived: {
      'wrong-code': {
        ...twoStep,
        value: '',
        focusIndex: 0,
        recoveryHref: undefined,
        error: 'That code didn’t work. Enter the current code from your authenticator app.',
      },
      'no-passkey': { ...twoStep, value: '', focusIndex: 0, passkeyHref: undefined, recoveryHref: undefined },
      busy: { ...twoStep, value: '194306', focusIndex: undefined, busy: true },
    },
  }),
}
