/** Devices group fixtures: strings copied verbatim from the 4b/4c/4d mocks. */
import { DeviceConfirm, type DeviceConfirmProps } from '../../screens/DeviceConfirm'
import { defineFixture, type FixtureGroup } from '../types'

const confirm: DeviceConfirmProps = {
  code: 'WDJB-MJHT',
  client: { name: 'auto.dev CLI', tile: { kind: 'icon', icon: 'terminal' } },
  cliName: 'auto.dev',
  deviceMeta: 'macOS · Miami, FL · requested 1 min ago',
  device: 'macOS · Miami, FL',
  account: { name: 'Bryant Skarda', email: 'bryant@driv.ly' },
  switchHref: '/account/choose',
  workspaces: [
    { value: 'org_drivly', label: 'Drivly' },
    { value: 'org_do', label: '.do Industries' },
    { value: 'org_studio', label: 'Startups Studio' },
  ],
  selectedWorkspace: 'org_drivly',
  permissions: [
    { icon: 'user', title: 'See your name and email', detail: 'Shown in the CLI as who is signed in.', scope: 'openid profile email' },
    { icon: 'terminal', title: 'Use the auto.dev API as you in Drivly', detail: 'Calls count against Drivly’s auto.dev plan.', scope: 'auto.dev:api' },
    { icon: 'clock', title: 'Stay signed in on this device', detail: 'Until you sign out or revoke it in Connected apps.', scope: 'offline_access' },
  ],
  revokeHref: '/device/revoke',
  action: '/device/decision',
  csrf: 'gallery',
}

const title = (p: DeviceConfirmProps) => `Confirm ${p.client.name} · id.org.ai`

export const deviceFixtures: FixtureGroup = {
  '4b-device-confirm': defineFixture({
    screen: DeviceConfirm,
    title,
    scripts: ['fetch-form.js'],
    default: confirm,
    states: {
      connecting: { ...confirm, state: 'connecting' },
      verdict: { ...confirm, state: 'verdict' },
      signed: { ...confirm, state: 'signed' },
      cancelling: { ...confirm, state: 'cancelling' },
      cancelled: { ...confirm, state: 'cancelled' },
    },
  }),
}
