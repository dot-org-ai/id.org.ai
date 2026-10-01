/** Devices group fixtures: strings copied verbatim from the 4b/4c/4d mocks. */
import { DeviceConfirm, type DeviceConfirmProps } from '../../screens/DeviceConfirm'
import { DeviceDone, type DeviceDoneProps, type DeviceSignedProps } from '../../screens/DeviceDone'
import { DeviceEntry, type DeviceEntryProps } from '../../screens/DeviceEntry'
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

const entry: DeviceEntryProps = {
  focusIndex: 0,
  action: '/device',
  csrf: 'gallery',
}

const done: DeviceSignedProps = {
  client: { name: 'auto.dev CLI', tile: { kind: 'icon', icon: 'terminal' } },
  account: { email: 'bryant@driv.ly' },
  workspace: { name: 'Drivly' },
  device: 'macOS · Miami, FL',
  revokeHref: '/device/revoke',
}

const doneTitle = (p: DeviceDoneProps) => (p.outcome === 'cancelled' ? 'Sign-in cancelled · id.org.ai' : `${p.client.name} is signed in · id.org.ai`)

export const deviceFixtures: FixtureGroup = {
  '4b-device-confirm': defineFixture({
    screen: DeviceConfirm,
    title,
    scripts: ['device-confirm.js'],
    default: confirm,
    states: {
      connecting: { ...confirm, state: 'connecting' },
      verdict: { ...confirm, state: 'verdict' },
      signed: { ...confirm, state: 'signed' },
      cancelling: { ...confirm, state: 'cancelling' },
      cancelled: { ...confirm, state: 'cancelled' },
    },
  }),
  '4c-device-entry': defineFixture({
    screen: DeviceEntry,
    title: () => 'Connect a device · id.org.ai',
    scripts: ['code-input.js', 'submit.js'],
    default: entry,
    derived: {
      // The code was invalid, expired or already used: the server renders 4c again with what was typed.
      error: { value: 'WDJB-MJHX', error: 'That code is invalid or has expired. Check your terminal for the current code.', action: '/device', csrf: 'gallery' },
    },
  }),
  '4d-device-done': defineFixture({
    screen: DeviceDone,
    title: doneTitle,
    default: done,
    derived: {
      // GET /device/cancelled?code=: 4b's cancelled content on its own.
      cancelled: { outcome: 'cancelled', client: done.client, cliName: 'auto.dev' },
    },
  }),
}
