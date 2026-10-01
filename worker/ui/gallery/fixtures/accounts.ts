/** Accounts (2a, 2b, 2c, 2e) group fixtures: strings copied verbatim from the mocks. */
import { AccountChooser, type AccountChooserProps } from '../../screens/AccountChooser'
import { Handoff, type HandoffProps } from '../../screens/Handoff'
import { Invitation, type InvitationProps } from '../../screens/Invitation'
import { WorkspaceChooser, type WorkspaceChooserProps } from '../../screens/WorkspaceChooser'
import { defineFixture, type FixtureGroup } from '../types'

const accountChooser: AccountChooserProps = {
  app: { name: 'startups.studio', tile: { kind: 'monogram', text: 'S' } },
  accounts: [
    { sessionId: 'ses_gallery_do', name: 'Bryant Skarda', email: 'bryant@do.industries', lastUsedHere: true },
    { sessionId: 'ses_gallery_drivly', name: 'Bryant Skarda', email: 'bryant@driv.ly', lastUsedHere: false },
  ],
  anotherAccountHref: '/login?prompt=login',
  action: '/account/choose',
  signOutAction: '/signout',
  csrf: 'gallery',
}

const workspaceChooser: WorkspaceChooserProps = {
  mode: { kind: 'choose', action: '/workspace/choose' },
  app: { name: 'headless.ly', tile: { kind: 'monogram', text: 'h' } },
  account: { name: 'Bryant Skarda', email: 'bryant@driv.ly' },
  switchHref: '/account/choose',
  workspaces: [
    { id: 'org_drivly', name: 'Drivly', role: 'owner' },
    { id: 'org_do', name: '.do Industries', role: 'owner' },
    { id: 'org_studio', name: 'Startups Studio', role: 'admin' },
    { id: 'org_personal', name: 'Personal', role: 'personal' },
  ],
  selectedId: 'org_drivly',
  remember: true,
  newWorkspaceHref: '/workspace/new',
  csrf: 'gallery',
}

const handoff: HandoffProps = {
  app: { name: 'headless.ly', tile: { kind: 'monogram', text: 'h' } },
  account: { name: 'Bryant Skarda' },
  workspace: { name: 'Drivly' },
  target: 'https://headless.ly/',
}

const invitation: InvitationProps = {
  inviter: { name: 'Nathan Clevenger' },
  workspace: { name: '.do Industries', tile: { kind: 'monogram', text: '.d' } },
  role: 'Admin',
  invitedEmail: 'bryant@driv.ly',
  expiresIn: 'in 6 days',
  account: { name: 'Bryant Skarda', email: 'bryant@driv.ly' },
  switchHref: '/account/choose',
  action: '/invite/gallery',
  csrf: 'gallery',
}

export const accountsFixtures: FixtureGroup = {
  '2a-account-chooser': defineFixture({
    screen: AccountChooser,
    title: () => 'Choose an account · id.org.ai',
    scripts: ['submit.js'],
    default: accountChooser,
  }),
  '2b-workspace-chooser': defineFixture({
    screen: WorkspaceChooser,
    title: () => 'Choose a workspace · id.org.ai',
    scripts: ['submit.js'],
    default: workspaceChooser,
    derived: {
      // WorkOS organization_selection_required at sign-in: posts /api/org-select, nothing is remembered.
      'sign-in': {
        ...workspaceChooser,
        mode: { kind: 'sign-in', action: '/api/org-select', pendingAuthenticationToken: 'gallery-pending-token', state: 'gallery-state' },
        switchHref: '/login?prompt=login',
        remember: undefined,
        newWorkspaceHref: undefined,
      },
    },
  }),
  '2c-handoff': defineFixture({
    screen: Handoff,
    title: (p) => `Signing you in to ${p.app.name} · id.org.ai`,
    default: handoff,
  }),
  '2e-invitation': defineFixture({
    screen: Invitation,
    title: (p) => (p.state === 'declined' ? 'Invitation declined · id.org.ai' : `Join ${p.workspace.name} · id.org.ai`),
    scripts: ['submit.js'],
    default: invitation,
    derived: {
      // Signed in as a different email than the invited one: Join disabled, Switch prominent.
      mismatch: { ...invitation, account: { name: 'Bryant Skarda', email: 'bryant@do.industries' } },
      declined: { ...invitation, state: 'declined' },
    },
  }),
}
