/**
 * Emails (8a–8c) group fixtures: strings copied verbatim from the mocks. Each
 * renders the whole preview document (inbox frame + template); see
 * worker/ui/emails/PreviewFrame.tsx and spec/emails.md#gallery-preview.
 */
import type { EmailParts } from '../../emails/layout'
import { invitationEmail, type InvitationEmailProps } from '../../emails/Invitation'
import { PreviewFrame } from '../../emails/PreviewFrame'
import { signInAlertEmail, type SignInAlertEmailProps } from '../../emails/SignInAlert'
import { signInCodeEmail, type SignInCodeEmailProps } from '../../emails/SignInCode'
import { defineFixture, type FixtureGroup } from '../types'

/** A fixture screen: the template built from props, inside the mock's frame (board height `height`). */
const preview =
  <P>(build: (p: P) => EmailParts, height: number) =>
  (p: P) =>
    PreviewFrame({ email: build(p), height })

const code: SignInCodeEmailProps = { code: '482913', app: 'headless.ly', browser: 'Chrome', os: 'macOS', location: 'Miami, FL' }

const invitation: InvitationEmailProps = {
  inviter: 'Nathan Clevenger',
  email: 'bryant@driv.ly',
  workspace: '.do Industries',
  role: 'Admin',
  acceptUrl: 'https://id.org.ai/invite/inv_gallery',
}

const alert: SignInAlertEmailProps = {
  app: 'auto.dev CLI',
  os: 'macOS',
  location: 'Miami, FL',
  when: 'Oct 1, 1:52 PM EDT',
  email: 'bryant@driv.ly',
  revokeUrl: 'https://id.org.ai/sessions/revoke/gallery',
}

export const emailsFixtures: FixtureGroup = {
  '8a-email-sign-in-code': defineFixture({
    document: 'email',
    screen: preview(signInCodeEmail, 640),
    title: (p) => signInCodeEmail(p).subject,
    default: code,
    derived: { 'no-location': { ...code, location: undefined } },
  }),
  '8b-email-invitation': defineFixture({
    document: 'email',
    screen: preview(invitationEmail, 620),
    title: (p) => invitationEmail(p).subject,
    default: invitation,
    derived: { member: { ...invitation, role: 'Member', expiresInDays: 1 } },
  }),
  '8c-email-sign-in-alert': defineFixture({
    document: 'email',
    screen: preview(signInAlertEmail, 680),
    title: (p) => signInAlertEmail(p).subject,
    default: alert,
  }),
}
