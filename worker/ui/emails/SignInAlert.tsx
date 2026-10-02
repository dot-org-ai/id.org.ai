/**
 * 8c · New sign-in alert (spec/screens.md#8c). "This wasn’t me" links straight to
 * a one-click revoke for that session or device.
 */
import {
  EmailButton,
  EmailContent,
  EmailHeading,
  EmailKeyValues,
  EmailParagraph,
  emailText,
  httpUrl,
  oneLine,
  renderEmail,
  SECURITY_SENDER,
  type EmailParts,
  type EmailRenderOptions,
  type RenderedEmail,
} from './layout'

export interface SignInAlertEmailProps {
  /** The app that signed in, for example "auto.dev CLI". */
  app: string
  /** The device's OS, for example "macOS" (the Device row and the subject). */
  os: string
  /** "City, region", for example "Miami, FL". */
  location: string
  /** When, formatted in the person's time zone, for example "Oct 1, 1:52 PM EDT". */
  when: string
  /** The account that was signed in to. */
  email: string
  /** Absolute signed, single-use revoke URL for that session. */
  revokeUrl: string
}

export function signInAlertEmail(props: SignInAlertEmailProps): EmailParts {
  const app = oneLine(props.app)
  const os = oneLine(props.os)
  const revokeUrl = httpUrl(props.revokeUrl)
  const rows: [string, string][] = [
    ['App', app],
    ['Device', os],
    ['Where', oneLine(props.location)],
    ['When', oneLine(props.when)],
  ]
  const signedIn = `${app} was just signed in as ${oneLine(props.email)}.`
  const ok = 'If this was you, there’s nothing to do.'
  return {
    from: { name: 'id.org.ai', email: SECURITY_SENDER },
    subject: `New sign-in: ${app} on ${os}`,
    content: (
      <EmailContent
        blocks={[
          <EmailHeading>New sign-in to your account</EmailHeading>,
          <EmailParagraph>{signedIn}</EmailParagraph>,
          <EmailKeyValues rows={rows} />,
          <EmailParagraph>{ok}</EmailParagraph>,
          <EmailButton href={revokeUrl}>This wasn’t me</EmailButton>,
        ]}
      />
    ),
    text: emailText(['New sign-in to your account', signedIn, rows.map(([k, v]) => `${k}: ${v}`).join('\n'), ok, `This wasn’t me: ${revokeUrl}`]),
  }
}

export function renderSignInAlertEmail(props: SignInAlertEmailProps, opts?: EmailRenderOptions): RenderedEmail {
  return renderEmail(signInAlertEmail(props), opts)
}
