/**
 * The sign-in link email for a trusted-account app (worker/routes/trusted-magic-link.ts):
 * one button that signs the person in to the app and lands them on it. It names
 * the app, says how long the link lasts and that it works once.
 */
import {
  EmailButton,
  EmailContent,
  EmailHeading,
  EmailMeta,
  EmailParagraph,
  EmailStrong,
  emailText,
  NO_REPLY,
  oneLine,
  type EmailParts,
  type EmailSender,
} from './layout'

export interface SignInLinkEmailProps {
  /** The link: https://id.org.ai/oauth/magic-link/<token>. */
  url: string
  /** The app, as a phrase: "the Startups.Studio Fund I deck". */
  app: string
  /** The address it went to, shown so a forwarded email reads plainly. */
  email: string
  expiresInMinutes: number
  from?: EmailSender
}

export function signInLinkEmail(props: SignInLinkEmailProps): EmailParts {
  const app = oneLine(props.app)
  const minutes = props.expiresInMinutes
  const expiry = `The link works once, for ${minutes} minutes, on any device.`
  const ignore = 'Didn’t ask to sign in? Ignore this email: nothing happens unless the link is opened.'
  const meta = `Sent to ${oneLine(props.email)} · Sign-in by id.org.ai`
  return {
    from: props.from ?? { name: 'id.org.ai', email: NO_REPLY },
    subject: `Your sign-in link for ${app}`,
    content: (
      <EmailContent
        blocks={[
          <EmailHeading>{`Sign in to ${app}`}</EmailHeading>,
          <EmailParagraph>
            Open <EmailStrong>{app}</EmailStrong> with the button below. {expiry}
          </EmailParagraph>,
          <EmailButton href={props.url}>Sign in</EmailButton>,
          <EmailParagraph>{ignore}</EmailParagraph>,
          <EmailMeta>{meta}</EmailMeta>,
        ]}
      />
    ),
    text: emailText([`Sign in to ${app}`, `Open ${app} with this link. ${expiry}`, props.url, ignore, meta]),
  }
}
