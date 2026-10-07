/**
 * 8b · Invitation email (spec/screens.md#8b). "Accept invitation" links to /invite/:token.
 */
import {
  EmailButton,
  EmailContent,
  EmailHeading,
  EmailParagraph,
  EmailStrong,
  emailText,
  httpUrl,
  NO_REPLY,
  oneLine,
  renderEmail,
  type EmailParts,
  type EmailRenderOptions,
  type RenderedEmail,
} from './layout'

export interface InvitationEmailProps {
  /** Who sent the invite, for example "Nathan Clevenger". */
  inviter: string
  /** The invited address. */
  email: string
  /** The workspace, for example ".do Industries". */
  workspace: string
  /** The role granted, for example "Admin". */
  role: string
  /** Absolute `/invite/:token` URL. */
  acceptUrl: string
  /** Default 7. */
  expiresInDays?: number
}

/** "an Admin", "an Owner", "a Member", "a User". */
function article(word: string): string {
  return /^[aeio]/i.test(word) ? 'an' : 'a'
}

export function invitationEmail(props: InvitationEmailProps): EmailParts {
  const inviter = oneLine(props.inviter)
  const email = oneLine(props.email)
  const workspace = oneLine(props.workspace)
  const role = oneLine(props.role)
  const acceptUrl = httpUrl(props.acceptUrl)
  const days = props.expiresInDays ?? 7
  const invited = ` to the ${workspace} workspace as ${article(role)} ${role}.`
  const expiry = `The invite expires in ${days} ${days === 1 ? 'day' : 'days'}. If you weren’t expecting it, you can ignore this email.`
  return {
    from: { name: `${inviter} via id.org.ai`, email: NO_REPLY },
    subject: `${inviter} invited you to ${workspace}`,
    content: (
      <EmailContent
        blocks={[
          <EmailHeading>{`Join ${workspace}`}</EmailHeading>,
          <EmailParagraph>
            {`${inviter} invited `}
            <EmailStrong>{email}</EmailStrong>
            {invited}
          </EmailParagraph>,
          <EmailButton href={acceptUrl}>Accept invitation</EmailButton>,
          <EmailParagraph>{expiry}</EmailParagraph>,
        ]}
      />
    ),
    text: emailText([`Join ${workspace}`, `${inviter} invited ${email}${invited}`, `Accept invitation: ${acceptUrl}`, expiry]),
  }
}

export function renderInvitationEmail(props: InvitationEmailProps, opts?: EmailRenderOptions): RenderedEmail {
  return renderEmail(invitationEmail(props), opts)
}
