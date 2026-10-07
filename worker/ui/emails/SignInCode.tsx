/**
 * 8a · Sign-in code email (spec/screens.md#8a). The code goes in the subject for
 * autofill; the card shows it grouped ("482 913").
 */
import {
  EmailCode,
  EmailContent,
  EmailHeading,
  EmailMeta,
  EmailParagraph,
  EmailStrong,
  emailText,
  NO_REPLY,
  oneLine,
  renderEmail,
  type EmailParts,
  type EmailRenderOptions,
  type RenderedEmail,
} from './layout'

export interface SignInCodeEmailProps {
  /** The one-time code, for example "482913". */
  code: string
  /** The app being signed in to, for example "headless.ly". */
  app: string
  /** Where the request came from: browser, OS and (when known) "city, region". */
  browser: string
  os: string
  location?: string
  /** Default 10. */
  expiresInMinutes?: number
}

export function signInCodeEmail(props: SignInCodeEmailProps): EmailParts {
  const code = oneLine(props.code)
  const app = oneLine(props.app)
  const minutes = props.expiresInMinutes ?? 10
  const expiry = `It expires in ${minutes} ${minutes === 1 ? 'minute' : 'minutes'} and works once.`
  const ignore = 'Didn’t try to sign in? Ignore this email. Someone may have typed your address by mistake; nothing happens without the code.'
  const requested = `Requested from ${oneLine(props.browser)} on ${oneLine(props.os)}${props.location ? ` · ${oneLine(props.location)}` : ''}`
  return {
    from: { name: 'id.org.ai', email: NO_REPLY },
    subject: `Your id.org.ai code: ${code}`,
    content: (
      <EmailContent
        blocks={[
          <EmailHeading>Your sign-in code</EmailHeading>,
          <EmailCode code={code} />,
          <EmailParagraph>
            Enter this code to sign in to <EmailStrong>{app}</EmailStrong>. {expiry}
          </EmailParagraph>,
          <EmailParagraph>{ignore}</EmailParagraph>,
          <EmailMeta>{requested}</EmailMeta>,
        ]}
      />
    ),
    text: emailText(['Your sign-in code', code, `Enter this code to sign in to ${app}. ${expiry}`, ignore, requested]),
  }
}

export function renderSignInCodeEmail(props: SignInCodeEmailProps, opts?: EmailRenderOptions): RenderedEmail {
  return renderEmail(signInCodeEmail(props), opts)
}
