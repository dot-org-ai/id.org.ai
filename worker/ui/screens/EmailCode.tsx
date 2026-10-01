/**
 * 1b · Email code (docs/product-update/spec/screens.md#1b).
 *
 * GET/POST /login/code/:flow (the RP-initiated /magic-link/:flow renders the
 * same screen). Verify posts the six boxes; every box is named `code`, so the
 * server joins them. A ?code= link prefills the boxes and never auto-submits.
 * Resend posts its own form to /login/code/:flow/resend once the countdown ends.
 *
 * States: a wrong code clears the boxes and shows the error under them in
 * accent (no shake); too many tries also disables Verify and offers a new code.
 */
import type { JSX } from 'hono/jsx/jsx-runtime'
import { Actions, Button, Card, CardFoot, CardHead, CodeInput, Connector, Em, FootNote, Page, Stack, type TileContent } from '../components'
import { CodeHint } from '../components/CodeHint'
import { Resend, ResendForm } from '../components/Resend'

export type EmailCodeError = 'wrong-code' | 'too-many-tries'

export interface EmailCodeProps {
  app: { name: string; tile: TileContent }
  /** Shown in full: it's the person's own address. */
  email: string
  expiresInMinutes: number
  /** POST /login/code/:flow */
  action: string
  /** POST /login/code/:flow/resend */
  resendAction: string
  csrf: string
  /** Back to 1a with the email cleared. */
  differentEmailHref: string
  /** Prefill from the email link (/login/code/:flow?code=…). */
  code?: string
  /** Seconds until a new code can be sent (the send budget, B4). */
  resendIn: number
  /** When the resend wait ends (ISO 8601). */
  resendAt: string
  error?: EmailCodeError
  /** Gallery only: draw this box focused (the mock shows the 5th). */
  focusIndex?: number
}

const ORG: TileContent = { kind: 'org' }
const ERROR_ID = 'code-error'
const RESEND_FORM = 'resend'

const ERRORS: Record<EmailCodeError, string> = {
  'wrong-code': 'That code didn’t match. Check the email and try again.',
  'too-many-tries': 'Too many tries. Send a new code to keep going.',
}

export function EmailCode(p: EmailCodeProps): JSX.Element {
  const locked = p.error === 'too-many-tries'
  // A wrong code clears the boxes; the script focuses the first one.
  const code = p.error ? undefined : p.code
  return (
    <Page>
      <form class="id-form" method="post" action={p.action} data-js="submit">
        <input type="hidden" name="csrf" value={p.csrf} />
        <Card
          foot={
            <CardFoot>
              <Actions>
                <Button variant="secondary" block href={p.differentEmailHref}>
                  Use a different email
                </Button>
                <Button variant="primary" block busyLabel="Verifying…" disabled={locked}>
                  Verify
                </Button>
              </Actions>
              <FootNote icon="mail">Or open the link in the email on this device.</FootNote>
            </CardFoot>
          }
        >
          <CardHead
            connector={<Connector left={ORG} right={p.app.tile} />}
            title="Check your email"
            description={
              <>
                We sent a 6-digit code to <Em>{p.email}</Em>. It expires in {p.expiresInMinutes} minutes.
              </>
            }
          />
          {p.error ? (
            <Stack gap={8}>
              <CodeInput length={6} label="Enter the 6-digit code" value={code} focusIndex={p.focusIndex} errorId={ERROR_ID} />
              <CodeHint id={ERROR_ID} error>
                {ERRORS[p.error]}
              </CodeHint>
            </Stack>
          ) : (
            <CodeInput length={6} label="Enter the 6-digit code" value={code} focusIndex={p.focusIndex} />
          )}
          <Resend availableIn={locked ? 0 : p.resendIn} availableAt={p.resendAt} form={RESEND_FORM} />
          <span class="id-sr" role="status"></span>
        </Card>
      </form>
      <ResendForm id={RESEND_FORM} action={p.resendAction} csrf={p.csrf} />
    </Page>
  )
}
