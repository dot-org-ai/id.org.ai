/**
 * 6d · Two-step code (docs/product-update/spec/screens.md#6d).
 *
 * GET/POST /login/two-step/:flow, shown when a workspace requires two-step and
 * WorkOS returns an MFA challenge. Verify posts the six boxes (each named
 * `code`, joined by the server); it never auto-submits. Per D8 "Use a passkey
 * instead" shows only when the person has a passkey, and "Use a recovery code"
 * stays hidden until a recovery design exists: each renders only when its
 * href is given.
 */
import type { JSX } from 'hono/jsx/jsx-runtime'
import { Button, Card, CardFoot, CardHead, CodeInput, Connector, Em, Link, Page, Stack, type TileContent } from '../components'
import { FootLinks } from '../components/FootLinks'
import { InlineError } from '../components/InlineError'

export interface TwoStepProps {
  /** The workspace that requires two-step ("Drivly"). */
  workspace: string
  /** The form target: /login/two-step/:flow. */
  action: string
  csrf: string
  /** Prefilled characters (the gallery shows "19"). */
  value?: string
  /** Gallery only: draw this box focused. */
  focusIndex?: number
  /** Wrong code or too many tries: shown under the boxes in accent. */
  error?: string
  /** "Use a passkey instead": only when the person has a passkey (D8). */
  passkeyHref?: string
  /** "Use a recovery code": hidden until a recovery design exists (D8). */
  recoveryHref?: string
  /** Verifying: the primary shows "Verifying…". */
  busy?: boolean
}

const ORG: TileContent = { kind: 'org' }
const SHIELD: TileContent = { kind: 'icon', icon: 'shield' }
const ERROR_ID = 'two-step-error'

export function TwoStep(p: TwoStepProps): JSX.Element {
  const links = p.passkeyHref || p.recoveryHref
  const code = <CodeInput length={6} value={p.value} focusIndex={p.focusIndex} label="Enter the 6-digit code from your authenticator app" errorId={p.error ? ERROR_ID : undefined} />
  return (
    <Page>
      <form class="id-form" method="post" action={p.action} data-js="submit">
        <input type="hidden" name="csrf" value={p.csrf} />
        <Card
          foot={
            <CardFoot>
              <Button variant="primary" block grow busy={p.busy} busyLabel="Verifying…">
                Verify
              </Button>
              {links ? (
                <FootLinks>
                  {p.passkeyHref ? <Link href={p.passkeyHref}>Use a passkey instead</Link> : null}
                  {p.recoveryHref ? <Link href={p.recoveryHref}>Use a recovery code</Link> : null}
                </FootLinks>
              ) : null}
            </CardFoot>
          }
        >
          <CardHead
            connector={<Connector left={ORG} right={SHIELD} />}
            title="Enter your authenticator code"
            description={
              <>
                <Em>{p.workspace}</Em> requires two-step verification for this sign-in.
              </>
            }
          />
          {p.error ? (
            <Stack gap={10}>
              {code}
              <InlineError id={ERROR_ID}>{p.error}</InlineError>
            </Stack>
          ) : (
            code
          )}
          <span class="id-sr" role="status" data-status></span>
        </Card>
      </form>
    </Page>
  )
}
