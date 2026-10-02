/**
 * 6c · Add a passkey (docs/product-update/spec/screens.md#6c).
 *
 * GET/POST /passkeys/new?continue=. Offered once, right after a code sign-in,
 * when the browser supports WebAuthn and the person has no passkey. Both
 * buttons submit: `decision=add` is the WebAuthn create (the passkey script
 * takes it over through `data-on="passkey"`, B7), `decision=later` remembers
 * the dismissal for 30 days.
 * Either continues.
 */
import type { JSX } from 'hono/jsx/jsx-runtime'
import { Actions, Button, Card, CardFoot, CardHead, Connector, Page, type TileContent } from '../components'

export interface AddPasskeyProps {
  /** The form target: /passkeys/new?continue=<validated>. */
  action: string
  csrf: string
  /** Creating the passkey: the primary shows "Adding…". */
  busy?: boolean
}

const ORG: TileContent = { kind: 'org' }
const KEY: TileContent = { kind: 'icon', icon: 'key' }

export function AddPasskey(p: AddPasskeyProps): JSX.Element {
  return (
    <Page narrow>
      <form class="id-form" method="post" action={p.action} data-js="submit">
        <input type="hidden" name="csrf" value={p.csrf} />
        <Card
          foot={
            <CardFoot>
              <Actions>
                <Button variant="secondary" block name="decision" value="later" disabled={p.busy}>
                  Not now
                </Button>
                <Button variant="primary" block name="decision" value="add" icon="key" busy={p.busy} busyLabel="Adding…" on="passkey">
                  Add a passkey
                </Button>
              </Actions>
            </CardFoot>
          }
        >
          <CardHead
            connector={<Connector left={ORG} right={KEY} />}
            title="Sign in faster with a passkey"
            description="Use Touch ID, Face ID or a security key instead of email codes. Passkeys can’t be phished."
          />
          <span class="id-sr" role="status" data-status></span>
        </Card>
      </form>
    </Page>
  )
}
