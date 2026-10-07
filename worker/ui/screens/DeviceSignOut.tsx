/**
 * "Sign this device out" (docs/product-update/spec/backend.md#b3), reached
 * from 4d's "Wasn’t you?" link. No mock: built from 4d's parts. A link must
 * never revoke by itself, so `GET /device/:id/revoke` asks, and the form posts
 * (with CSRF) to the same URL, which revokes the device's grant and shows
 * `done`.
 */
import type { JSX } from 'hono/jsx/jsx-runtime'
import { Actions, Button, Card, CardFoot, CardHead, Connector, FootText, Page, type TileContent } from '../components'

const ORG: TileContent = { kind: 'org' }

export interface DeviceSignOutProps {
  state: 'confirm' | 'done'
  client: { name: string; tile: TileContent }
  /** "macOS · Miami, FL", when known. */
  device?: string
  /** POST /device/:id/revoke */
  action: string
  csrf: string
  /** Where "Keep it signed in" goes. */
  cancelHref: string
}

export function DeviceSignOut(p: DeviceSignOutProps): JSX.Element {
  const which = p.device ? `${p.client.name} on ${p.device}` : p.client.name
  if (p.state === 'done') {
    return (
      <Page>
        <Card
          foot={
            <CardFoot>
              <FootText>It will need to sign in again before it can act as you.</FootText>
            </CardFoot>
          }
        >
          <CardHead connector={<Connector left={ORG} right={p.client.tile} state="fail" />} title="Device signed out" description={`${which} is signed out.`} />
          <span class="id-sr" role="status" data-status>
            Device signed out
          </span>
        </Card>
      </Page>
    )
  }
  return (
    <Page>
      <form class="id-form" method="post" action={p.action} data-js="submit">
        <input type="hidden" name="csrf" value={p.csrf} />
        <Card
          foot={
            <CardFoot>
              <Actions>
                <Button variant="secondary" block href={p.cancelHref}>
                  Keep it signed in
                </Button>
                <Button variant="primary" block busyLabel="Signing out…">
                  Sign it out
                </Button>
              </Actions>
            </CardFoot>
          }
        >
          <CardHead
            connector={<Connector left={ORG} right={p.client.tile} />}
            title="Sign this device out?"
            description={`${which} loses access to your account. Its sign-in can’t be used again.`}
          />
          <span class="id-sr" role="status" data-status></span>
        </Card>
      </form>
    </Page>
  )
}
