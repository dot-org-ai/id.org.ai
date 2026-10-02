/**
 * 4d · Device connected (docs/product-update/spec/screens.md#4d), the no-JS
 * result of 4b at `GET /device/done?code=`, and the cancelled card on its own
 * (`GET /device/cancelled?code=`, `outcome: 'cancelled'`). Both are 4b's
 * signed and cancelled content as standalone pages, centred, with no fade.
 */
import type { JSX } from 'hono/jsx/jsx-runtime'
import { Card, CardFoot, CardHead, Connector, FootText, KeyValues, Link, Page, Well, type TileContent } from '../components'

interface DeviceDoneBase {
  client: { name: string; tile: TileContent }
}

export interface DeviceSignedProps extends DeviceDoneBase {
  outcome?: 'signed'
  account: { email: string }
  workspace: { name: string }
  /** "macOS · Miami, FL" */
  device: string
  /** Where "Sign this device out" goes (the device's revoke action, B3). */
  revokeHref: string
}

export interface DeviceCancelledProps extends DeviceDoneBase {
  outcome: 'cancelled'
  /** The CLI people run again ("auto.dev"). */
  cliName: string
}

export type DeviceDoneProps = DeviceSignedProps | DeviceCancelledProps

const ORG: TileContent = { kind: 'org' }

export function DeviceDone(p: DeviceDoneProps): JSX.Element {
  if (p.outcome === 'cancelled') {
    return (
      <Page>
        <Card
          foot={
            <CardFoot>
              <FootText>{`Started it by mistake? Run ${p.cliName} login again.`}</FootText>
            </CardFoot>
          }
        >
          <CardHead
            connector={<Connector left={ORG} right={p.client.tile} state="fail" />}
            title="Sign-in cancelled"
            description={`Your terminal will show the request was denied. Nothing was shared with ${p.client.name}.`}
          />
          <span class="id-sr" role="status" data-status>
            Cancelled
          </span>
        </Card>
      </Page>
    )
  }
  return (
    <Page>
      <Card
        foot={
          <CardFoot>
            <FootText>
              Wasn’t you? <Link href={p.revokeHref}>Sign this device out</Link>
            </FootText>
          </CardFoot>
        }
      >
        <CardHead
          connector={<Connector left={ORG} right={p.client.tile} state="ok" />}
          title={`${p.client.name} is signed in`}
          description="Go back to your terminal. You can close this tab."
        />
        <Well>
          <KeyValues
            items={[
              { k: 'Account', v: p.account.email },
              { k: 'Workspace', v: p.workspace.name },
              { k: 'Device', v: p.device },
            ]}
          />
        </Well>
        <span class="id-sr" role="status" data-status>
          Signed in
        </span>
      </Card>
    </Page>
  )
}
