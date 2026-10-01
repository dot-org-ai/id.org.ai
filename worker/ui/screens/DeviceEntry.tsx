/**
 * 4c · Enter device code (docs/product-update/spec/screens.md#4c).
 *
 * Shown at `GET /device` with no code. The boxes are all named `code`, so
 * without JS the form posts the characters in order; the server joins and
 * normalises them (with or without the hyphen) and continues to 4b at
 * `/device?code=XXXX-XXXX`, or renders this page again with `error`.
 */
import type { JSX } from 'hono/jsx/jsx-runtime'
import { Button, Card, CardFoot, CardHead, CodeInput, Connector, Page, type TileContent } from '../components'
import { CodeHint } from '../components/CodeHint'

export interface DeviceEntryProps {
  /** What was typed, when re-rendering after an error. */
  value?: string
  /** The code was invalid, expired or already used. */
  error?: string
  /** Gallery only: draw this box focused (the mock shows the first). */
  focusIndex?: number
  /** `/device` */
  action: string
  csrf: string
}

const ORG: TileContent = { kind: 'org' }
const DEVICE: TileContent = { kind: 'icon', icon: 'terminal' }
const ERROR_ID = 'device-code-error'

export function DeviceEntry(p: DeviceEntryProps): JSX.Element {
  return (
    <Page>
      <form class="id-form" method="post" action={p.action} data-js="submit">
        <input type="hidden" name="csrf" value={p.csrf} />
        <Card
          foot={
            <CardFoot>
              <Button variant="primary" block busyLabel="Checking…">
                Continue
              </Button>
            </CardFoot>
          }
        >
          <CardHead
            connector={<Connector left={ORG} right={DEVICE} />}
            title="Connect a device"
            description="Enter the code shown in your terminal or on your device."
          />
          <CodeInput length={8} value={p.value} focusIndex={p.focusIndex} label="Enter the 8-character device code" errorId={p.error ? ERROR_ID : undefined} />
          {p.error ? (
            <CodeHint id={ERROR_ID} error>
              {p.error}
            </CodeHint>
          ) : (
            <CodeHint>Codes look like WDJB-MJHT and last 30 minutes.</CodeHint>
          )}
          <span class="id-sr" role="status" data-status>
            {p.error ?? ''}
          </span>
        </Card>
      </form>
    </Page>
  )
}
