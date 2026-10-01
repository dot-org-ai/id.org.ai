/**
 * 2c · Handing off (docs/product-update/spec/screens.md#2c).
 *
 * The final response when the browser leaves id.org.ai for the app after a
 * choice made here. The connector shows `connecting` (this page is the
 * in-between moment). With `redirect`, the page carries the no-JS fallback
 * `<meta http-equiv="refresh" content="1;url=…">`; it also carries
 * data-js="handoff" and data-target, the hook for the script that runs
 * `location.replace(target)` on the next frame (wired with the route, B5).
 * The gallery omits `redirect`, so nothing navigates.
 */
import type { JSX } from 'hono/jsx/jsx-runtime'
import { Card, CardFoot, CardHead, Connector, Em, FootText, Link, Page, type TileContent } from '../components'

export interface HandoffProps {
  app: { name: string; tile: TileContent }
  account: { name: string }
  workspace?: { name: string }
  /** The redirect URL back to the app (already validated against the client's redirect URIs). */
  target: string
  /** Production: emit the meta refresh (and the script hook). The gallery leaves it off. */
  redirect?: boolean
}

const ORG: TileContent = { kind: 'org' }

export function Handoff(p: HandoffProps): JSX.Element {
  const title = `Signing you in to ${p.app.name}`
  return (
    <Page>
      {p.redirect ? <meta http-equiv="refresh" content={`1;url=${p.target}`} data-js="handoff" data-target={p.target} /> : null}
      <Card
        foot={
          <CardFoot>
            <FootText>
              Not redirected? <Link href={p.target}>{`Continue to ${p.app.name}`}</Link>
            </FootText>
          </CardFoot>
        }
      >
        <CardHead
          connector={<Connector left={ORG} right={p.app.tile} state="connecting" />}
          title={title}
          description={
            <>
              as <Em>{p.account.name}</Em>
              {p.workspace ? ` · ${p.workspace.name}` : null}
            </>
          }
        />
        <span class="id-sr" role="status" data-status>
          {`${title}…`}
        </span>
      </Card>
    </Page>
  )
}
