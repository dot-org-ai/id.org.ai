/**
 * 1c · SSO domain (docs/product-update/spec/screens.md#1c).
 *
 * GET /login/sso?email=&continue=: the email's domain belongs to an
 * organisation with an active SSO connection. "Continue with {idp}" leaves for
 * WorkOS authorize (organization_id or connection_id, plus login_hint), so it
 * is a link; nothing here posts.
 */
import type { JSX } from 'hono/jsx/jsx-runtime'
import { Actions, Button, Card, CardFoot, CardHead, Connector, Em, Note, Page, Well, type TileContent } from '../components'
import { OrgRow } from '../components/OrgRow'

export interface SsoProps {
  app: { name: string; tile: TileContent }
  email: string
  org: { name: string; domain: string }
  /** Okta, Entra ID, Google Workspace…, from the connection type. */
  idpName: string
  /** The org enforces SSO: shows the lock note. */
  enforced: boolean
  /** The WorkOS authorize URL for this organisation (server-built). */
  continueHref: string
  /** Back to 1a. */
  differentEmailHref: string
}

const ORG: TileContent = { kind: 'org' }

export function Sso(p: SsoProps): JSX.Element {
  return (
    <Page>
      <Card
        foot={
          <CardFoot>
            <Actions>
              <Button variant="secondary" block href={p.differentEmailHref}>
                Use a different email
              </Button>
              <Button variant="primary" block icon="external" href={p.continueHref}>
                {`Continue with ${p.idpName}`}
              </Button>
            </Actions>
          </CardFoot>
        }
      >
        <CardHead
          connector={<Connector left={ORG} right={p.app.tile} />}
          title={`${p.org.name} uses single sign-on`}
          description={
            <>
              <Em>{p.email}</Em>
              {` is managed by your company. You’ll sign in with ${p.idpName} and come straight back.`}
            </>
          }
        />
        <Well variant="quote">
          <OrgRow name={p.org.name} sub={`Verified domain ${p.org.domain}`} />
        </Well>
        {p.enforced ? <Note icon="lock">Your admin controls this account. Personal sign-in methods are turned off for it.</Note> : null}
      </Card>
    </Page>
  )
}
