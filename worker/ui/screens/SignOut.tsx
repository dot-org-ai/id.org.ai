/**
 * 6b · Sign out (docs/product-update/spec/screens.md#6b).
 *
 * GET/POST /signout?client_id=&return_url=. Scope defaults to this app only;
 * "everywhere" carries the accent dot (and needs a fresh auth_time, B8).
 * Cancel goes back to return_url, which the route has already validated.
 * Without an app (no client_id) the head shows id.org.ai alone and the
 * choice starts at this browser.
 */
import type { JSX } from 'hono/jsx/jsx-runtime'
import { Actions, Button, Card, CardFoot, CardHead, Connector, Dotted, Page, RadioCard, SingleTile, Who, type TileContent } from '../components'
import { RadioStack } from '../components/RadioStack'

export type SignOutScope = 'app' | 'browser' | 'everywhere'

export interface SignOutProps {
  /** The app asking to sign out (from client_id). */
  app?: { name: string; tile: TileContent }
  account: { name: string; email: string; avatar?: string }
  /** The preselected scope: `app` by default, `browser` without an app. */
  scope?: SignOutScope
  /** POST /signout */
  action: string
  csrf: string
  clientId?: string
  /** Already validated by resolveBrowserRedirect (enforce). */
  returnUrl?: string
  /** Where Cancel goes: return_url, or the account home. */
  cancelHref: string
  /** Signing out: the primary shows "Signing out…". */
  busy?: boolean
}

const ORG: TileContent = { kind: 'org' }

export function SignOut(p: SignOutProps): JSX.Element {
  const scope: SignOutScope = p.scope ?? (p.app ? 'app' : 'browser')
  const connector = p.app ? <Connector left={ORG} right={p.app.tile} /> : <SingleTile content={ORG} />
  return (
    <Page>
      <form class="id-form" method="post" action={p.action} data-js="submit">
        <input type="hidden" name="csrf" value={p.csrf} />
        {p.clientId ? <input type="hidden" name="client_id" value={p.clientId} /> : null}
        {p.returnUrl ? <input type="hidden" name="return_url" value={p.returnUrl} /> : null}
        <Card
          foot={
            <CardFoot>
              <Actions>
                <Button variant="secondary" block href={p.cancelHref}>
                  Cancel
                </Button>
                <Button variant="primary" block icon="logout" busy={p.busy} busyLabel="Signing out…">
                  Sign out
                </Button>
              </Actions>
            </CardFoot>
          }
        >
          <CardHead connector={connector} title="Sign out" description="Choose how far to sign out." />
          <Dotted />
          <Who name={p.account.name} sub={p.account.email} avatar={p.account.avatar} />
          <RadioStack legend="How far to sign out">
            {p.app ? (
              <RadioCard
                id="signout-app"
                name="scope"
                value="app"
                checked={scope === 'app'}
                title={`Sign out of ${p.app.name}`}
                description="You stay signed in to id.org.ai and your other apps."
              />
            ) : null}
            <RadioCard
              id="signout-browser"
              name="scope"
              value="browser"
              checked={scope === 'browser'}
              title="Sign out of this browser"
              description="Ends your id.org.ai session and every app using it here."
            />
            <RadioCard
              id="signout-everywhere"
              name="scope"
              value="everywhere"
              checked={scope === 'everywhere'}
              accent
              title="Sign out everywhere"
              description="Also signs out other browsers, CLIs and devices."
            />
          </RadioStack>
          <span class="id-sr" role="status" data-status></span>
        </Card>
      </form>
    </Page>
  )
}
