/**
 * 2a · Choose account (docs/product-update/spec/screens.md#2a).
 *
 * Each account row is a submit button posting `session=<sessionId>` to
 * `POST /account/choose?continue=`; "Use another account" is a link that adds
 * a session; "Sign out of all accounts" posts `scope=browser` to /signout from
 * its own form in the foot.
 */
import type { JSX } from 'hono/jsx/jsx-runtime'
import {
  AccountList,
  AccountRow,
  AnotherAccountRow,
  Button,
  Card,
  CardFoot,
  CardHead,
  Connector,
  Em,
  Page,
  type TileContent,
} from '../components'

export interface ChooserAccount {
  sessionId: string
  name: string
  email: string
  avatar?: string
  lastUsedHere: boolean
}

export interface AccountChooserProps {
  app: { name: string; tile: TileContent }
  accounts: ChooserAccount[]
  /** `/login?prompt=login&continue=…` (adds a session). */
  anotherAccountHref: string
  /** `/account/choose?continue=…` (POST `{session}`). */
  action: string
  /** `/signout` (POST `{scope: 'browser'}`). */
  signOutAction: string
  csrf: string
}

const ORG: TileContent = { kind: 'org' }

export function AccountChooser(p: AccountChooserProps): JSX.Element {
  return (
    <Page>
      <Card
        foot={
          <CardFoot>
            <form class="id-form id-row-center" method="post" action={p.signOutAction}>
              <input type="hidden" name="csrf" value={p.csrf} />
              <input type="hidden" name="scope" value="browser" />
              <Button variant="ghost" size="sm" icon="logout">
                Sign out of all accounts
              </Button>
            </form>
          </CardFoot>
        }
      >
        <CardHead
          connector={<Connector left={ORG} right={p.app.tile} />}
          title="Choose an account"
          description={
            <>
              to continue to <Em>{p.app.name}</Em>. It only sees the account you pick.
            </>
          }
        />
        <form class="id-form" method="post" action={p.action} data-js="submit">
          <input type="hidden" name="csrf" value={p.csrf} />
          <AccountList>
            {[
              ...p.accounts.map((a) => (
                <AccountRow name={a.name} email={a.email} avatar={a.avatar} lastUsedHere={a.lastUsedHere} sessionValue={a.sessionId} />
              )),
              <AnotherAccountRow href={p.anotherAccountHref}>Use another account</AnotherAccountRow>,
            ]}
          </AccountList>
        </form>
        <span class="id-sr" role="status" data-status></span>
      </Card>
    </Page>
  )
}
