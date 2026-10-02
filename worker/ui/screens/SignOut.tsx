/**
 * 6b · Sign out (docs/product-update/spec/screens.md#6b).
 *
 * GET/POST /signout?client_id=&return_url=. Scope defaults to this app only;
 * "everywhere" carries the accent dot (and needs a fresh auth_time, B8: the
 * server answers `{redirect}` to step-up when it is stale). Cancel goes back
 * to return_url, which the route has already validated. Without an app (no
 * client_id) the head shows id.org.ai alone and the choice starts at this
 * browser.
 *
 * 6b stays on id.org.ai (motion.md#where-the-person-goes-next), so the form is
 * a fetch-form (worker/ui/client/lib/fetch-form.ts): Sign out goes
 * `connecting`, then `done` on the server's OK, and the `signed-out` template
 * swaps in 2150ms later. Without JS the form posts and the server renders the
 * same result as `state: 'signed-out'`, naming the scope that was signed out.
 */
import type { Child } from 'hono/jsx'
import type { JSX } from 'hono/jsx/jsx-runtime'
import {
  Actions,
  Button,
  Card,
  CardFoot,
  CardHead,
  Connector,
  Dotted,
  Em,
  FootText,
  Link,
  Page,
  RadioCard,
  SingleTile,
  Stack,
  Who,
  type ConnectorState,
  type TileContent,
} from '../components'
import { RadioGroup } from '../components/RadioCard'

export type SignOutScope = 'app' | 'browser' | 'everywhere'

export type SignOutState = 'idle' | 'signed-out'

export interface SignOutProps {
  /** `idle` is the live form; `signed-out` is the result. */
  state?: SignOutState
  /** The app asking to sign out (from client_id). */
  app?: { name: string; tile: TileContent }
  account: { name: string; email: string; avatar?: string }
  /**
   * The preselected scope: `app` by default, `browser` without an app. On the
   * `signed-out` result, the scope that was signed out.
   */
  scope?: SignOutScope
  /** POST /signout */
  action: string
  csrf: string
  clientId?: string
  /** Already validated by resolveBrowserRedirect (enforce). The result's "Continue to {app}" link. */
  returnUrl?: string
  /** Where Cancel goes: return_url, or the account home. */
  cancelHref: string
  /** Signing out: the primary shows "Signing out…" and the connector is connecting. */
  busy?: boolean
}

const ORG: TileContent = { kind: 'org' }

function defaultScope(p: SignOutProps): SignOutScope {
  return p.scope ?? (p.app ? 'app' : 'browser')
}

function headTile(p: SignOutProps, state: ConnectorState): Child {
  return p.app ? <Connector left={ORG} right={p.app.tile} state={state} /> : <SingleTile content={ORG} />
}

/**
 * What was signed out. `scope` is unknown (undefined) in the live page's
 * template, which is rendered before the choice: it then says only what every
 * scope did (this app, or this browser without one).
 */
export function signedOutDescription(app: string | undefined, scope: SignOutScope | undefined): Child {
  switch (scope) {
    case 'app':
      if (app) {
        return (
          <>
            You’re signed out of <Em>{app}</Em>. You’re still signed in to id.org.ai and your other apps.
          </>
        )
      }
      return 'You’re signed out of id.org.ai and every app using it in this browser.'
    case 'browser':
      return 'You’re signed out of id.org.ai and every app using it in this browser.'
    case 'everywhere':
      return 'You’re signed out of id.org.ai on every browser, CLI and device.'
    default:
      if (app) {
        return (
          <>
            You’re signed out of <Em>{app}</Em>.
          </>
        )
      }
      return 'You’re signed out of id.org.ai in this browser.'
  }
}

function FormBody({ p }: { p: SignOutProps }): JSX.Element {
  const scope = defaultScope(p)
  return (
    <Stack gap={22}>
      <CardHead connector={headTile(p, p.busy ? 'connecting' : 'idle')} title="Sign out" description="Choose how far to sign out." />
      <Dotted />
      <Who name={p.account.name} sub={p.account.email} avatar={p.account.avatar} />
      <RadioGroup legend="How far to sign out" layout="stack" hideLabel>
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
      </RadioGroup>
    </Stack>
  )
}

function FormFoot({ p }: { p: SignOutProps }): JSX.Element {
  return (
    <Actions>
      <Button variant="secondary" block href={p.cancelHref}>
        Cancel
      </Button>
      <Button variant="primary" block icon="logout" busy={p.busy} busyLabel="Signing out…" done="signed-out">
        Sign out
      </Button>
    </Actions>
  )
}

function SignedOutBody({ p, scope }: { p: SignOutProps; scope: SignOutScope | undefined }): JSX.Element {
  return (
    <Stack gap={22}>
      <CardHead connector={headTile(p, 'ok')} title="You’re signed out" description={signedOutDescription(p.app?.name, scope)} />
    </Stack>
  )
}

function SignedOutFoot({ p }: { p: SignOutProps }): JSX.Element {
  return (
    <div class="id-fade">
      <FootText>
        {p.returnUrl ? <Link href={p.returnUrl}>{p.app ? `Continue to ${p.app.name}` : 'Continue'}</Link> : 'You can close this tab.'}
      </FootText>
    </div>
  )
}

export function SignOut(p: SignOutProps): JSX.Element {
  if (p.state === 'signed-out') {
    return (
      <Page narrow>
        <Card
          foot={
            <CardFoot>
              <SignedOutFoot p={p} />
            </CardFoot>
          }
        >
          <SignedOutBody p={p} scope={defaultScope(p)} />
          <span class="id-sr" role="status" data-status>
            Signed out
          </span>
        </Card>
      </Page>
    )
  }
  const live = !p.busy
  return (
    <Page narrow>
      <form class="id-form" method="post" action={p.action} data-js="fetch-form">
        <input type="hidden" name="csrf" value={p.csrf} />
        {p.clientId ? <input type="hidden" name="client_id" value={p.clientId} /> : null}
        {p.returnUrl ? <input type="hidden" name="return_url" value={p.returnUrl} /> : null}
        <Card
          foot={
            <CardFoot>
              <div data-region="foot">
                <FormFoot p={p} />
              </div>
              {live ? (
                <template data-state="signed-out">
                  <SignedOutFoot p={p} />
                </template>
              ) : null}
            </CardFoot>
          }
        >
          <div data-region="body">
            <FormBody p={p} />
          </div>
          {live ? (
            <template data-state="signed-out">
              <SignedOutBody p={p} scope={undefined} />
            </template>
          ) : null}
          <span class="id-sr" role="status" data-status></span>
        </Card>
      </form>
    </Page>
  )
}
