/**
 * 1e · Email already has an account (docs/product-update/spec/screens.md#1e, D6).
 *
 * GET /login/link?flow=: a sign-in resolved to an email that already belongs
 * to another id.org.ai identity. "Continue with {existing}" proves the old
 * method (GET /login?provider=…), then the accounts are linked and the person
 * is signed in. Nothing is merged before that.
 */
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
  Note,
  Page,
  PROVIDER_NAMES,
  Who,
  type Provider,
  type TileContent,
} from '../components'
import { ProviderAction } from '../components/ProviderAction'

export interface LinkAccountProps {
  app: { name: string; tile: TileContent }
  email: string
  /** How the existing identity signs in. */
  existingProvider: Provider
  /** The method just used, to be added to it. */
  newProvider: Provider
  identity: { name: string; email: string; avatar?: string }
  /** GET /login?provider=…&link=<flow>: sign in with the existing method. */
  continueHref: string
  /** Back to 1a. */
  differentEmailHref: string
}

const ORG: TileContent = { kind: 'org' }

export function LinkAccount(p: LinkAccountProps): JSX.Element {
  const existing = PROVIDER_NAMES[p.existingProvider]
  const added = PROVIDER_NAMES[p.newProvider]
  return (
    <Page>
      <Card
        foot={
          <CardFoot>
            <Actions>
              <Button variant="secondary" block href={p.differentEmailHref}>
                Use a different email
              </Button>
              <ProviderAction provider={p.existingProvider} href={p.continueHref}>
                {`Continue with ${existing}`}
              </ProviderAction>
            </Actions>
          </CardFoot>
        }
      >
        <CardHead
          connector={<Connector left={ORG} right={p.app.tile} />}
          title="You already have an account"
          description={
            <>
              <Em>{p.email}</Em>
              {` signs in with ${existing}. Sign in with ${existing} once and we’ll add ${added} to the same account.`}
            </>
          }
        />
        <Dotted />
        <Who name={p.identity.name} sub={`${p.identity.email} · signs in with ${existing}`} email={p.identity.email} avatar={p.identity.avatar} />
        <Note icon="lock">We only link accounts after you prove you own both. Nothing is merged until then.</Note>
      </Card>
    </Page>
  )
}
