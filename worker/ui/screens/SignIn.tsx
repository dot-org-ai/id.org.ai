/**
 * 1a · Sign in and 1g · Branded sign-in (docs/product-update/spec/screens.md#1a, #1g).
 *
 * Email first: the email form posts to POST /login/email (SSO domains go to
 * 1c, everything else gets a code and 1b). Providers are links to
 * GET /login?provider=…; the passkey button hands off to hosted AuthKit until
 * FEATURE_PASSKEYS is on, when B7's script upgrades it to WebAuthn in place.
 *
 * With `brand` (first-party clients only) the header shows the app's tile and
 * name, the footer reads "Secured by id.org.ai", and the head is the app's
 * single tile. An app sets its name and mark, nothing else.
 */
import type { JSX } from 'hono/jsx/jsx-runtime'
import {
  Button,
  Card,
  CardFoot,
  CardHead,
  Connector,
  Dotted,
  Em,
  Field,
  FootText,
  Input,
  Page,
  ProviderButton,
  Providers,
  SingleTile,
  Stack,
  type AppBrandProps,
  type Provider,
  type TileContent,
} from '../components'

export interface ProviderLink {
  provider: Provider
  /** GET /login?provider=… (login_hint and continue forwarded). */
  href: string
}

export interface SignInProps {
  /** The app being signed in to (from client_id or the continue host). Absent on a bare /login. */
  app?: { name: string; tile: TileContent }
  /** 1g: a listed first-party client's brand. Never set for third-party clients. */
  brand?: AppBrandProps
  /** From a valid login_hint, or the address that failed validation. */
  email?: string
  /** Shown under the email field (invalid address, send budget spent). */
  emailError?: string
  /** POST /login/email */
  action: string
  csrf: string
  /** The continue URL, carried through the email form. */
  continueUrl?: string
  /** Enabled providers, in order (GitHub, Google, Microsoft, Apple). */
  providers: ProviderLink[]
  /** From the id_last_provider cookie: shows the "Last used" pill. */
  lastUsedProvider?: Provider
  /**
   * The passkey button. `href` is hosted AuthKit (/login?provider=authkit&…),
   * which supports passkeys (D2); `webauthn` (FEATURE_PASSKEYS=1) marks it for
   * B7's WebAuthn script, with the href as the no-JS fallback.
   */
  passkey?: { href: string; webauthn?: boolean }
}

const ORG: TileContent = { kind: 'org' }

/** Copy for first-party (.do) apps; not settable by the app. */
const BRANDED_DESCRIPTION = 'Use the same account you use across .do apps.'

function Head({ p }: { p: SignInProps }): JSX.Element {
  if (p.brand && p.app) {
    return <CardHead connector={<SingleTile content={p.app.tile} />} title={`Sign in to ${p.app.name}`} description={BRANDED_DESCRIPTION} />
  }
  if (p.app) {
    return (
      <CardHead
        connector={<Connector left={ORG} right={p.app.tile} />}
        title="Sign in"
        description={
          <>
            to continue to <Em>{p.app.name}</Em>
          </>
        }
      />
    )
  }
  return (
    <CardHead
      connector={<SingleTile content={ORG} />}
      title="Sign in"
      description={
        <>
          to continue to <Em>id.org.ai</Em>
        </>
      }
    />
  )
}

export function SignIn(p: SignInProps): JSX.Element {
  const emailId = 'email'
  return (
    <Page branded={p.brand}>
      <Card
        foot={
          <CardFoot>
            <FootText>New here? Any option above creates your account.</FootText>
          </CardFoot>
        }
      >
        <Head p={p} />
        <form class="id-form" method="post" action={p.action} data-js="submit">
          <input type="hidden" name="csrf" value={p.csrf} />
          {p.continueUrl ? <input type="hidden" name="continue" value={p.continueUrl} /> : null}
          <Stack gap={12}>
            <Field id={emailId} label="Email" error={p.emailError}>
              <Input
                id={emailId}
                name="email"
                type="email"
                value={p.email}
                placeholder="you@company.com"
                autocomplete="email"
                required
                autofocus={p.emailError ? true : undefined}
                error={Boolean(p.emailError)}
              />
            </Field>
            <Button variant="primary" block busyLabel="Sending code…">
              Continue with email
            </Button>
          </Stack>
        </form>
        <Dotted label="or" />
        <Providers>
          {p.providers.map((x) => (
            <ProviderButton provider={x.provider} href={x.href} lastUsed={x.provider === p.lastUsedProvider} />
          ))}
        </Providers>
        {p.passkey ? (
          <Button variant="secondary" block icon="key" href={p.passkey.href} on={p.passkey.webauthn ? 'passkey' : undefined}>
            Sign in with a passkey
          </Button>
        ) : null}
        <span class="id-sr" role="status" data-status></span>
      </Card>
    </Page>
  )
}
