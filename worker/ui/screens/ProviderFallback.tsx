/**
 * 1f · Provider sign-in failed (docs/product-update/spec/screens.md#1f).
 *
 * Rendered by GET /api/callback when the upstream provider returns an error
 * (tenant policy, admin consent, outage). The reason is one plain sentence
 * mapped from the upstream code; the raw code and request ID go in the
 * optional developer details. "Email me a code" posts the email form to
 * POST /login/email; "Try {provider} again" restarts the provider flow.
 */
import type { JSX } from 'hono/jsx/jsx-runtime'
import {
  Actions,
  Button,
  Card,
  CardFoot,
  CardHead,
  Connector,
  CopyButton,
  Disclosure,
  Field,
  Input,
  KeyValues,
  Page,
  PROVIDER_NAMES,
  type KV,
  type Provider,
  type TileContent,
} from '../components'

export interface ProviderFallbackProps {
  app: { name: string; tile: TileContent }
  provider: Provider
  /** One plain sentence, mapped from the upstream error code. */
  reason: string
  /** Prefill for the email field. */
  email?: string
  /** "Work email" when the provider is a work identity (Microsoft); "Email" otherwise. */
  emailLabel?: string
  emailError?: string
  /** POST /login/email */
  action: string
  csrf: string
  continueUrl?: string
  /** Restarts the provider flow (GET /login?provider=…). */
  retryHref: string
  /** Developer details (upstream error code, request ID), closed by default. */
  details?: { items: KV[]; copy: string }
}

const ORG: TileContent = { kind: 'org' }

export function ProviderFallback(p: ProviderFallbackProps): JSX.Element {
  const name = PROVIDER_NAMES[p.provider]
  return (
    <Page narrow>
      <form class="id-form" method="post" action={p.action} data-js="submit">
        <input type="hidden" name="csrf" value={p.csrf} />
        {p.continueUrl ? <input type="hidden" name="continue" value={p.continueUrl} /> : null}
        <Card
          foot={
            <CardFoot>
              <Actions>
                <Button variant="secondary" block href={p.retryHref}>
                  {`Try ${name} again`}
                </Button>
                <Button variant="primary" block icon="mail" busyLabel="Sending code…">
                  Email me a code
                </Button>
              </Actions>
            </CardFoot>
          }
        >
          <CardHead
            connector={<Connector left={ORG} right={p.app.tile} state="fail" />}
            title={`${name} sign-in didn’t finish`}
            description={`${p.reason} Verify with an emailed code instead.`}
          />
          <Field id="fallback-email" label={p.emailLabel ?? 'Email'} error={p.emailError}>
            <Input id="fallback-email" name="email" type="email" value={p.email} autocomplete="email" required autofocus={Boolean(p.emailError)} error={Boolean(p.emailError)} />
          </Field>
          {p.details ? (
            <Disclosure summary="Developer details">
              <KeyValues items={p.details.items} />
              <CopyButton value={p.details.copy} labelled />
            </Disclosure>
          ) : null}
          <span class="id-sr" role="status" data-status></span>
        </Card>
      </form>
    </Page>
  )
}
