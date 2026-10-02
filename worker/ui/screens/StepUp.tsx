/**
 * 6a · Confirm it’s you (docs/product-update/spec/screens.md#6a).
 *
 * GET/POST /step-up?resume=<id>&reason=<code>. `resume` is a single-use
 * server-side record, never a URL. The sentence under the title comes from
 * STEP_UP_REASONS, never from the query string. Both factors submit the same
 * form: `factor=email` starts the email code flow in step-up mode (1b) and
 * `factor=passkey` is the WebAuthn get (B7), which the passkey script takes
 * over through `data-on="passkey"` (as on 1a). Either refreshes auth_time and
 * resumes.
 */
import type { JSX } from 'hono/jsx/jsx-runtime'
import { Actions, Button, Card, CardFoot, CardHead, Connector, Dotted, Page, Who, WhoMeta, type TileContent } from '../components'

export type StepUpReason = 'act_permissions' | 'privileged_agent' | 'max_age' | 'sign_out_everywhere'

/** The reason catalogue: the only source of the description (never query text). */
export const STEP_UP_REASONS: Record<StepUpReason, (app: string) => string> = {
  act_permissions: (app) => `Letting ${app} act in your name needs a fresh check.`,
  privileged_agent: (app) => `Approving ${app} as a Privileged agent needs a fresh check.`,
  max_age: (app) => `${app} asks you to confirm it’s you before continuing.`,
  sign_out_everywhere: () => 'Signing out everywhere needs a fresh check.',
}

export interface StepUpProps {
  /** The app (or agent) the check is for. */
  app: { name: string; tile: TileContent }
  reason: StepUpReason
  account: { name: string; email: string; avatar?: string }
  /** "3 hours ago", shown as "Confirmed 3 hours ago". */
  lastConfirmedAgo: string
  /** The factors this person has; the email code is always available for a signed-in session. */
  factors: { passkey: boolean; email: boolean }
  /** The form target: /step-up?resume=<id>&reason=<code>. */
  action: string
  csrf: string
}

const ORG: TileContent = { kind: 'org' }

function Foot({ factors }: { factors: StepUpProps['factors'] }): JSX.Element {
  const both = factors.passkey && factors.email
  const email = (
    <Button variant={both ? 'secondary' : 'primary'} block grow={!both} name="factor" value="email" icon="mail" busyLabel="Sending…">
      Email me a code
    </Button>
  )
  const passkey = (
    <Button variant="primary" block grow={!both} name="factor" value="passkey" icon="key" busyLabel="Checking…" on="passkey">
      Use passkey
    </Button>
  )
  if (both) {
    return (
      <Actions>
        {email}
        {passkey}
      </Actions>
    )
  }
  return factors.passkey ? passkey : email
}

export function StepUp(p: StepUpProps): JSX.Element {
  return (
    <Page narrow>
      <form class="id-form" method="post" action={p.action} data-js="submit">
        <input type="hidden" name="csrf" value={p.csrf} />
        <Card
          foot={
            <CardFoot>
              <Foot factors={p.factors} />
            </CardFoot>
          }
        >
          <CardHead connector={<Connector left={ORG} right={p.app.tile} />} title="Confirm it’s you" description={STEP_UP_REASONS[p.reason](p.app.name)} />
          <Dotted />
          <Who name={p.account.name} sub={p.account.email} avatar={p.account.avatar} right={<WhoMeta>{`Confirmed ${p.lastConfirmedAgo}`}</WhoMeta>} />
          <span class="id-sr" role="status" data-status></span>
        </Card>
      </form>
    </Page>
  )
}
