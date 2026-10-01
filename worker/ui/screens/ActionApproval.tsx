/**
 * 5b · Approve an action (docs/product-update/spec/screens.md#5b). Built for a
 * phone: the link arrives by push, email or the CLI.
 *
 * A Trusted agent asks before it sends, deletes or spends. The header counts
 * down from the server's `secondsLeft`; unanswered requests expire as a no. At 0 the card
 * swaps to the expired template (the 7b shape: "This request expired"), which
 * is also what the server renders once the request has expired (`expired`).
 * The connector runs agent → id.org.ai: the agent is the requester.
 */
import type { JSX } from 'hono/jsx/jsx-runtime'
import {
  Actions,
  Button,
  Card,
  CardFoot,
  CardHead,
  Checkbox,
  Connector,
  Countdown,
  Excerpt,
  FootText,
  KeyValues,
  Link,
  Page,
  Well,
  type ConnectorState,
  type TileContent,
} from '../components'
import type { IconName } from '../icons'

export type ActionApprovalState = 'pending' | 'expired'

/** A typed preview of what the agent wants to do. Email is the first kind. */
export interface EmailAction {
  kind: 'email'
  /** "412 customers in Q3 renewals" */
  to: string
  from: string
  subject: string
  /** The body excerpt (plain text). */
  excerpt: string
  /** "View full email" */
  viewHref: string
}

export type ActionPreview = EmailAction

export interface ActionApprovalProps {
  state?: ActionApprovalState
  agent: {
    name: string
    /** "Support agent" */
    role: string
    /** "headless.ly" */
    app: string
    /** "Drivly" */
    workspace: string
    tile: TileContent
  }
  action: ActionPreview
  /** Seconds left at render time ("4:32 left"); the header counts down from it. */
  secondsLeft: number
  /** "Always allow Susan to send renewal emails": the checkbox creates a standing rule. */
  alwaysAllowLabel: string
  /** `/approvals/:requestId` */
  formAction: string
  csrf: string
}

const ORG: TileContent = { kind: 'org' }

/** Per-kind copy: the title verb, the primary button and what an expiry means. */
const KIND: Record<ActionPreview['kind'], { wants: string; approve: string; busy: string; icon: IconName; expired: string }> = {
  email: {
    wants: 'send an email',
    approve: 'Approve and send',
    busy: 'Sending…',
    icon: 'send',
    expired: 'Unanswered requests expire as a no, so nothing was sent.',
  },
}

function Head({ p, connector, title, description }: { p: ActionApprovalProps; connector: ConnectorState; title: string; description: string }): JSX.Element {
  return <CardHead connector={<Connector left={p.agent.tile} right={ORG} state={connector} />} title={title} description={description} />
}

function Preview({ action }: { action: ActionPreview }): JSX.Element {
  return (
    <Well variant="tight">
      <KeyValues
        items={[
          { k: 'To', v: action.to },
          { k: 'From', v: action.from },
          { k: 'Subject', v: action.subject },
        ]}
      />
      <Excerpt>{action.excerpt}</Excerpt>
      <Link href={action.viewHref}>View full email</Link>
    </Well>
  )
}

/** The expired card (7b template): swapped in by countdown.ts at 0, or rendered by the server. */
function ExpiredCard({ p }: { p: ActionApprovalProps }): JSX.Element {
  return (
    <Card
      foot={
        <CardFoot>
          <FootText>{`${p.agent.name} can ask again from ${p.agent.app}.`}</FootText>
        </CardFoot>
      }
    >
      <Head p={p} connector="fail" title="This request expired" description={KIND[p.action.kind].expired} />
    </Card>
  )
}

export function ActionApproval(p: ActionApprovalProps): JSX.Element {
  const kind = KIND[p.action.kind]
  if (p.state === 'expired') {
    return (
      <Page>
        <ExpiredCard p={p} />
      </Page>
    )
  }
  return (
    <Page headerRight={<Countdown secondsLeft={p.secondsLeft} urgent expiredTemplate="expired" />}>
      <form class="id-form" method="post" action={p.formAction} data-js="submit">
        <input type="hidden" name="csrf" value={p.csrf} />
        <Card
          foot={
            <CardFoot>
              <Actions>
                <Button variant="secondary" block name="decision" value="deny">
                  Deny
                </Button>
                <Button variant="primary" block name="decision" value="approve" icon={kind.icon} busyLabel={kind.busy}>
                  {kind.approve}
                </Button>
              </Actions>
            </CardFoot>
          }
        >
          <Head p={p} connector="idle" title={`${p.agent.name} wants to ${kind.wants}`} description={`${p.agent.role} · ${p.agent.app} · ${p.agent.workspace}`} />
          <Preview action={p.action} />
          <Checkbox id="always-allow" name="always_allow">
            {p.alwaysAllowLabel}
          </Checkbox>
        </Card>
      </form>
      {/* Outside the card, so countdown.ts's "This request expired." survives the swap. */}
      <span class="id-sr" role="status" data-status></span>
      <template data-state="expired">
        <ExpiredCard p={p} />
      </template>
    </Page>
  )
}
