/**
 * 5b · Approve an action (docs/product-update/spec/screens.md#5b). Built for a
 * phone: the link arrives by push, email or the CLI.
 *
 * A Trusted agent asks before it sends, deletes or spends. The page stays on
 * id.org.ai (spec/motion.md#where-the-person-goes-next): the live page renders
 * the `pending` form, and the sent and denied bodies and feet ride along in
 * <template data-state> elements that fetch-form.ts swaps in. Without JS the
 * form posts and the server renders `sent` or `denied` directly.
 *
 * The header counts down from the server's `secondsLeft`; unanswered requests
 * expire as a no. At 0, countdown.ts swaps the card for the `expired`
 * template: the 7b error card ("This request expired"), which is also what
 * the server renders once the request has expired (`expired`). That template
 * sits inside the body region, so once a decision swaps in it is gone and the
 * countdown can no longer replace the verdict.
 *
 * The connector runs agent → id.org.ai: the agent is the requester.
 */
import type { Child } from 'hono/jsx'
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
  Em,
  Excerpt,
  FootText,
  KeyValues,
  Link,
  Page,
  Stack,
  Well,
  type ConnectorState,
  type TileContent,
} from '../components'
import { errorPageProps } from '../errors'
import type { IconName } from '../icons'
import { ErrorCard } from './ErrorPage'

export type ActionApprovalState = 'pending' | 'sent' | 'denied' | 'expired'

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
  /** X-Request-Id, for the expired error card. */
  requestId: string
}

const ORG: TileContent = { kind: 'org' }

/** Per-kind copy: the title verb, the primary button and the verdicts. */
const KIND: Record<ActionPreview['kind'], { wants: string; approve: string; busy: string; icon: IconName; sent: string }> = {
  email: {
    wants: 'send an email',
    approve: 'Approve and send',
    busy: 'Sending…',
    icon: 'send',
    sent: 'sent the email to',
  },
}

function Head({ p, connector, title, description }: { p: ActionApprovalProps; connector: ConnectorState; title: string; description: Child }): JSX.Element {
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

/** The 7b error card with the approval copy and the agent's tile: swapped in by countdown.ts at 0, or rendered by the server. */
function ExpiredCard({ p }: { p: ActionApprovalProps }): JSX.Element {
  return <ErrorCard {...errorPageProps('expired', { requestId: p.requestId, expired: { what: 'approval' }, startHref: '/' })} tile={p.agent.tile} />
}

function PendingBody({ p }: { p: ActionApprovalProps }): JSX.Element {
  return (
    <Stack gap={22}>
      <Head p={p} connector="idle" title={`${p.agent.name} wants to ${KIND[p.action.kind].wants}`} description={`${p.agent.role} · ${p.agent.app} · ${p.agent.workspace}`} />
      <Preview action={p.action} />
      <Checkbox id="always-allow" name="always_allow">
        {p.alwaysAllowLabel}
      </Checkbox>
    </Stack>
  )
}

function PendingFoot({ p }: { p: ActionApprovalProps }): JSX.Element {
  const kind = KIND[p.action.kind]
  return (
    <Actions>
      <Button variant="secondary" block name="decision" value="deny" deny done="denied">
        Deny
      </Button>
      <Button variant="primary" block name="decision" value="approve" icon={kind.icon} busyLabel={kind.busy} done="sent">
        {kind.approve}
      </Button>
    </Actions>
  )
}

function SentBody({ p }: { p: ActionApprovalProps }): JSX.Element {
  return (
    <Stack gap={22}>
      <Head
        p={p}
        connector="ok"
        title="Sent"
        description={
          <>
            <Em>{p.agent.name}</Em> {KIND[p.action.kind].sent} {p.action.to}.
          </>
        }
      />
    </Stack>
  )
}

function SentFoot(): JSX.Element {
  return (
    <div class="id-fade">
      <FootText>You can close this tab.</FootText>
    </div>
  )
}

function DeniedBody({ p }: { p: ActionApprovalProps }): JSX.Element {
  return (
    <Stack gap={22}>
      <Head
        p={p}
        connector="fail"
        title="Not sent"
        description={
          <>
            <Em>{p.agent.name}</Em> won’t send it. Nothing left <Em>{p.agent.app}</Em>.
          </>
        }
      />
    </Stack>
  )
}

function DeniedFoot({ p }: { p: ActionApprovalProps }): JSX.Element {
  return (
    <div class="id-fade">
      <FootText>{`Denied by mistake? ${p.agent.name} can ask again from ${p.agent.app}.`}</FootText>
    </div>
  )
}

export function ActionApproval(p: ActionApprovalProps): JSX.Element {
  const state = p.state ?? 'pending'
  if (state === 'expired') {
    return (
      <Page>
        <ExpiredCard p={p} />
      </Page>
    )
  }
  const live = state === 'pending'
  let body: JSX.Element
  let foot: JSX.Element
  let verdict = ''
  switch (state) {
    case 'sent':
      body = <SentBody p={p} />
      foot = <SentFoot />
      verdict = 'Sent.'
      break
    case 'denied':
      body = <DeniedBody p={p} />
      foot = <DeniedFoot p={p} />
      verdict = 'Not sent.'
      break
    default:
      body = <PendingBody p={p} />
      foot = <PendingFoot p={p} />
  }
  return (
    <Page headerRight={live ? <Countdown secondsLeft={p.secondsLeft} urgent expiredTemplate="expired" /> : undefined}>
      <form class="id-form" method="post" action={p.formAction} data-js="fetch-form">
        <input type="hidden" name="csrf" value={p.csrf} />
        <Card
          foot={
            <CardFoot>
              <div data-region="foot">{foot}</div>
              {live ? (
                <>
                  <template data-state="sent">
                    <SentFoot />
                  </template>
                  <template data-state="denied">
                    <DeniedFoot p={p} />
                  </template>
                </>
              ) : null}
            </CardFoot>
          }
        >
          <div data-region="body">
            {body}
            {live ? (
              <template data-state="expired">
                <ExpiredCard p={p} />
              </template>
            ) : null}
          </div>
          {live ? (
            <>
              <template data-state="sent">
                <SentBody p={p} />
              </template>
              <template data-state="denied">
                <DeniedBody p={p} />
              </template>
            </>
          ) : null}
        </Card>
        {/* Inside the form (fetch-form.ts) but outside the card, so countdown.ts's "This request expired." survives the swap. */}
        <span class="id-sr" role="status" data-status>
          {verdict}
        </span>
      </form>
    </Page>
  )
}
