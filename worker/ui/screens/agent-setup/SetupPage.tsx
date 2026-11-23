/**
 * The setup page (docs/agent-setup/HANDOFF.md sections 3 and 4): one agent
 * setting up one API, or running one workflow, for one workspace.
 *
 * id.org.ai displays, the product decides. The page renders whatever ordered
 * steps the product posts (the Setup contract in agent-setup/types.ts) and
 * derives the connector and the header status from the setup's state. Nothing
 * here marks a step done: a step ticks only when the product reports it.
 * The same page runs migrations, multi-API jobs and headless SaaS setup.
 */
import type { JSX } from 'hono/jsx/jsx-runtime'
import { clock } from '../../agent-setup/format'
import { rich, type Rich } from '../../agent-setup/rich'
import { AGENT_ROUTES } from '../../agent-setup/routes'
import { productTile } from '../../agent-setup/tiles'
import type { Evidence, Setup, SetupState, SetupStep } from '../../agent-setup/types'
import {
  CallResult,
  Card,
  CardFoot,
  CardHead,
  CompareWell,
  Connector,
  Dotted,
  Field,
  FieldMapRow,
  HeaderStatus,
  KeyValue,
  Link,
  Listening,
  Page,
  PayLine,
  PromptWell,
  RadioCard,
  Select,
  Spend,
  StepItem,
  StepList,
  Well,
  type ConnectorState,
  type SpendProps,
  type TileContent,
} from '../../components'
import { Blocks, Foot, footPosts, type Block, type FootProps } from './blocks'

export interface SetupPageProps {
  setup: Setup
  agent: { name: string; tile: TileContent }
  title: string
  description: Rich
  /** Seconds since the product's last event (the header's "Updated 4s ago"). */
  sinceSeconds?: number
  /** Blocks between the head and the steps (a live setup's summary well). */
  top?: Block[]
  /** The workspace's payment method, for the pays-with line under a spend or plan step. None: offer to add one. */
  payMethod?: string
  /** The per-API spend block for a plan step (19b): what the product offers. */
  spend?: SpendProps
  foot: FootProps
  /** Account-level states drawn on this page (19f renewal failed): the connector to show. */
  connector?: ConnectorState
  /** The right tile when it isn't the product's letters (the layers icon for a job across several APIs). */
  rightTile?: TileContent
  /** The person's time zone, for step times. */
  timeZone?: string
  action?: string
  csrf?: string
  /** Gallery only: a prompt's copy button in its copied state. */
  copied?: boolean
}

/** HANDOFF.md section 4: the connector for each setup state. X only for things that have ended or are refused. */
export const SETUP_CONNECTOR: Record<SetupState, ConnectorState> = {
  awaiting_approval: 'idle',
  rejected: 'fail',
  running: 'connecting',
  needs_spend_approval: 'hold',
  needs_plan_approval: 'hold',
  needs_person: 'hold',
  needs_payment_method: 'hold',
  needs_bank_confirmation: 'hold',
  needs_wallet_approval: 'hold',
  payment_declined: 'fail',
  call_failing: 'hold',
  stalled: 'hold',
  paused: 'idle',
  in_review: 'idle',
  cancelled: 'fail',
  live: 'ok',
  live_with_warning: 'ok',
}

/** HANDOFF.md section 4: the header status for each setup state, or none. */
export function setupStatus(state: SetupState): { tone: 'ok' | 'warn'; verb: string } | null {
  switch (state) {
    case 'running':
      return { tone: 'ok', verb: 'Updated' }
    case 'stalled':
      return { tone: 'warn', verb: 'Last seen' }
    case 'needs_spend_approval':
    case 'needs_plan_approval':
    case 'needs_person':
    case 'needs_payment_method':
    case 'needs_bank_confirmation':
    case 'needs_wallet_approval':
    case 'payment_declined':
    case 'call_failing':
      return { tone: 'warn', verb: 'Updated' }
    default:
      return null
  }
}

/** The right-hand label: the product's own, a time when done, or the state's default. None when todo. */
export function stepWhen(step: SetupStep, timeZone?: string): string | undefined {
  if (step.label) return step.label
  switch (step.state) {
    case 'done':
      return step.at ? clock(step.at, timeZone) : undefined
    case 'now':
      return 'Now'
    case 'you':
      return 'Waiting on you'
    case 'fail':
      return 'Declined'
    case 'held':
      return 'Paused'
    default:
      return undefined
  }
}

function EvidenceView({ step, p }: { step: SetupStep; p: SetupPageProps }): JSX.Element | null {
  const ev = step.evidence as Evidence
  const payLine = <PayLine method={p.payMethod} href={AGENT_ROUTES.paymentMethods} addHref={AGENT_ROUTES.paymentMethodNew} />
  switch (ev.type) {
    case 'listening':
      return <Listening text={ev.text ?? `Listening on test key …${ev.key_last4 ?? ''}`} elapsed={ev.elapsed} note={ev.note} />
    case 'call':
      return (
        <CallResult
          method={ev.method}
          path={ev.path}
          status={ev.status}
          result={ev.code ?? (ev.ms !== undefined ? `${ev.ms} ms` : undefined)}
          rows={ev.rows}
          link={ev.more_url ? { href: ev.more_url, label: ev.more_label ?? 'View full response' } : undefined}
        />
      )
    case 'prompt':
      return <PromptWell label={ev.label} text={ev.text} copied={p.copied} />
    case 'rows':
      return (
        <Well>
          {ev.rows.map(([k, v]) => (
            <KeyValue k={k} v={v} />
          ))}
        </Well>
      )
    case 'compare':
      return <CompareWell rows={ev.rows.map((r) => ({ name: r.name, state: r.state, text: r.state === 'ok' ? `${r.matched} of ${r.of} match` : `${r.matched} of ${r.of} so far` }))} note={ev.note} />
    case 'choice':
      return (
        <>
          <Well>
            {ev.items.map(([k, v]) => (
              <KeyValue k={k} v={v} mono />
            ))}
          </Well>
          <fieldset class="id-fieldset">
            <legend class="id-sr">{step.title}</legend>
            {ev.options.map((o) => (
              <RadioCard id={`${step.id}-${o.id}`} name={`answer_${step.id}`} value={o.id} checked={o.id === ev.value} title={o.title} description={o.detail} />
            ))}
          </fieldset>
        </>
      )
    case 'field_map':
      return (
        <Well variant="ten">
          {ev.rows.map((r, i) => (
            <FieldMapRow id={`${step.id}-map-${i}`} name={`answer_${step.id}_${r.column}`} column={r.column} options={r.options} value={r.value} />
          ))}
        </Well>
      )
    case 'field':
      return (
        <>
          <Field id={`${step.id}-field`} label={ev.label}>
            <Select id={`${step.id}-field`} name={`answer_${step.id}`} options={ev.options} selected={ev.value} />
          </Field>
          {payLine}
        </>
      )
    case 'plan':
      return (
        <>
          <Well>
            <KeyValue k={ev.plan} v={ev.price} />
            <div class="id-rates">
              {ev.rates.map(([k, v]) => (
                <KeyValue k={k} v={v} />
              ))}
            </div>
            {ev.more_url ? <Link href={ev.more_url}>{ev.more_label ?? 'All data fees'}</Link> : null}
          </Well>
          {p.spend ? <Spend {...p.spend} /> : null}
          {payLine}
        </>
      )
  }
}

export function SetupPage(p: SetupPageProps): JSX.Element {
  const { setup } = p
  const status = setupStatus(setup.state)
  const product: TileContent = p.rightTile ?? productTile(setup.product)
  const card = (
    <Card
      foot={
        <CardFoot>
          <Foot {...p.foot} />
        </CardFoot>
      }
    >
      <CardHead connector={<Connector left={p.agent.tile} right={product} state={p.connector ?? SETUP_CONNECTOR[setup.state]} />} title={p.title} description={rich(p.description)} />
      {p.top ? <Blocks blocks={p.top} /> : null}
      {setup.steps.length ? (
        <>
          <Dotted />
          <StepList label={`${setup.product.name} setup steps`}>
            {setup.steps.map((s) => (
              <StepItem state={s.state} title={s.title} detail={s.detail} tag={s.tag} when={stepWhen(s, p.timeZone)}>
                {s.evidence ? <EvidenceView step={s} p={p} /> : undefined}
              </StepItem>
            ))}
          </StepList>
        </>
      ) : null}
    </Card>
  )
  return (
    <Page headerRight={status && p.sinceSeconds !== undefined ? <HeaderStatus tone={status.tone} verb={status.verb} seconds={p.sinceSeconds} /> : undefined}>
      {footPosts(p.foot) ? (
        <form class="id-form" method="post" action={p.action ?? AGENT_ROUTES.setup(setup.setup_id)}>
          <input type="hidden" name="csrf" value={p.csrf ?? ''} />
          {card}
        </form>
      ) : (
        card
      )}
    </Page>
  )
}
