/**
 * 5a · Approve an agent (docs/product-update/spec/screens.md#5a).
 *
 * A delegated agent registered and is pending. The person approves it once,
 * with a trust level, spend limit and expiry, or rejects it. The POST renders
 * the result in place (`approved` / `rejected`), still: the motion happened on
 * the click (submit.js), so the page reached afterwards shows the verdict.
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
  Field,
  FootText,
  KeyValues,
  Link,
  Page,
  RadioCard,
  RadioGroup,
  Select,
  SourceRow,
  Well,
  type ConnectorState,
  type SelectOption,
  type TileContent,
} from '../components'

export type AgentApproveState = 'pending' | 'approved' | 'rejected'

export interface TrustLevel {
  value: string
  title: string
  description: string
  /** The accent dot for the elevated choice (Privileged). */
  accent?: boolean
}

export interface AgentApproveProps {
  state?: AgentApproveState
  agent: {
    name: string
    /** The agent's own tile (the bot icon for a coding agent). */
    tile: TileContent
    /** "bryant-mbp" */
    host: string
    /** "macOS" */
    os: string
    /** "2 min ago" */
    askedAgo: string
    /** "ed25519" */
    keyType: string
    /** The full public-key fingerprint (copied); shown shortened, "7f3a…c21d". */
    fingerprint: string
  }
  workspace: string
  trustLevels: TrustLevel[]
  selectedTrust: string
  spendLimits: SelectOption[]
  selectedSpend: string
  expiries: SelectOption[]
  selectedExpiry: string
  /** Where "Pause or remove it" goes once approved (the account's agents list). */
  manageHref: string
  /** `/agents/approve/:agentId` */
  action: string
  csrf: string
  /** Gallery only: the fingerprint's copy button in its copied state. */
  copied?: boolean
}

const ORG: TileContent = { kind: 'org' }

/** "7f3a9e…c21d" → "7f3a…c21d": first and last four of the fingerprint. */
export function shortFingerprint(fp: string): string {
  return fp.length > 9 ? `${fp.slice(0, 4)}…${fp.slice(-4)}` : fp
}

function Head({ p, connector, title, description }: { p: AgentApproveProps; connector: ConnectorState; title: string; description: string }): JSX.Element {
  return <CardHead connector={<Connector left={ORG} right={p.agent.tile} state={connector} />} title={title} description={description} />
}

function label(options: SelectOption[], value: string): string {
  return options.find((o) => o.value === value)?.label ?? ''
}

function PendingBody({ p }: { p: AgentApproveProps }): JSX.Element {
  return (
    <>
      <Head p={p} connector="idle" title={`${p.agent.name} wants to work as your agent`} description="It gets its own identity, linked to you. Pause or remove it anytime." />
      <Dotted />
      <SourceRow
        icon="key"
        mono
        display={`${p.agent.keyType} · ${shortFingerprint(p.agent.fingerprint)}`}
        copyValue={p.agent.fingerprint}
        copied={p.copied}
        details={[
          { k: 'Host', v: `${p.agent.host} (${p.agent.os})` },
          { k: 'Asked', v: p.agent.askedAgo },
          { k: 'Workspace', v: p.workspace },
        ]}
      />
      <RadioGroup legend="Trust level" layout="stack">
        {p.trustLevels.map((t) => (
          <RadioCard
            id={`agent-trust-${t.value}`}
            name="trust_level"
            value={t.value}
            checked={t.value === p.selectedTrust}
            title={t.title}
            description={t.description}
            accent={t.accent}
          />
        ))}
      </RadioGroup>
      <div class="id-agent-limits">
        <Field id="agent-spend" label="Spend limit">
          <Select id="agent-spend" name="spend_limit" options={p.spendLimits} selected={p.selectedSpend} />
        </Field>
        <Field id="agent-expiry" label="Expires">
          <Select id="agent-expiry" name="expires" options={p.expiries} selected={p.selectedExpiry} />
        </Field>
      </div>
    </>
  )
}

function ApprovedBody({ p }: { p: AgentApproveProps }): JSX.Element {
  const trust = p.trustLevels.find((t) => t.value === p.selectedTrust)?.title ?? ''
  return (
    <>
      <Head p={p} connector="ok" title={`${p.agent.name} is now your agent`} description="It can start working now. You can close this tab." />
      <Well>
        <KeyValues
          items={[
            { k: 'Trust level', v: trust },
            { k: 'Spend limit', v: label(p.spendLimits, p.selectedSpend) },
            { k: 'Expires', v: label(p.expiries, p.selectedExpiry) },
            { k: 'Workspace', v: p.workspace },
          ]}
        />
      </Well>
    </>
  )
}

function RejectedBody({ p }: { p: AgentApproveProps }): JSX.Element {
  return <Head p={p} connector="fail" title={`${p.agent.name} wasn’t approved`} description={`Its key won’t work, and it can’t see anything in ${p.workspace}.`} />
}

export function AgentApprove(p: AgentApproveProps): JSX.Element {
  const state = p.state ?? 'pending'
  if (state === 'pending') {
    return (
      <Page>
        <form class="id-form" method="post" action={p.action} data-js="submit">
          <input type="hidden" name="csrf" value={p.csrf} />
          <Card
            foot={
              <CardFoot>
                <Actions>
                  <Button variant="secondary" block name="decision" value="reject">
                    Reject
                  </Button>
                  <Button variant="primary" block name="decision" value="approve" busyLabel="Approving…">
                    Approve agent
                  </Button>
                </Actions>
              </CardFoot>
            }
          >
            <PendingBody p={p} />
            <span class="id-sr" role="status" data-status></span>
          </Card>
        </form>
      </Page>
    )
  }
  const approved = state === 'approved'
  return (
    <Page>
      <Card
        foot={
          <CardFoot>
            {approved ? (
              <FootText>
                Changed your mind? <Link href={p.manageHref}>Pause or remove it</Link>
              </FootText>
            ) : (
              <FootText>{`Rejected by mistake? Ask ${p.agent.name} to connect again.`}</FootText>
            )}
          </CardFoot>
        }
      >
        {approved ? <ApprovedBody p={p} /> : <RejectedBody p={p} />}
        <span class="id-sr" role="status" data-status>
          {approved ? `${p.agent.name} approved.` : `${p.agent.name} rejected.`}
        </span>
      </Card>
    </Page>
  )
}
