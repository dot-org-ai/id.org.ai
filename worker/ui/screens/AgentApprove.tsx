/**
 * 5a · Approve an agent (docs/product-update/spec/screens.md#5a).
 *
 * A delegated agent registered and is pending. The person approves it once,
 * with a trust level, spend limit and expiry, or rejects it. The page stays on
 * id.org.ai (spec/motion.md#where-the-person-goes-next): the live page renders
 * the `pending` form, and the approved and rejected bodies and feet ride along
 * in <template data-state> elements that fetch-form.ts swaps in. Without JS
 * the form posts and the server renders `approved` or `rejected` directly.
 *
 * The templates are rendered before the person picks, so they only name what
 * can't change (the agent, the workspace). The server-rendered `approved`
 * page also lists the policy that was stored.
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
  Field,
  FootText,
  KeyValues,
  Link,
  Page,
  RadioCard,
  RadioGroup,
  Select,
  SourceRow,
  Stack,
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
  /** The default choice; on the `approved` page, the stored one. */
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

function Head({ p, connector, title, description }: { p: AgentApproveProps; connector: ConnectorState; title: string; description: Child }): JSX.Element {
  return <CardHead connector={<Connector left={ORG} right={p.agent.tile} state={connector} />} title={title} description={description} />
}

function label(options: SelectOption[], value: string): string {
  return options.find((o) => o.value === value)?.label ?? ''
}

function PendingBody({ p }: { p: AgentApproveProps }): JSX.Element {
  return (
    <Stack gap={22}>
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
    </Stack>
  )
}

function PendingFoot(): JSX.Element {
  return (
    <Actions>
      <Button variant="secondary" block name="decision" value="reject" deny done="rejected">
        Reject
      </Button>
      <Button variant="primary" block name="decision" value="approve" busyLabel="Approving…" done="approved">
        Approve agent
      </Button>
    </Actions>
  )
}

/** `policy`: list the stored trust level, spend limit and expiry (the server-rendered page only). */
function ApprovedBody({ p, policy }: { p: AgentApproveProps; policy: boolean }): JSX.Element {
  const trust = p.trustLevels.find((t) => t.value === p.selectedTrust)?.title ?? ''
  return (
    <Stack gap={22}>
      <Head
        p={p}
        connector="ok"
        title={`${p.agent.name} is now your agent`}
        description={
          <>
            It can start working in <Em>{p.workspace}</Em> now. You can close this tab.
          </>
        }
      />
      {policy ? (
        <Stack gap={22} class="id-fade">
          <Well>
            <KeyValues
              items={[
                { k: 'Trust level', v: trust },
                { k: 'Spend limit', v: label(p.spendLimits, p.selectedSpend) },
                { k: 'Expires', v: label(p.expiries, p.selectedExpiry) },
              ]}
            />
          </Well>
        </Stack>
      ) : null}
    </Stack>
  )
}

function ApprovedFoot({ p }: { p: AgentApproveProps }): JSX.Element {
  return (
    <div class="id-fade">
      <FootText>
        Changed your mind? <Link href={p.manageHref}>Pause or remove it</Link>
      </FootText>
    </div>
  )
}

function RejectedBody({ p }: { p: AgentApproveProps }): JSX.Element {
  return (
    <Stack gap={22}>
      <Head
        p={p}
        connector="fail"
        title={`${p.agent.name} wasn’t approved`}
        description={
          <>
            Its key won’t work, and it can’t see anything in <Em>{p.workspace}</Em>.
          </>
        }
      />
    </Stack>
  )
}

function RejectedFoot({ p }: { p: AgentApproveProps }): JSX.Element {
  return (
    <div class="id-fade">
      <FootText>{`Rejected by mistake? Ask ${p.agent.name} to connect again.`}</FootText>
    </div>
  )
}

export function AgentApprove(p: AgentApproveProps): JSX.Element {
  const state = p.state ?? 'pending'
  const live = state === 'pending'
  let body: JSX.Element
  let foot: JSX.Element
  let verdict = ''
  switch (state) {
    case 'approved':
      body = <ApprovedBody p={p} policy />
      foot = <ApprovedFoot p={p} />
      verdict = `${p.agent.name} approved.`
      break
    case 'rejected':
      body = <RejectedBody p={p} />
      foot = <RejectedFoot p={p} />
      verdict = `${p.agent.name} rejected.`
      break
    default:
      body = <PendingBody p={p} />
      foot = <PendingFoot />
  }
  return (
    <Page>
      <form class="id-form" method="post" action={p.action} data-js="fetch-form">
        <input type="hidden" name="csrf" value={p.csrf} />
        <Card
          foot={
            <CardFoot>
              <div data-region="foot">{foot}</div>
              {live ? (
                <>
                  <template data-state="approved">
                    <ApprovedFoot p={p} />
                  </template>
                  <template data-state="rejected">
                    <RejectedFoot p={p} />
                  </template>
                </>
              ) : null}
            </CardFoot>
          }
        >
          <div data-region="body">{body}</div>
          {live ? (
            <>
              <template data-state="approved">
                <ApprovedBody p={p} policy={false} />
              </template>
              <template data-state="rejected">
                <RejectedBody p={p} />
              </template>
            </>
          ) : null}
          <span class="id-sr" role="status" data-status>
            {verdict}
          </span>
        </Card>
      </form>
    </Page>
  )
}
