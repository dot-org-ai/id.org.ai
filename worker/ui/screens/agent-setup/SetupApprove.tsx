/**
 * 9a · Approve an agent that a product's setup sent, and 17a · one approval
 * and one limit across several APIs (docs/agent-setup/HANDOFF.md).
 *
 * 5a with what the product asked for: the signed-in account with Switch, the
 * workspace the approval and the bill are for, what the agent would like to
 * do, one agent limit and an expiry, and the card it would pay with. Approving
 * lands on the setup page at once (9b), with no redirect in between.
 */
import type { JSX } from 'hono/jsx/jsx-runtime'
import { rich, type Rich } from '../../agent-setup/rich'
import { AGENT_ROUTES } from '../../agent-setup/routes'
import {
  Card,
  CardFoot,
  CardHead,
  Connector,
  Dotted,
  Field,
  Link,
  Page,
  PayLine,
  PermissionList,
  Select,
  SourceRow,
  Who,
  type KV,
  type PermissionItem,
  type SelectOption,
  type TileContent,
} from '../../components'
import { shortFingerprint } from '../AgentApprove'
import { Foot, type FootProps } from './blocks'

export interface SetupApproveProps {
  agent: { name: string; tile: TileContent; keyType: string; fingerprint: string }
  /** The identity row's details: host, when it asked, who sent it. */
  source: KV[]
  title: string
  description: Rich
  account: { name: string; email: string }
  workspaces: SelectOption[]
  selectedWorkspace: string
  permissions: PermissionItem[]
  /** The limit's label when it covers more than one API (17a: "Spend limit, all three"). */
  spendLabel?: string
  spendLimits: SelectOption[]
  selectedSpend: string
  expiries: SelectOption[]
  selectedExpiry: string
  /** "Visa ending 4417". None: the line offers to add one. */
  payMethod?: string
  /** 17a is drawn without the pays-with line (revision 2 added it to 9a only). */
  payLine?: boolean
  foot: FootProps
  /** `/agent?code=…` */
  action: string
  csrf: string
  copied?: boolean
}

export function SetupApprove(p: SetupApproveProps): JSX.Element {
  return (
    <Page>
      <form class="id-form" method="post" action={p.action}>
        <input type="hidden" name="csrf" value={p.csrf} />
        <Card
          foot={
            <CardFoot>
              <Foot {...p.foot} />
            </CardFoot>
          }
        >
          <CardHead connector={<Connector left={{ kind: 'org' }} right={p.agent.tile} state="idle" />} title={p.title} description={rich(p.description)} />
          <Dotted />
          <Who name={p.account.name} sub={p.account.email} right={<Link href={AGENT_ROUTES.switchAccount}>Switch</Link>} />
          <Field id="setup-workspace" label="Workspace">
            <Select id="setup-workspace" name="workspace" options={p.workspaces} selected={p.selectedWorkspace} />
          </Field>
          <PermissionList heading={`${p.agent.name} would like to`} items={p.permissions} />
          <div class="id-agent-limits">
            <Field id="setup-spend" label={p.spendLabel ?? 'Spend limit'}>
              <Select id="setup-spend" name="spend_limit" options={p.spendLimits} selected={p.selectedSpend} />
            </Field>
            <Field id="setup-expiry" label="Expires">
              <Select id="setup-expiry" name="expires" options={p.expiries} selected={p.selectedExpiry} />
            </Field>
          </div>
          {p.payLine === false ? null : <PayLine method={p.payMethod} href={AGENT_ROUTES.paymentMethods} addHref={AGENT_ROUTES.paymentMethodNew} />}
          <Dotted />
          <SourceRow icon="key" mono display={`${p.agent.keyType} · ${shortFingerprint(p.agent.fingerprint)}`} copyValue={p.agent.fingerprint} copied={p.copied} details={p.source} />
        </Card>
      </form>
    </Page>
  )
}
