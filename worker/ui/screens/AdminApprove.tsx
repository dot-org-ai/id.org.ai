/**
 * 3d · Admin approves an app (docs/product-update/spec/screens.md#3d).
 *
 * A workspace admin opens an access request (sent from 7c) and approves it for
 * everyone in the workspace or the requester only, or declines it. The form
 * posts to POST /admin/requests/:id (scope=everyone|requester,
 * decision=approve|decline); both notify the requester (B11). The person stays
 * on id.org.ai, so the server answers with the result in place: `approved`
 * (connector ok) or `declined` (connector fail). The connector runs app →
 * workspace (components.md#connector).
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
  FootText,
  KeyValues,
  PermissionList,
  QuoteWell,
  RadioCard,
  RadioGroup,
  SourceRow,
  Stack,
  Well,
  Who,
  Page,
  type ConnectorState,
  type PermissionItem,
  type SourceRowProps,
  type TileContent,
} from '../components'

export type AdminApproveState = 'pending' | 'approved' | 'declined'
export type ApprovalScope = 'everyone' | 'requester'

export interface AdminApproveProps {
  /** `pending` is the request; `approved` and `declined` are the results rendered in place. */
  state?: AdminApproveState
  requester: { name: string; firstName?: string }
  client: { name: string; tile: TileContent }
  workspace: { name: string; tile: TileContent }
  /** The requester's note, shown quoted. */
  note?: string
  permissions: PermissionItem[]
  /** Approve for everyone in the workspace, or the requester only (the default). */
  scope: ApprovalScope
  /** The signed-in admin (who row, no Switch). */
  admin: { name: string; email: string; avatar?: string }
  /** The source row: the CIMD URL (or client_id) and its details. */
  source: Omit<SourceRowProps, 'icon' | 'copied'>
  /** Gallery: the source row's copied state. */
  copied?: boolean
  /** Submitting: the connector connects and Approve shows "Approving…". */
  busy?: boolean
  /** POST /admin/requests/:id */
  action: string
  csrf: string
}

function firstName(r: AdminApproveProps['requester']): string {
  return r.firstName ?? r.name.trim().split(/\s+/)[0] ?? r.name
}

function scopeLabel(p: AdminApproveProps): string {
  return p.scope === 'everyone' ? `Everyone in ${p.workspace.name}` : `${firstName(p.requester)} only`
}

function Head({ p, state, title, description }: { p: AdminApproveProps; state: ConnectorState; title: string; description: JSX.Element }): JSX.Element {
  return <CardHead connector={<Connector left={p.client.tile} right={p.workspace.tile} state={state} />} title={title} description={description} />
}

function RequestBody({ p }: { p: AdminApproveProps }): JSX.Element {
  const ws = p.workspace.name
  return (
    <Stack gap={22}>
      <Head
        p={p}
        state={p.busy ? 'connecting' : 'idle'}
        title={`Approve ${p.client.name} for ${ws}?`}
        description={
          <>
            <Em>{p.requester.name}</Em>
            {` asked to use ${p.client.name} in the ${ws} workspace.`}
          </>
        }
      />
      <Dotted />
      <Who name={p.admin.name} sub={`${p.admin.email} · ${ws} admin`} email={p.admin.email} avatar={p.admin.avatar} />
      {p.note ? <QuoteWell>{`“${p.note}”`}</QuoteWell> : null}
      <PermissionList heading="It asked to" items={p.permissions} />
      <RadioGroup legend="Approve for" layout="stack">
        <RadioCard
          id="approve-everyone"
          name="scope"
          value="everyone"
          checked={p.scope === 'everyone'}
          title={`Everyone in ${ws}`}
          description={`Anyone can connect ${p.client.name} with these permissions.`}
        />
        <RadioCard id="approve-requester" name="scope" value="requester" checked={p.scope === 'requester'} title={`${firstName(p.requester)} only`} description="Others still need to ask." />
      </RadioGroup>
      <Dotted />
      <SourceRow icon="globe" {...p.source} copied={p.copied} />
    </Stack>
  )
}

function ApprovedBody({ p }: { p: AdminApproveProps }): JSX.Element {
  const ws = p.workspace.name
  return (
    <Stack gap={22}>
      <Head
        p={p}
        state="ok"
        title={`${p.client.name} is approved for ${ws}`}
        description={
          <>
            {'We let '}
            <Em>{p.requester.name}</Em>
            {p.scope === 'everyone' ? ` know. Anyone in ${ws} can connect it now.` : ' know they can connect it now.'}
          </>
        }
      />
      <Well>
        <KeyValues
          items={[
            { k: 'App', v: p.client.name },
            { k: 'Workspace', v: ws },
            { k: 'Approved for', v: scopeLabel(p) },
          ]}
        />
      </Well>
    </Stack>
  )
}

function DeclinedBody({ p }: { p: AdminApproveProps }): JSX.Element {
  return (
    <Stack gap={22}>
      <Head
        p={p}
        state="fail"
        title="Request declined"
        description={
          <>
            {'We let '}
            <Em>{p.requester.name}</Em>
            {` know. ${p.client.name} stays blocked in ${p.workspace.name}.`}
          </>
        }
      />
    </Stack>
  )
}

function RequestFoot({ p }: { p: AdminApproveProps }): JSX.Element {
  const busy = !!p.busy
  return (
    <CardFoot>
      <Actions>
        <Button variant="secondary" block name="decision" value="decline" disabled={busy} on="decline">
          Decline
        </Button>
        <Button variant="primary" block name="decision" value="approve" busy={busy} busyLabel="Approving…" on="approve">
          Approve
        </Button>
      </Actions>
    </CardFoot>
  )
}

function ResultFoot(): JSX.Element {
  return (
    <CardFoot>
      <FootText>You can close this tab.</FootText>
    </CardFoot>
  )
}

export function AdminApprove(p: AdminApproveProps): JSX.Element {
  const state = p.state ?? 'pending'
  if (state !== 'pending') {
    return (
      <Page>
        <Card foot={<ResultFoot />}>
          {state === 'approved' ? <ApprovedBody p={p} /> : <DeclinedBody p={p} />}
          <span class="id-sr" role="status" data-status>
            {state === 'approved' ? 'Approved' : 'Declined'}
          </span>
        </Card>
      </Page>
    )
  }
  return (
    <Page>
      <form class="id-form" method="post" action={p.action} data-js="submit">
        <input type="hidden" name="csrf" value={p.csrf} />
        <Card foot={<RequestFoot p={p} />}>
          <RequestBody p={p} />
          <span class="id-sr" role="status" data-status>
            {p.busy ? 'Approving…' : ''}
          </span>
        </Card>
      </form>
    </Page>
  )
}
