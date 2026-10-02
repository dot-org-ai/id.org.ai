/**
 * 3d · Admin approves an app (docs/product-update/spec/screens.md#3d).
 *
 * A workspace admin opens an access request (sent from 7c) and approves it for
 * everyone in the workspace or the requester only, or declines it. The form
 * posts to POST /admin/requests/:id (scope=everyone|requester,
 * decision=approve|decline); both notify the requester (B11). The connector
 * runs app → workspace (components.md#connector).
 *
 * The admin stays on id.org.ai (motion.md#where-the-person-goes-next), so the
 * form is a fetch-form: the live `pending` page carries the approved and
 * declined bodies and feet in <template data-state> elements, and
 * lib/fetch-form.ts swaps them in. Approve goes `done`, then `approved` 2150ms
 * after the server's OK; Decline is a deny: `broken` at once, then `declined`
 * once 1820ms have passed and the server agreed. Without JS the form posts and
 * the server renders the result directly through `state`.
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
  type KV,
  type PermissionItem,
  type SourceRowProps,
  type TileContent,
} from '../components'
import { clientTile, consentAppName, firstName, type ConsentClient } from './Consent'

export type AdminApproveState = 'pending' | 'approved' | 'declined'
export type ApprovalScope = 'everyone' | 'requester'

export interface AdminApproveProps {
  /** `pending` is the request; `approved` and `declined` are the results the server renders after a no-JS post. */
  state?: AdminApproveState
  requester: { name: string; firstName?: string }
  /**
   * The app, as consent takes it (screens.md#3a Data). Its name and tile are
   * derived like consent's: the host when unverified, never the name it claims.
   */
  client: Pick<ConsentClient, 'displayName' | 'host' | 'verified' | 'logoUrl' | 'monogram'>
  workspace: { name: string; tile: TileContent }
  /** The requester's note, shown quoted. */
  note?: string
  permissions: PermissionItem[]
  /** Approve for everyone in the workspace, or the requester only (the default). On `approved`, the scope that was approved. */
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

function scopeLabel(p: AdminApproveProps, scope: ApprovalScope): string {
  return scope === 'everyone' ? `Everyone in ${p.workspace.name}` : `${firstName(p.requester)} only`
}

function Head({ p, state, title, description }: { p: AdminApproveProps; state: ConnectorState; title: string; description: JSX.Element }): JSX.Element {
  return <CardHead connector={<Connector left={clientTile(p.client)} right={p.workspace.tile} state={state} />} title={title} description={description} />
}

function RequestBody({ p }: { p: AdminApproveProps }): JSX.Element {
  const ws = p.workspace.name
  return (
    <Stack gap={22}>
      <Head
        p={p}
        state={p.busy ? 'connecting' : 'idle'}
        title={`Approve ${consentAppName(p.client)} for ${ws}?`}
        description={
          <>
            <Em>{p.requester.name}</Em>
            {` asked to use ${consentAppName(p.client)} in the ${ws} workspace.`}
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
          description={`Anyone can connect ${consentAppName(p.client)} with these permissions.`}
        />
        <RadioCard id="approve-requester" name="scope" value="requester" checked={p.scope === 'requester'} title={`${firstName(p.requester)} only`} description="Others still need to ask." />
      </RadioGroup>
      <Dotted />
      <SourceRow icon="globe" {...p.source} copied={p.copied} />
    </Stack>
  )
}

/**
 * The approved result. The template is rendered before the admin picks a
 * scope, so without `scope` it says only what is true either way; the no-JS
 * result page knows the scope that was posted and says who it is for.
 */
function ApprovedBody({ p, scope }: { p: AdminApproveProps; scope?: ApprovalScope }): JSX.Element {
  const ws = p.workspace.name
  const rows: KV[] = [
    { k: 'App', v: consentAppName(p.client) },
    { k: 'Workspace', v: ws },
  ]
  if (scope) rows.push({ k: 'Approved for', v: scopeLabel(p, scope) })
  return (
    <Stack gap={22}>
      <Head
        p={p}
        state="ok"
        title={`${consentAppName(p.client)} is approved for ${ws}`}
        description={
          <>
            {'We let '}
            <Em>{p.requester.name}</Em>
            {scope === 'everyone' ? ` know. Anyone in ${ws} can connect it now.` : ' know they can connect it now.'}
          </>
        }
      />
      <Stack gap={22} class="id-fade">
        <Well>
          <KeyValues items={rows} />
        </Well>
      </Stack>
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
            {` know. ${consentAppName(p.client)} stays blocked in ${p.workspace.name}.`}
          </>
        }
      />
    </Stack>
  )
}

function RequestFoot({ p }: { p: AdminApproveProps }): JSX.Element {
  const busy = !!p.busy
  return (
    <Actions>
      <Button variant="secondary" block name="decision" value="decline" disabled={busy} on="decline" deny done="declined">
        Decline
      </Button>
      <Button variant="primary" block name="decision" value="approve" busy={busy} busyLabel="Approving…" on="approve" done="approved">
        Approve
      </Button>
    </Actions>
  )
}

function ResultFoot(): JSX.Element {
  return (
    <div class="id-fade">
      <FootText>You can close this tab.</FootText>
    </div>
  )
}

export function AdminApprove(p: AdminApproveProps): JSX.Element {
  const state = p.state ?? 'pending'
  if (state !== 'pending') {
    return (
      <Page>
        <Card
          foot={
            <CardFoot>
              <ResultFoot />
            </CardFoot>
          }
        >
          {state === 'approved' ? <ApprovedBody p={p} scope={p.scope} /> : <DeclinedBody p={p} />}
          <span class="id-sr" role="status" data-status>
            {state === 'approved' ? 'Approved' : 'Declined'}
          </span>
        </Card>
      </Page>
    )
  }
  return (
    <Page>
      <form class="id-form" method="post" action={p.action} data-js="fetch-form">
        <input type="hidden" name="csrf" value={p.csrf} />
        <Card
          foot={
            <CardFoot>
              <div data-region="foot">
                <RequestFoot p={p} />
              </div>
              <template data-state="approved">
                <ResultFoot />
              </template>
              <template data-state="declined">
                <ResultFoot />
              </template>
            </CardFoot>
          }
        >
          <div data-region="body">
            <RequestBody p={p} />
          </div>
          <template data-state="approved">
            <ApprovedBody p={p} />
          </template>
          <template data-state="declined">
            <DeclinedBody p={p} />
          </template>
          <span class="id-sr" role="status" data-status>
            {p.busy ? 'Approving…' : ''}
          </span>
        </Card>
      </form>
    </Page>
  )
}
