/**
 * 4b · Confirm device code (docs/product-update/spec/screens.md#4b).
 *
 * The live page renders the `idle` form; the signed and cancelled bodies and
 * feet ride along in <template data-state> elements, and device-confirm.ts
 * swaps them in on the state machine in spec/motion.md. The gallery renders
 * each state directly through `state`.
 */
import type { JSX } from 'hono/jsx/jsx-runtime'
import {
  Actions,
  Button,
  Card,
  CardFoot,
  CardHead,
  Connector,
  DeviceCodeWell,
  Field,
  FootNote,
  FootText,
  KeyValues,
  Link,
  Page,
  PermissionList,
  Select,
  Stack,
  Well,
  Who,
  type ConnectorState,
  type PermissionItem,
  type SelectOption,
  type TileContent,
} from '../components'

export type DeviceConfirmState = 'idle' | 'connecting' | 'verdict' | 'signed' | 'cancelling' | 'cancelled'

export interface DeviceConfirmProps {
  state?: DeviceConfirmState
  /** Shown as XXXX-XXXX. */
  code: string
  client: { name: string; tile: TileContent }
  /** The CLI command people run again after a cancel ("auto.dev"). */
  cliName: string
  /** "macOS · Miami, FL · requested 1 min ago" */
  deviceMeta: string
  /** "macOS · Miami, FL" (the signed well's Device row) */
  device: string
  account: { name: string; email: string; avatar?: string }
  switchHref: string
  workspaces: SelectOption[]
  selectedWorkspace: string
  permissions: PermissionItem[]
  /** Where "Sign this device out" goes. */
  revokeHref: string
  action: string
  csrf: string
}

const ORG: TileContent = { kind: 'org' }

function Head({ p, connector, title, description }: { p: DeviceConfirmProps; connector: ConnectorState; title: string; description: string }): JSX.Element {
  return <CardHead connector={<Connector left={ORG} right={p.client.tile} state={connector} />} title={title} description={description} />
}

function FormBody({ p, connector }: { p: DeviceConfirmProps; connector: ConnectorState }): JSX.Element {
  return (
    <Stack gap={22}>
      <Head p={p} connector={connector} title={`Confirm sign-in on ${p.client.name}`} description="Check that this code matches the one in your terminal." />
      <DeviceCodeWell code={p.code} meta={p.deviceMeta} />
      <Who name={p.account.name} sub={p.account.email} avatar={p.account.avatar} right={<Link href={p.switchHref}>Switch</Link>} />
      <Field id="device-workspace" label="Workspace">
        <Select id="device-workspace" name="org_id" options={p.workspaces} selected={p.selectedWorkspace} />
      </Field>
      <PermissionList heading={`${p.client.name} would like to`} items={p.permissions} />
    </Stack>
  )
}

function SignedBody({ p }: { p: DeviceConfirmProps }): JSX.Element {
  const ws = p.workspaces.find((w) => w.value === p.selectedWorkspace)?.label ?? ''
  return (
    <Stack gap={22}>
      <Head p={p} connector="ok" title={`${p.client.name} is signed in`} description="Go back to your terminal. You can close this tab." />
      <Stack gap={22} class="id-fade">
        <Well>
          <KeyValues
            items={[
              { k: 'Account', v: p.account.email },
              { k: 'Workspace', v: ws },
              { k: 'Device', v: p.device },
            ]}
          />
        </Well>
      </Stack>
    </Stack>
  )
}

function CancelledBody({ p }: { p: DeviceConfirmProps }): JSX.Element {
  return (
    <Stack gap={22}>
      <Head
        p={p}
        connector="fail"
        title="Sign-in cancelled"
        description={`Your terminal will show the request was denied. Nothing was shared with ${p.client.name}.`}
      />
    </Stack>
  )
}

type FootMode = 'ready' | 'busy' | 'stopped'

function FormFoot({ mode }: { mode: FootMode }): JSX.Element {
  return (
    <Stack gap={14}>
      <Actions>
        <Button variant="secondary" block name="decision" value="deny" disabled={mode !== 'ready'} on="cancel">
          Cancel
        </Button>
        <Button variant="primary" block name="decision" value="approve" busy={mode === 'busy'} disabled={mode === 'stopped'} busyLabel="Confirming…" on="confirm">
          Confirm
        </Button>
      </Actions>
      <FootNote icon="shield">Never confirm a code someone sent you.</FootNote>
    </Stack>
  )
}

function SignedFoot({ p }: { p: DeviceConfirmProps }): JSX.Element {
  return (
    <div class="id-fade">
      <FootText>
        Wasn’t you? <Link href={p.revokeHref}>Sign this device out</Link>
      </FootText>
    </div>
  )
}

function CancelledFoot({ p }: { p: DeviceConfirmProps }): JSX.Element {
  return (
    <div class="id-fade">
      <FootText>{`Started it by mistake? Run ${p.cliName} login again.`}</FootText>
    </div>
  )
}

export function DeviceConfirm(p: DeviceConfirmProps): JSX.Element {
  const state = p.state ?? 'idle'
  let body: JSX.Element
  let foot: JSX.Element
  switch (state) {
    case 'signed':
      body = <SignedBody p={p} />
      foot = <SignedFoot p={p} />
      break
    case 'cancelled':
      body = <CancelledBody p={p} />
      foot = <CancelledFoot p={p} />
      break
    default: {
      const connector: Record<string, ConnectorState> = { idle: 'idle', connecting: 'connecting', verdict: 'done', cancelling: 'broken' }
      const mode: Record<string, FootMode> = { idle: 'ready', connecting: 'busy', verdict: 'busy', cancelling: 'stopped' }
      body = <FormBody p={p} connector={connector[state] ?? 'idle'} />
      foot = <FormFoot mode={mode[state] ?? 'ready'} />
    }
  }
  const live = state === 'idle'
  return (
    <Page pinTop>
      <form class="id-form" method="post" action={p.action} data-js="device-confirm">
        <input type="hidden" name="csrf" value={p.csrf} />
        <input type="hidden" name="code" value={p.code} />
        <Card
          foot={
            <CardFoot>
              <div data-region="foot">{foot}</div>
              {live ? (
                <>
                  <template data-state="signed">
                    <SignedFoot p={p} />
                  </template>
                  <template data-state="cancelled">
                    <CancelledFoot p={p} />
                  </template>
                </>
              ) : null}
            </CardFoot>
          }
        >
          <div data-region="body">{body}</div>
          {live ? (
            <>
              <template data-state="signed">
                <SignedBody p={p} />
              </template>
              <template data-state="cancelled">
                <CancelledBody p={p} />
              </template>
            </>
          ) : null}
          <span class="id-sr" role="status" data-status></span>
        </Card>
      </form>
    </Page>
  )
}
