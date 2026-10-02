/**
 * 4b · Confirm device code (docs/product-update/spec/screens.md#4b).
 *
 * The live page renders the `idle` form; the signed, cancelled and error
 * bodies and feet ride along in <template data-state> elements, and
 * fetch-form.ts swaps them in on the state machine in spec/motion.md. The
 * gallery renders each state directly through `state`.
 *
 * Errors (motion.md#device-confirm-4b-the-reference-state-machine): a refused
 * Confirm shows the 7b copy for `expired` / `already_used` (from
 * worker/ui/errors.ts) or the generic error with "Try again"; a failed Cancel
 * says the request may still be pending.
 */
import type { JSX } from 'hono/jsx/jsx-runtime'
import { errorPageProps } from '../errors'
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

/** The error templates, named as fetch-form.ts looks them up: `error-<code>`, `error-cancel` (a failed Cancel), `error`. */
export type DeviceConfirmError = 'error-expired' | 'error-already_used' | 'error-cancel' | 'error'

export const DEVICE_CONFIRM_ERRORS: readonly DeviceConfirmError[] = ['error-expired', 'error-already_used', 'error-cancel', 'error']

export type DeviceConfirmState = 'idle' | 'connecting' | 'verdict' | 'signed' | 'cancelling' | 'cancelled' | DeviceConfirmError

export interface DeviceConfirmProps {
  state?: DeviceConfirmState
  /** Shown as XXXX-XXXX. */
  code: string
  /** Minutes until the code expires ("the code expires in 29 minutes" after a failed Cancel). */
  expiresInMinutes: number
  /** X-Request-Id, the context for the error copy. */
  requestId: string
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
        <Button variant="secondary" block name="decision" value="deny" disabled={mode !== 'ready'} deny done="cancelled">
          Cancel
        </Button>
        <Button variant="primary" block name="decision" value="approve" busy={mode === 'busy'} disabled={mode === 'stopped'} busyLabel="Confirming…" done="signed">
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

/** Where "Try again" goes: this page again, re-reading the code's state. */
function deviceConfirmHref(code: string): string {
  return `/device?code=${encodeURIComponent(code)}`
}

function minutes(n: number): string {
  return `${n} ${n === 1 ? 'minute' : 'minutes'}`
}

/** Each error's head copy and foot: the 7b copy (errors.ts) for expired and used codes. */
function errorContent(p: DeviceConfirmProps, error: DeviceConfirmError): { title: string; reason: string; foot: JSX.Element } {
  switch (error) {
    case 'error-expired':
    case 'error-already_used': {
      const e = errorPageProps(error === 'error-expired' ? 'expired' : 'already_used', {
        requestId: p.requestId,
        expired: { what: 'device code' },
        startHref: '/device',
      })
      const a = e.actions.primary
      return {
        title: e.title,
        reason: e.reason,
        foot: (
          <Button variant="primary" block href={a.href}>
            {a.label}
          </Button>
        ),
      }
    }
    case 'error-cancel':
      return {
        title: 'We couldn’t cancel this request',
        reason: `Close this tab; the code expires in ${minutes(p.expiresInMinutes)}.`,
        foot: <FootText>{`Nothing is shared with ${p.client.name} unless you confirm.`}</FootText>,
      }
    case 'error': {
      const e = errorPageProps('server_error', { requestId: p.requestId })
      return {
        title: e.title,
        reason: e.reason,
        foot: (
          <Button variant="primary" block href={deviceConfirmHref(p.code)}>
            Try again
          </Button>
        ),
      }
    }
  }
}

function ErrorBody({ p, error }: { p: DeviceConfirmProps; error: DeviceConfirmError }): JSX.Element {
  const c = errorContent(p, error)
  return (
    <Stack gap={22}>
      <Head p={p} connector="fail" title={c.title} description={c.reason} />
    </Stack>
  )
}

function ErrorFoot({ p, error }: { p: DeviceConfirmProps; error: DeviceConfirmError }): JSX.Element {
  return <div class="id-fade">{errorContent(p, error).foot}</div>
}

function isError(state: DeviceConfirmState): state is DeviceConfirmError {
  return (DEVICE_CONFIRM_ERRORS as readonly string[]).includes(state)
}

export function DeviceConfirm(p: DeviceConfirmProps): JSX.Element {
  const state = p.state ?? 'idle'
  let body: JSX.Element
  let foot: JSX.Element
  if (state === 'signed') {
    body = <SignedBody p={p} />
    foot = <SignedFoot p={p} />
  } else if (state === 'cancelled') {
    body = <CancelledBody p={p} />
    foot = <CancelledFoot p={p} />
  } else if (isError(state)) {
    body = <ErrorBody p={p} error={state} />
    foot = <ErrorFoot p={p} error={state} />
  } else {
    const connector: Record<string, ConnectorState> = { idle: 'idle', connecting: 'connecting', verdict: 'done', cancelling: 'broken' }
    const mode: Record<string, FootMode> = { idle: 'ready', connecting: 'busy', verdict: 'busy', cancelling: 'stopped' }
    body = <FormBody p={p} connector={connector[state] ?? 'idle'} />
    foot = <FormFoot mode={mode[state] ?? 'ready'} />
  }
  const live = state === 'idle'
  return (
    <Page pinTop>
      <form class="id-form" method="post" action={p.action} data-js="fetch-form">
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
                  {DEVICE_CONFIRM_ERRORS.map((e) => (
                    <template data-state={e}>
                      <ErrorFoot p={p} error={e} />
                    </template>
                  ))}
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
              {DEVICE_CONFIRM_ERRORS.map((e) => (
                <template data-state={e}>
                  <ErrorBody p={p} error={e} />
                </template>
              ))}
            </>
          ) : null}
          <span class="id-sr" role="status" data-status></span>
        </Card>
      </form>
    </Page>
  )
}
