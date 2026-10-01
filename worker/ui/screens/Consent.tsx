/**
 * 3a · Authorize app, 3b · Sign in with id.org.ai, 3c · Unverified app
 * (docs/product-update/spec/screens.md#3a, #3b, #3c). Replaces
 * renderConsentPage in src/sdk/oauth/provider.ts.
 *
 * One form posts to POST /oauth/authorize: the existing hidden fields, the
 * chosen workspace (org_id), the access level (access=read|act) and the
 * clicked button (approved=true|false, the existing contract). submit.ts puts
 * the connector into `connecting` and the Allow button into "Allowing…" on
 * submit, then lets the post and the redirect to the app happen.
 *
 * Variants:
 * - `full` (3a): workspace select, the access level radios, permissions.
 * - `basic` (3b): identity scopes only; the primary reads "Continue as {first name}".
 * - `unverified` (3c): the host is the name, the warning callout replaces the
 *   rule under the head, and the buttons flip (Allow outlined on the left,
 *   Cancel primary on the right).
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
  PermissionList,
  RadioCard,
  RadioGroup,
  Select,
  SourceRow,
  Stack,
  WarningCallout,
  Who,
  Link,
  Page,
  type PermissionItem,
  type SelectOption,
  type SourceRowProps,
  type TileContent,
} from '../components'

export type ConsentVariant = 'full' | 'basic' | 'unverified'
export type AccessLevel = 'read' | 'act'

export interface ConsentClient {
  /** The display name: a verified client's name, or the host for an unverified one (security.md). */
  name: string
  /** The app tile: its logo_uri, or the monogram fallback. */
  tile: TileContent
  /** The app runs on this computer (loopback redirect). 3c says so in its description. */
  runsOnThisComputer?: boolean
}

export interface ConsentProps {
  variant: ConsentVariant
  client: ConsentClient
  /** The API resource host ("api.sb"). */
  resource: string
  /**
   * What the app wants, after "{app} wants to". Defaults to "use {resource} as you"
   * (3a); the scope registry words a read-only request ("read your Startups", 3c).
   */
  intent?: string
  /** 3b: what identity scopes share ("name, email address and profile photo"). */
  scopesSummary?: string
  account: { name: string; email: string; avatar?: string; firstName?: string }
  /** Who row "Switch": /login?prompt=login&continue=<current request> while FEATURE_SESSIONS_V2 is off. */
  switchHref: string
  /** The person's workspaces. Without them the selected one posts as a hidden org_id. */
  workspaces?: SelectOption[]
  selectedWorkspace?: string
  /**
   * The access level (B2). With `choice` (descriptions for Read only and Read and act)
   * it renders the two radios; otherwise it posts as a hidden field.
   */
  access?: { value: AccessLevel; choice?: { read: string; act: string } }
  /** Permission rows from the scope registry (unused by 3b). */
  permissions?: PermissionItem[]
  /** The source row: the CIMD URL (or client_id) and its details. */
  source: Omit<SourceRowProps, 'icon' | 'copied'>
  /** Gallery: the source row's copied state. */
  copied?: boolean
  /** Submitting: the connector connects and Allow shows "Allowing…". */
  busy?: boolean
  /** The existing hidden fields: client_id, redirect_uri, scope, state, code_challenge, code_challenge_method, nonce, resource. */
  hidden: Record<string, string>
  /** POST /oauth/authorize */
  action: string
  csrf: string
}

const ORG: TileContent = { kind: 'org' }

function firstName(account: ConsentProps['account']): string {
  return account.firstName ?? account.name.trim().split(/\s+/)[0] ?? account.name
}

/** Title and description per variant (screens.md#3a, mocks 3b and 3c). */
function heading(p: ConsentProps): { title: string; description: string } {
  const app = p.client.name
  switch (p.variant) {
    case 'basic':
      return { title: `Sign in to ${app}`, description: `${app} will get your ${p.scopesSummary ?? 'name and email address'}.` }
    case 'unverified': {
      const where = p.client.runsOnThisComputer ? 'It runs on your computer and asked' : 'It asked'
      const level = p.access?.value === 'act' ? 'read and act' : 'read'
      return { title: `${app} wants to ${p.intent ?? `use ${p.resource} as you`}`, description: `${where} for ${level} access to ${p.resource}.` }
    }
    default:
      return { title: `${app} wants to ${p.intent ?? `use ${p.resource} as you`}`, description: 'Choose what it can do. You can change this or revoke it anytime.' }
  }
}

/** The primary action's label and progressive form. */
function allowLabels(p: ConsentProps): { label: string; busy: string } {
  return p.variant === 'basic' ? { label: `Continue as ${firstName(p.account)}`, busy: 'Continuing…' } : { label: 'Allow', busy: 'Allowing…' }
}

function Workspace({ p }: { p: ConsentProps }): JSX.Element | null {
  if (p.workspaces && p.workspaces.length) {
    return (
      <Field id="consent-workspace" label="Workspace">
        <Select id="consent-workspace" name="org_id" options={p.workspaces} selected={p.selectedWorkspace} />
      </Field>
    )
  }
  return null
}

function Access({ p }: { p: ConsentProps }): JSX.Element | null {
  const choice = p.access?.choice
  if (!p.access || !choice) return null
  return (
    <RadioGroup legend="Access" layout="row">
      <RadioCard id="consent-access-read" name="access" value="read" checked={p.access.value === 'read'} title="Read only" description={choice.read} />
      <RadioCard id="consent-access-act" name="access" value="act" checked={p.access.value === 'act'} title="Read and act" description={choice.act} accent />
    </RadioGroup>
  )
}

function Body({ p }: { p: ConsentProps }): JSX.Element {
  const { title, description } = heading(p)
  const unverified = p.variant === 'unverified'
  const permissions = p.variant !== 'basic' && p.permissions && p.permissions.length ? p.permissions : null
  return (
    <Stack gap={22}>
      <CardHead connector={<Connector left={ORG} right={p.client.tile} state={p.busy ? 'connecting' : 'idle'} />} title={title} description={description} />
      {unverified ? (
        <WarningCallout title="id.org.ai can’t vouch for this app">{`Only continue if you trust ${p.client.name} and started this yourself.`}</WarningCallout>
      ) : (
        <Dotted />
      )}
      <Who name={p.account.name} sub={p.account.email} avatar={p.account.avatar} right={<Link href={p.switchHref}>Switch</Link>} />
      <Workspace p={p} />
      <Access p={p} />
      {permissions ? <PermissionList heading={`${p.client.name} would like to`} items={permissions} /> : null}
      {permissions ? <Dotted /> : null}
      <SourceRow icon="globe" {...p.source} copied={p.copied} />
    </Stack>
  )
}

function Foot({ p }: { p: ConsentProps }): JSX.Element {
  const allow = allowLabels(p)
  const busy = !!p.busy
  const cancelButton = (variant: 'primary' | 'secondary') => (
    <Button variant={variant} block name="approved" value="false" disabled={busy} on="cancel">
      Cancel
    </Button>
  )
  const allowButton = (variant: 'primary' | 'secondary') => (
    <Button variant={variant} block name="approved" value="true" busy={busy} busyLabel={allow.busy} on="allow">
      {allow.label}
    </Button>
  )
  // Unverified apps flip the emphasis: Allow outlined on the left, Cancel primary on the right (layout.md#actions).
  return (
    <CardFoot>
      <Actions>
        {p.variant === 'unverified' ? (
          <>
            {allowButton('secondary')}
            {cancelButton('primary')}
          </>
        ) : (
          <>
            {cancelButton('secondary')}
            {allowButton('primary')}
          </>
        )}
      </Actions>
    </CardFoot>
  )
}

export function Consent(p: ConsentProps): JSX.Element {
  const showsWorkspaces = !!(p.workspaces && p.workspaces.length)
  return (
    <Page>
      <form class="id-form" method="post" action={p.action} data-js="submit">
        <input type="hidden" name="csrf" value={p.csrf} />
        {Object.entries(p.hidden).map(([name, value]) => (
          <input type="hidden" name={name} value={value} />
        ))}
        {!showsWorkspaces && p.selectedWorkspace ? <input type="hidden" name="org_id" value={p.selectedWorkspace} /> : null}
        {p.access && !p.access.choice ? <input type="hidden" name="access" value={p.access.value} /> : null}
        <Card foot={<Foot p={p} />}>
          <Body p={p} />
          <span class="id-sr" role="status" data-status>
            {p.busy ? allowLabels(p).busy : ''}
          </span>
        </Card>
      </form>
    </Page>
  )
}
