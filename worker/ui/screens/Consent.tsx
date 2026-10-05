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
 * The trust level is the component's job, not the caller's (security.md, D3).
 * From `client.verified` it derives the variant, the name shown, the tile's
 * monogram, the warning callout, the button order and the "Verified: No" row:
 * - `full` (3a): workspace select, the access level radios, permissions.
 * - `basic` (3b): a verified client asking for identity scopes only; the
 *   primary reads "Continue as {first name}".
 * - `unverified` (3c): every unverified client, whatever the caller asked for.
 *   The host is the name (never the self-asserted client_name), the warning
 *   callout replaces the rule under the head, and Cancel gets primary emphasis.
 *   Cancel stays on the left and Allow on the right for every trust level.
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
  type KV,
  type PermissionItem,
  type SelectOption,
  type SourceRowProps,
  type TileContent,
} from '../components'

/** What the screen renders: 3a, 3b or 3c. Derived by `consentVariant`, never taken from the caller as is. */
export type ConsentVariant = 'full' | 'basic' | 'unverified'
/** What the caller asks for: the full screen (3a) or the identity-only one (3b). */
export type ConsentRequest = 'full' | 'basic'
export type AccessLevel = 'read' | 'act'

/** The OAuth client, as the authorize request resolves it (screens.md#3a Data). */
export interface ConsentClient {
  /** The client's self-asserted `client_name`. Shown only when `verified` (security.md). */
  displayName: string
  /** The host the client is identified by (the CIMD host). The name shown for an unverified client. */
  host: string
  /** The client's logo_uri (https), or a first-party file; the monogram stands in without it (logos.md). */
  logoUrl?: string
  /** On the verified list (D3). False for every DCR client and any CIMD host not on the list. */
  verified: boolean
  /** The redirect is loopback: the app runs on this computer. 3c says so in its description. */
  runsOnThisComputer: boolean
  /** The redirect's host ("127.0.0.1:57585"). The Returns to row in `sourceDetails` words it per screen. */
  redirectHost: string
  /** The client metadata document URL. The source row shows it, or the client_id (DCR) without one (backend.md#b2). */
  cimdUrl?: string
  /** The app's privacy policy and terms (https only), linked in the source row under the shown name. */
  privacyUrl?: string
  termsUrl?: string
  /**
   * A verified client's 1–2 letter monogram ("Cx"). Default: the first letter of
   * its name. An unverified client always gets the first letter of its host.
   */
  monogram?: string
}

export interface ConsentProps {
  /**
   * The screen asked for. `basic` (3b) renders only for a verified client whose
   * scopes are all identity scopes; anything else asked as `basic` renders 3a.
   * An unverified client always renders 3c, whatever this says.
   */
  variant: ConsentRequest
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
  /**
   * The source row's details in the order the screen shows them (Runs on,
   * Returns to, Identified by). An unverified client gets "Verified: No" added
   * last; a caller's own Verified row is dropped.
   */
  sourceDetails: KV[]
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
const IDENTITY_SCOPES = new Set(['openid', 'profile', 'email'])

/** A person's first name: theirs when known, else the first word of their name. Shared with 3d. */
export function firstName(person: { name: string; firstName?: string }): string {
  return person.firstName ?? person.name.trim().split(/\s+/)[0] ?? person.name
}

/** The name shown for a client: the host when unverified, never the self-asserted name (security.md, screens.md#3c). */
export function consentAppName(client: Pick<ConsentClient, 'displayName' | 'host' | 'verified'>): string {
  return client.verified ? client.displayName : client.host
}

function identityOnly(p: ConsentProps): boolean {
  const scopes = (p.hidden.scope ?? '').split(/\s+/).filter(Boolean)
  return scopes.length > 0 && scopes.every((s) => IDENTITY_SCOPES.has(s))
}

/** 3c whenever the client is unverified; 3b only for a verified, identity-only request; 3a otherwise. */
export function consentVariant(p: ConsentProps): ConsentVariant {
  if (!p.client.verified) return 'unverified'
  return p.variant === 'basic' && identityOnly(p) ? 'basic' : 'full'
}

/** The app tile: its logo with the monogram fallback. An unverified client's monogram comes from its host. */
export function clientTile(c: Pick<ConsentClient, 'displayName' | 'host' | 'verified' | 'logoUrl' | 'monogram'>): TileContent {
  const monogram = (c.verified ? c.monogram : undefined) ?? (consentAppName(c).trim().charAt(0) || '?')
  return c.logoUrl ? { kind: 'logo', src: c.logoUrl, monogram } : { kind: 'monogram', text: monogram }
}

/** The source row: the CIMD URL (or client_id) with copy, the details (plus Verified: No), the app's links under the shown name. */
function sourceRow(p: ConsentProps, v: ConsentVariant, app: string): Omit<SourceRowProps, 'icon' | 'copied'> {
  const value = p.client.cimdUrl ?? p.hidden.client_id ?? p.client.host
  const details = p.sourceDetails.filter((d) => d.k !== 'Verified')
  if (v === 'unverified') details.push({ k: 'Verified', v: 'No' })
  const links: { href: string; label: string }[] = []
  if (p.client.privacyUrl) links.push({ href: p.client.privacyUrl, label: `${app} privacy policy` })
  if (p.client.termsUrl) links.push({ href: p.client.termsUrl, label: `${app} terms` })
  return { display: value.replace(/^https:\/\//, ''), copyValue: value, details, links }
}

/** Everything the trust level decides, worked out once per render. */
interface View {
  v: ConsentVariant
  app: string
}

/** Title and description per variant (screens.md#3a, mocks 3b and 3c). */
function heading(p: ConsentProps, { v, app }: View): { title: string; description: string } {
  switch (v) {
    case 'basic':
      return { title: `Sign in to ${app}`, description: `${app} will get your ${p.scopesSummary ?? 'name and email address'}.` }
    case 'unverified': {
      const where = p.client.runsOnThisComputer ? 'It runs on your computer and asked' : 'It asked'
      const title = `${app} wants to ${p.intent ?? `use ${p.resource} as you`}`
      // Without an access level the request is for identity only (no API access to name).
      if (!p.access) return { title, description: `${where} to see your name, email and photo.` }
      const level = p.access.value === 'act' ? 'read and act' : 'read'
      return { title, description: `${where} for ${level} access to ${p.resource}.` }
    }
    default:
      return { title: `${app} wants to ${p.intent ?? `use ${p.resource} as you`}`, description: 'Choose what it can do. You can change this or revoke it anytime.' }
  }
}

/** The primary action's label and progressive form. */
function allowLabels(p: ConsentProps, { v }: View): { label: string; busy: string } {
  return v === 'basic' ? { label: `Continue as ${firstName(p.account)}`, busy: 'Continuing…' } : { label: 'Allow', busy: 'Allowing…' }
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

function Body({ p, view }: { p: ConsentProps; view: View }): JSX.Element {
  const { title, description } = heading(p, view)
  const { v, app } = view
  const permissions = v !== 'basic' && p.permissions && p.permissions.length ? p.permissions : null
  return (
    <Stack gap={22}>
      <CardHead connector={<Connector left={ORG} right={clientTile(p.client)} state={p.busy ? 'connecting' : 'idle'} />} title={title} description={description} />
      {v === 'unverified' ? (
        <WarningCallout title="id.org.ai can’t vouch for this app">{`Only continue if you trust ${app} and started this yourself.`}</WarningCallout>
      ) : (
        <Dotted />
      )}
      <Who name={p.account.name} sub={p.account.email} avatar={p.account.avatar} right={<Link href={p.switchHref}>Switch</Link>} />
      <Workspace p={p} />
      <Access p={p} />
      {permissions ? <PermissionList heading={`${app} would like to`} items={permissions} /> : null}
      {permissions ? <Dotted /> : null}
      <SourceRow icon="globe" {...sourceRow(p, v, app)} copied={p.copied} />
    </Stack>
  )
}

function Foot({ p, view }: { p: ConsentProps; view: View }): JSX.Element {
  const allow = allowLabels(p, view)
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
  // Keep action positions consistent; unverified apps emphasize Cancel without moving it.
  return (
    <CardFoot>
      <Actions>
        {view.v === 'unverified' ? (
          <>
            {cancelButton('primary')}
            {allowButton('secondary')}
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

/** The document title, naming the app as the screen does (the host for an unverified client). */
export function consentTitle(p: ConsentProps): string {
  return consentVariant(p) === 'basic' ? `Sign in to ${consentAppName(p.client)} · id.org.ai` : `Authorize ${consentAppName(p.client)} · id.org.ai`
}

export function Consent(p: ConsentProps): JSX.Element {
  const view: View = { v: consentVariant(p), app: consentAppName(p.client) }
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
        <Card foot={<Foot p={p} view={view} />}>
          <Body p={p} view={view} />
          <span class="id-sr" role="status" data-status>
            {p.busy ? allowLabels(p, view).busy : ''}
          </span>
        </Card>
      </form>
    </Page>
  )
}
