/**
 * Consent view model → the 3a/3b/3c screen's props (docs/product-update/spec/backend.md#b2).
 *
 * Pure: the route (worker/routes/consent-screen.ts) gathers the person and
 * their workspaces, then calls this; tests and the gallery build the same
 * props from the same inputs. The screen itself derives everything the trust
 * level decides (name, variant, buttons, callout, "Verified: No") from
 * `client.verified`, so nothing here names an unverified client by its own name.
 */
import type { ConsentViewModel } from '../../src/sdk/oauth/consent-view'
import { describeScopes } from '../../src/sdk/oauth/scope-registry'
import type { KV, SelectOption } from './components'
import type { ConsentProps } from './screens/Consent'

export interface ConsentPageContext {
  account: { name: string; email: string; avatar?: string }
  /** The person's active workspaces, in the order to list them. */
  workspaces: Array<{ id: string; name: string }>
  /** The preselected workspace: the request's organization_id, else the remembered one, else the session's. */
  selectedOrgId?: string
  /** /login?prompt=login&continue=<this authorize request> */
  switchHref: string
  /** The hidden fields to post, with `state` already CSRF-bound where the route binds it. */
  fields: Record<string, string>
  csrf: string
}

/** The copy for the two access levels (mock 3a). */
const ACCESS_CHOICE = { read: 'Search and read your Startups', act: 'Also run Verbs that change them' }

function hostOf(uri: string): string {
  try {
    return new URL(uri).host
  } catch {
    return uri
  }
}

/** Where the code goes back to: host:port for a loopback app, the URL without its query otherwise. */
function returnsTo(vm: ConsentViewModel): string {
  if (vm.redirect.loopback) return vm.redirect.host
  try {
    const u = new URL(vm.redirect.uri)
    return `${u.origin}${u.pathname}`
  } catch {
    return vm.redirect.uri
  }
}

/** The source row's details, in each screen's order (mocks 3a, 3b, 3c). The screen adds "Verified: No". */
function sourceDetails(vm: ConsentViewModel): KV[] {
  const runsOn: KV = { k: 'Runs on', v: vm.redirect.loopback ? 'This computer' : vm.redirect.host }
  const back: KV = { k: 'Returns to', v: returnsTo(vm), mono: true }
  const by: KV = { k: 'Identified by', v: vm.client.host }
  if (!vm.client.verified) return [runsOn, back]
  return vm.request === 'basic' ? [by, back] : [runsOn, back, by]
}

/** 3b's line: what the identity scopes share. */
function scopesSummary(scopes: string[]): string {
  const profile = scopes.includes('profile')
  const email = scopes.includes('email')
  if (profile && email) return 'name, email address and profile photo'
  if (profile) return 'name and profile photo'
  return 'email address'
}

export function consentProps(vm: ConsentViewModel, ctx: ConsentPageContext): ConsentProps {
  const selected = ctx.workspaces.find((w) => w.id === ctx.selectedOrgId)
  const resourceHost = vm.resource ? hostOf(vm.resource) : 'id.org.ai'
  const appName = vm.client.verified ? vm.client.displayName : vm.client.host
  const readOnly = vm.scopes.includes('sb:read') && !vm.scopes.includes('sb:do')
  const workspaces: SelectOption[] = ctx.workspaces.map((w) => ({ value: w.id, label: w.name }))
  return {
    variant: vm.request,
    client: {
      displayName: vm.client.displayName,
      host: vm.client.host,
      verified: vm.client.verified,
      runsOnThisComputer: vm.redirect.loopback,
      redirectHost: vm.redirect.host,
      ...(vm.client.logoUrl && { logoUrl: vm.client.logoUrl }),
      ...(vm.client.cimdUrl && { cimdUrl: vm.client.cimdUrl }),
      ...(vm.client.privacyUrl && { privacyUrl: vm.client.privacyUrl }),
      ...(vm.client.termsUrl && { termsUrl: vm.client.termsUrl }),
    },
    resource: resourceHost,
    // 3c words a read-only sb request by what it does (mock 3c).
    ...(!vm.client.verified && readOnly && { intent: 'read your Startups' }),
    ...(vm.request === 'basic' && { scopesSummary: scopesSummary(vm.scopes) }),
    account: ctx.account,
    switchHref: ctx.switchHref,
    ...(workspaces.length > 0 && { workspaces }),
    ...(selected && { selectedWorkspace: selected.id }),
    ...(vm.access && { access: vm.access.choice ? { value: vm.access.default, choice: ACCESS_CHOICE } : { value: vm.access.default } }),
    permissions: describeScopes(vm.scopes, {
      context: vm.client.verified ? 'consent' : 'consentUnverified',
      ...(vm.resource && { resource: vm.resource }),
      ...(selected && { workspaceName: selected.name }),
      appName,
    }),
    sourceDetails: sourceDetails(vm),
    hidden: ctx.fields,
    action: '/oauth/authorize',
    csrf: ctx.csrf,
  }
}
