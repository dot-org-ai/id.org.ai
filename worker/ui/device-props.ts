/**
 * Device request → the 4b confirm screen's props (docs/product-update/spec/backend.md#b3,
 * screens.md#4b). Pure, like consent-props.ts: the route gathers the person
 * and their workspaces, then calls this.
 *
 * The client is named as consent names it (D3): a first-party client by its
 * own name, any other by its registered redirect host, never by the name it
 * gave itself.
 */
import type { DeviceMeta, DeviceRequestView } from '../../src/sdk/oauth/provider'
import { describeScopes } from '../../src/sdk/oauth/scope-registry'
import type { SelectOption } from './components'
import type { DeviceConfirmProps } from './screens/DeviceConfirm'

export interface DevicePageContext {
  account: { name: string; email: string; avatar?: string }
  workspaces: Array<{ id: string; name: string }>
  selectedOrgId?: string
  switchHref: string
  requestId: string
  csrf: string
  now: number
}

/**
 * "macOS · Miami, FL": the OS when known, then always a place (the city and
 * region, else the country, else "location unknown"), so a device name can
 * never stand in for the place (phase 6 review S5).
 */
export function deviceWhere(meta: DeviceMeta | undefined): string {
  const place = [meta?.city, meta?.region].filter(Boolean).join(', ') || meta?.country || 'location unknown'
  return [meta?.os, place].filter(Boolean).join(' · ')
}

/** "macOS · Miami, FL · requested 1 min ago" (unknown parts left out, with their separators). */
export function deviceMetaLine(meta: DeviceMeta | undefined, now: number): string {
  const minutes = meta ? Math.floor((now - meta.requestedAt) / 60_000) : undefined
  const when = minutes === undefined ? undefined : minutes < 1 ? 'requested just now' : `requested ${minutes} min ago`
  return [deviceWhere(meta), when].filter(Boolean).join(' · ')
}

/** The client's name on the page (D3), and the command people run again ("auto.dev"). */
export function deviceClientName(view: DeviceRequestView): { name: string; cliName: string } {
  if (view.client.trusted) return { name: view.client.name, cliName: view.client.name.replace(/ CLI$/, '') }
  const name = view.client.host ?? 'An unverified app'
  return { name, cliName: name }
}

export function deviceConfirmProps(view: DeviceRequestView, ctx: DevicePageContext): DeviceConfirmProps {
  const { name, cliName } = deviceClientName(view)
  const selected = ctx.workspaces.find((w) => w.id === ctx.selectedOrgId) ?? ctx.workspaces[0]
  const workspaces: SelectOption[] = ctx.workspaces.map((w) => ({ value: w.id, label: w.name }))
  return {
    code: view.userCode,
    expiresInMinutes: Math.max(1, Math.ceil((view.expiresAt - ctx.now) / 60_000)),
    requestId: ctx.requestId,
    client: { name, tile: { kind: 'icon', icon: 'terminal' } },
    cliName,
    deviceMeta: deviceMetaLine(view.meta, ctx.now),
    device: deviceWhere(view.meta),
    account: ctx.account,
    switchHref: ctx.switchHref,
    workspaces,
    selectedWorkspace: selected?.id ?? '',
    permissions: describeScopes(view.scopes, { context: 'device', appName: name, ...(selected && { workspaceName: selected.name }) }),
    revokeHref: `/device/${encodeURIComponent(view.family)}/revoke`,
    action: '/device/decision',
    csrf: ctx.csrf,
  }
}
