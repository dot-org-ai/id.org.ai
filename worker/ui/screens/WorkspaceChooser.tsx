/**
 * 2b · Choose workspace (docs/product-update/spec/screens.md#2b).
 *
 * Two modes share the card:
 * - `choose`: `POST /workspace/choose?continue=` with `org_id` and `remember`.
 * - `sign-in`: WorkOS returned `organization_selection_required`; the card
 *   posts the existing `POST /api/org-select` contract (`pending_token`,
 *   `state`, `organization_id`), so the WorkOS exchange is unchanged.
 */
import type { JSX } from 'hono/jsx/jsx-runtime'
import {
  Actions,
  Button,
  Card,
  CardFoot,
  CardHead,
  Checkbox,
  Connector,
  Dotted,
  Em,
  Link,
  Page,
  RadioCard,
  Who,
  type TileContent,
} from '../components'
import { RadioGroup } from '../components/RadioCard'

export type WorkspaceRole = 'owner' | 'admin' | 'member' | 'personal'

export interface ChooserWorkspace {
  id: string
  name: string
  role: WorkspaceRole
}

export type WorkspaceChooserMode =
  | { kind: 'choose'; /** `/workspace/choose?continue=…` */ action: string }
  | { kind: 'sign-in'; /** `/api/org-select` */ action: string; pendingAuthenticationToken: string; state: string }

export interface WorkspaceChooserProps {
  mode: WorkspaceChooserMode
  app: { name: string; tile: TileContent }
  account: { name: string; email: string; avatar?: string }
  /** The who row's Switch link; omitted, the row has no right slot. */
  switchHref?: string
  workspaces: ChooserWorkspace[]
  selectedId: string
  /** "Remember for {app}" (default on). Omitted, the checkbox is not shown (sign-in mode stores nothing). */
  remember?: boolean
  /** `/workspace/new`. Omitted, Continue fills the foot alone. */
  newWorkspaceHref?: string
  csrf: string
}

const ROLE_LABEL: Record<WorkspaceRole, string> = {
  owner: 'Owner',
  admin: 'Admin',
  member: 'Member',
  personal: 'Just you',
}

const ORG: TileContent = { kind: 'org' }

export function WorkspaceChooser(p: WorkspaceChooserProps): JSX.Element {
  const signIn = p.mode.kind === 'sign-in'
  const field = signIn ? 'organization_id' : 'org_id'
  const proceed = (
    <Button variant="primary" block busyLabel="Continuing…">
      Continue
    </Button>
  )
  return (
    <Page narrow>
      <form class="id-form" method="post" action={p.mode.action} data-js="submit">
        <input type="hidden" name="csrf" value={p.csrf} />
        {p.mode.kind === 'sign-in' ? (
          <>
            <input type="hidden" name="pending_token" value={p.mode.pendingAuthenticationToken} />
            <input type="hidden" name="state" value={p.mode.state} />
          </>
        ) : null}
        <Card
          foot={
            <CardFoot>
              {p.newWorkspaceHref !== undefined ? (
                <Actions>
                  <Button variant="secondary" block href={p.newWorkspaceHref} icon="plus">
                    New workspace
                  </Button>
                  {proceed}
                </Actions>
              ) : (
                proceed
              )}
            </CardFoot>
          }
        >
          <CardHead
            connector={<Connector left={ORG} right={p.app.tile} />}
            title="Choose a workspace"
            description={
              <>
                <Em>{p.app.name}</Em> will use this workspace’s data and billing.
              </>
            }
          />
          <Dotted />
          <Who name={p.account.name} sub={p.account.email} avatar={p.account.avatar} right={p.switchHref !== undefined ? <Link href={p.switchHref}>Switch</Link> : undefined} />
          <RadioGroup legend="Workspace" layout="stack" hideLabel>
            {p.workspaces.map((w) => (
              <RadioCard id={`ws-${w.id}`} name={field} value={w.id} checked={w.id === p.selectedId} title={w.name} description={ROLE_LABEL[w.role]} />
            ))}
          </RadioGroup>
          {p.remember !== undefined ? (
            <Checkbox id="ws-remember" name="remember" checked={p.remember}>
              {`Remember for ${p.app.name}`}
            </Checkbox>
          ) : null}
          <span class="id-sr" role="status" data-status></span>
        </Card>
      </form>
    </Page>
  )
}
