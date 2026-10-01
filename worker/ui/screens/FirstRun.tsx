/**
 * 1d · First run (docs/product-update/spec/screens.md#1d), and the derived
 * "Create a workspace" screen (/workspace/new, screens.md#2b): the same layout
 * with only the Workspace field.
 *
 * First run: GET/POST /welcome?continue=. Create account saves the name (the
 * WorkOS user's first and last name), renames the personal workspace, then
 * continues. "Not you?" signs this session out and returns to 1a.
 * The head is the single id.org.ai tile (no connector).
 */
import type { JSX } from 'hono/jsx/jsx-runtime'
import { Actions, Button, Card, CardFoot, CardHead, Em, Field, FootNote, Input, Link, Page, SingleTile, Stack } from '../components'

interface Common {
  /** POST /welcome?continue=… (first run) or POST /workspace/new. */
  action: string
  csrf: string
  /** Prefilled with the personal workspace name on first run. */
  workspaceName?: string
  workspaceError?: string
}

export interface FirstRunIdentityProps extends Common {
  variant?: 'first-run'
  /** Prefilled from the provider. */
  name?: string
  /** "GitHub": the hint "From GitHub" beside the Name label, and the foot line. */
  provider: string
  providerUsername: string
  /** Signs this session out and returns to 1a. */
  notYouHref: string
  nameError?: string
}

export interface NewWorkspaceProps extends Common {
  variant: 'new-workspace'
  /** Back to the workspace chooser (2b). */
  backHref?: string
}

export type FirstRunProps = FirstRunIdentityProps | NewWorkspaceProps

function WorkspaceField({ p, hint, placeholder }: { p: Common; hint?: string; placeholder?: string }): JSX.Element {
  return (
    <Field id="workspace" label="Workspace" hint={hint} error={p.workspaceError}>
      <Input
        id="workspace"
        name="workspace"
        value={p.workspaceName}
        placeholder={placeholder}
        autocomplete="organization"
        maxlength={64}
        required
        hint={Boolean(hint)}
        error={Boolean(p.workspaceError)}
      />
    </Field>
  )
}

function Identity(p: FirstRunIdentityProps): JSX.Element {
  return (
    <Card
      foot={
        <CardFoot>
          <Button variant="primary" block busyLabel="Creating account…">
            Create account
          </Button>
          <FootNote>
            {`Signed in with ${p.provider} as `}
            <Em>{p.providerUsername}</Em>
            {'. '}
            <Link href={p.notYouHref}>Not you?</Link>
          </FootNote>
        </CardFoot>
      }
    >
      <CardHead
        connector={<SingleTile content={{ kind: 'org' }} />}
        title="Create your identity"
        description="This is how you appear to the apps and agents you approve."
      />
      <Stack gap={18}>
        <Field id="name" label="Name" aside={p.name ? `From ${p.provider}` : undefined} error={p.nameError}>
          <Input id="name" name="name" value={p.name} autocomplete="name" maxlength={128} required error={Boolean(p.nameError)} />
        </Field>
        <WorkspaceField p={p} hint="A workspace holds your team, apps and agents. Add more anytime." />
      </Stack>
      <span class="id-sr" role="status" data-status></span>
    </Card>
  )
}

function NewWorkspace(p: NewWorkspaceProps): JSX.Element {
  const create = (
    <Button variant="primary" block busyLabel="Creating workspace…">
      Create workspace
    </Button>
  )
  return (
    <Card
      foot={
        <CardFoot>
          {p.backHref ? (
            <Actions>
              <Button variant="secondary" block href={p.backHref}>
                Back
              </Button>
              {create}
            </Actions>
          ) : (
            create
          )}
        </CardFoot>
      }
    >
      <CardHead connector={<SingleTile content={{ kind: 'org' }} />} title="Create a workspace" description="A workspace holds your team, apps and agents." />
      <WorkspaceField p={p} placeholder="Your team or company" />
      <span class="id-sr" role="status" data-status></span>
    </Card>
  )
}

export function FirstRun(p: FirstRunProps): JSX.Element {
  return (
    <Page>
      <form class="id-form" method="post" action={p.action} data-js="submit">
        <input type="hidden" name="csrf" value={p.csrf} />
        {p.variant === 'new-workspace' ? <NewWorkspace {...p} /> : <Identity {...p} />}
      </form>
    </Page>
  )
}
