/**
 * 5c · Claim agent work (docs/product-update/spec/screens.md#5c).
 *
 * An agent built something in a sandbox; one click claims it into a real
 * workspace for the signed-in account. Claim-by-commit (5d) stays as the repo
 * path. The connector runs agent → id.org.ai: the agent is the requester.
 *
 * The page stays on id.org.ai (spec/motion.md#where-the-person-goes-next):
 * the live page renders the `idle` form and the claimed body and foot ride
 * along in <template data-state="claimed">, which fetch-form.ts swaps in. When
 * the agent still waits for approval, the server answers `{ redirect }` to 5a
 * instead. Without JS the form posts and the server renders `claimed`.
 */
import type { Child } from 'hono/jsx'
import type { JSX } from 'hono/jsx/jsx-runtime'
import {
  Actions,
  Button,
  Card,
  CardFoot,
  CardHead,
  Connector,
  Em,
  Field,
  FootText,
  Link,
  Page,
  Select,
  Stack,
  Stats,
  Who,
  type ConnectorState,
  type SelectOption,
  type TileContent,
} from '../components'

export type ClaimState = 'idle' | 'claimed'

export interface ClaimProps {
  state?: ClaimState
  agent: { name: string; tile: TileContent }
  /** "headless.ly" */
  app: string
  /** Where "Open headless.ly" goes once claimed. */
  appHref: string
  /** Counts from the tenant: contacts, deals, workflows. */
  stats: { n: string; label: string }[]
  /** "18 hours" */
  sandboxEndsIn: string
  account: { name: string; email: string; avatar?: string }
  switchHref: string
  /** The account's workspaces, then "New workspace…". */
  workspaces: SelectOption[]
  selectedWorkspace: string
  /**
   * `claimed` (server-rendered) only: the workspace the sandbox went into. The
   * live page's template is rendered before the person picks, so it names none.
   */
  claimedInto?: string
  /** 5d · Claim from a repository. */
  repoHref: string
  /** `/claim/:token` */
  action: string
  csrf: string
}

const ORG: TileContent = { kind: 'org' }

function Head({ p, connector, title, description }: { p: ClaimProps; connector: ConnectorState; title: string; description: Child }): JSX.Element {
  return <CardHead connector={<Connector left={p.agent.tile} right={ORG} state={connector} />} title={title} description={description} />
}

function IdleBody({ p }: { p: ClaimProps }): JSX.Element {
  return (
    <Stack gap={22}>
      <Head p={p} connector="idle" title={`${p.agent.name} set up ${p.app} for you`} description="It’s running in a sandbox. Claim it to keep the data and lift the limits." />
      <Stats items={p.stats} footer={`Sandbox ends in ${p.sandboxEndsIn}`} />
      <Who name={p.account.name} sub={p.account.email} avatar={p.account.avatar} right={<Link href={p.switchHref}>Switch</Link>} />
      <Field id="claim-workspace" label="Claim into">
        <Select id="claim-workspace" name="org_id" options={p.workspaces} selected={p.selectedWorkspace} />
      </Field>
    </Stack>
  )
}

function IdleFoot({ p }: { p: ClaimProps }): JSX.Element {
  return (
    <Actions>
      <Button variant="secondary" block href={p.repoHref} icon="commit">
        Claim from a repo
      </Button>
      <Button variant="primary" block busyLabel="Claiming…" done="claimed">
        Claim workspace
      </Button>
    </Actions>
  )
}

function ClaimedBody({ p, into }: { p: ClaimProps; into?: string }): JSX.Element {
  return (
    <Stack gap={22}>
      <Head
        p={p}
        connector="ok"
        title="Your workspace is claimed"
        description={
          into ? (
            <>
              <Em>{p.app}</Em> now lives in <Em>{into}</Em>, with everything {p.agent.name} set up and no sandbox limits.
            </>
          ) : (
            <>
              <Em>{p.app}</Em> is yours now, with everything {p.agent.name} set up and no sandbox limits.
            </>
          )
        }
      />
    </Stack>
  )
}

function ClaimedFoot({ p }: { p: ClaimProps }): JSX.Element {
  return (
    <div class="id-fade">
      <FootText>
        <Link href={p.appHref}>{`Open ${p.app}`}</Link>
      </FootText>
    </div>
  )
}

export function Claim(p: ClaimProps): JSX.Element {
  const claimed = p.state === 'claimed'
  const live = !claimed
  return (
    <Page>
      <form class="id-form" method="post" action={p.action} data-js="fetch-form">
        <input type="hidden" name="csrf" value={p.csrf} />
        <Card
          foot={
            <CardFoot>
              <div data-region="foot">{claimed ? <ClaimedFoot p={p} /> : <IdleFoot p={p} />}</div>
              {live ? (
                <template data-state="claimed">
                  <ClaimedFoot p={p} />
                </template>
              ) : null}
            </CardFoot>
          }
        >
          <div data-region="body">{claimed ? <ClaimedBody p={p} into={p.claimedInto} /> : <IdleBody p={p} />}</div>
          {live ? (
            <template data-state="claimed">
              <ClaimedBody p={p} />
            </template>
          ) : null}
          <span class="id-sr" role="status" data-status>
            {claimed ? 'Workspace claimed.' : ''}
          </span>
        </Card>
      </form>
    </Page>
  )
}
