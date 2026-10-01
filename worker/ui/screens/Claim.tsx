/**
 * 5c · Claim agent work (docs/product-update/spec/screens.md#5c).
 *
 * An agent built something in a sandbox; one click claims it into a real
 * workspace for the signed-in account. Claim-by-commit (5d) stays as the repo
 * path. The connector runs agent → id.org.ai: the agent is the requester.
 */
import type { JSX } from 'hono/jsx/jsx-runtime'
import { Actions, Button, Card, CardFoot, CardHead, Connector, Field, Link, Page, Select, Stats, Who, type SelectOption, type TileContent } from '../components'

export interface ClaimProps {
  agent: { name: string; tile: TileContent }
  /** "headless.ly" */
  app: string
  /** Counts from the tenant: contacts, deals, workflows. */
  stats: { n: string; label: string }[]
  /** "18 hours" */
  sandboxEndsIn: string
  account: { name: string; email: string; avatar?: string }
  switchHref: string
  /** The account's workspaces, then "New workspace…". */
  workspaces: SelectOption[]
  selectedWorkspace: string
  /** 5d · Claim from a repository. */
  repoHref: string
  /** `/claim/:token` */
  action: string
  csrf: string
}

const ORG: TileContent = { kind: 'org' }

export function Claim(p: ClaimProps): JSX.Element {
  return (
    <Page>
      <form class="id-form" method="post" action={p.action} data-js="submit">
        <input type="hidden" name="csrf" value={p.csrf} />
        <Card
          foot={
            <CardFoot>
              <Actions>
                <Button variant="secondary" block href={p.repoHref} icon="commit">
                  Claim from a repo
                </Button>
                <Button variant="primary" block busyLabel="Claiming…">
                  Claim workspace
                </Button>
              </Actions>
            </CardFoot>
          }
        >
          <CardHead
            connector={<Connector left={p.agent.tile} right={ORG} />}
            title={`${p.agent.name} set up ${p.app} for you`}
            description="It’s running in a sandbox. Claim it to keep the data and lift the limits."
          />
          <Stats items={p.stats} footer={`Sandbox ends in ${p.sandboxEndsIn}`} />
          <Who name={p.account.name} sub={p.account.email} avatar={p.account.avatar} right={<Link href={p.switchHref}>Switch</Link>} />
          <Field id="claim-workspace" label="Claim into">
            <Select id="claim-workspace" name="org_id" options={p.workspaces} selected={p.selectedWorkspace} />
          </Field>
          <span class="id-sr" role="status" data-status></span>
        </Card>
      </form>
    </Page>
  )
}
