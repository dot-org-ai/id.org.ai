/**
 * 5d · Claim from a repository (docs/product-update/spec/screens.md#5d).
 *
 * Claim-by-commit: run the command (or commit the workflow) in the repo; the
 * push proves who you are. The live page polls `statusUrl` every 5s through
 * claim-status.js, which moves the status list and the connector in place
 * (connecting → done). The server renders `claimed` with the connector at ok.
 * The connector runs commit → id.org.ai: the commit is the requester.
 */
import type { JSX } from 'hono/jsx/jsx-runtime'
import { Card, CardFoot, CardHead, CodeBlock, Connector, Disclosure, Dotted, FootText, Link, Page, Pre, StatusList, Step, type StatusItem, type TileContent } from '../components'

export type ClaimRepoStatus = 'waiting' | 'pending' | 'claimed'

export interface ClaimRepoProps {
  status?: ClaimRepoStatus
  /** `npx id.org.ai claim clm_…` */
  command: string
  /** ".github/workflows/id.yml" */
  workflowPath: string
  workflowYaml: string
  /** The repository being watched, when known ("dot-do/headless-crm"). */
  repo?: string
  /** `GET /api/claim/:token/status`, polled every 5s. */
  statusUrl: string
  /** 5c · Claim with your account. */
  claimHref: string
  /** Gallery only: the command's copy button in its copied state. */
  copied?: boolean
}

const COMMIT: TileContent = { kind: 'icon', icon: 'commit' }
const ORG: TileContent = { kind: 'org' }
const ORDER: ClaimRepoStatus[] = ['waiting', 'pending', 'claimed']

function statusItems(p: ClaimRepoProps, status: ClaimRepoStatus): StatusItem[] {
  const at = ORDER.indexOf(status)
  return [
    { title: 'Waiting for a push', sub: p.repo ? `Watching ${p.repo}` : 'Watching for the commit' },
    { title: 'Pending on a branch', sub: 'Claimed once merged to main' },
    { title: 'Claimed', sub: 'The sandbox becomes your workspace' },
  ].map((it, i) => ({ ...it, current: i === at }))
}

export function ClaimRepo(p: ClaimRepoProps): JSX.Element {
  const status = p.status ?? 'waiting'
  const claimed = status === 'claimed'
  return (
    <Page>
      <Card
        foot={
          <CardFoot>
            <FootText>
              Prefer one click? <Link href={p.claimHref}>Claim with your account instead</Link>
            </FootText>
          </CardFoot>
        }
      >
        <CardHead
          connector={<Connector left={COMMIT} right={ORG} state={claimed ? 'ok' : 'connecting'} />}
          title="Claim from a repository"
          description="The commit proves who you are: GitHub already knows who pushed it. Any branch works; merging to main confirms the claim."
        />
        <Dotted />
        <Step n={1} label="Run this in the repo">
          <CodeBlock code={p.command} copied={p.copied} />
        </Step>
        <Step n={2} label="Or commit the workflow yourself">
          <Disclosure summary={p.workflowPath}>
            <Pre>{p.workflowYaml}</Pre>
          </Disclosure>
        </Step>
        <Dotted />
        <div data-js={claimed ? undefined : 'claim-status'} data-status-url={claimed ? undefined : p.statusUrl}>
          <StatusList items={statusItems(p, status)} />
        </div>
      </Card>
    </Page>
  )
}
