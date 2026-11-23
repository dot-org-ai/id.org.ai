/**
 * /__design/agent-setup: the agent setup, payment and connect screens by ID
 * (docs/agent-setup/HANDOFF.md section 2), each rendered from its fixture so it
 * can be compared with its PNG. The three phone drawings (9f, 9g, 9h) are not
 * listed: 9b, 9a and 9c are the same pages, and they are responsive. Dev only, like the rest of the gallery.
 */
import type { JSX } from 'hono/jsx/jsx-runtime'
import manifest from '../../../docs/agent-setup/manifest.json'
import { Card, CardFoot, CardHead, FootText, Link, Page, SingleTile } from '../components'
import type { FixtureGroup } from './types'

export interface AgentScreen {
  id: string
  slug: string
  file: string
  png: string
  title: string
  size: number[]
  kind: string
  phase: number
  /** A phone drawing of another screen: the slug of the fixture it shares. */
  renders?: string
  /** Why the page deliberately differs from its drawing, when it does. */
  departs?: string
}

export const AGENT_SCREENS = (manifest as { screens: AgentScreen[] }).screens

/** The fixture slug a screen renders from (a phone drawing shares its desktop screen's). */
export function fixtureSlug(s: AgentScreen): string {
  return s.renders ?? s.slug
}

const PHASES: Record<number, string> = {
  2: 'Setup page and its states',
  3: 'Agents and policy',
  4: 'Emails',
  5: 'apis.directory run',
  6: 'Workflows',
  7: 'Payments',
  8: 'Connect from Claude',
}

export function AgentSetupIndex({ fixtures }: { fixtures: FixtureGroup }): JSX.Element {
  const built = AGENT_SCREENS.filter((s) => fixtures[fixtureSlug(s)]).length
  return (
    <Page>
      <Card
        foot={
          <CardFoot>
            <FootText>
              Reference drawings are in docs/agent-setup/screens. <Link href="/__design">All gallery screens</Link>
            </FootText>
          </CardFoot>
        }
      >
        <CardHead connector={<SingleTile content={{ kind: 'icon', icon: 'bot' }} />} title="Agent setup screens" description={`${built} of ${AGENT_SCREENS.length} render from a fixture.`} />
        {Object.entries(PHASES).map(([phase, name]) => (
          <section class="id-sheet__section">
            <h2 class="id-sheet__heading">{name}</h2>
            <ul class="id-gallery">
              {AGENT_SCREENS.filter((s) => s.phase === Number(phase)).map((s) => {
                const f = fixtures[fixtureSlug(s)]
                const size = `${s.size[0]}×${s.size[1]}`
                return (
                  <li class="id-gallery__row">
                    <span class="id-gallery__id">{s.id}</span>
                    {f ? <a href={`/__design/${s.slug}`}>{s.title}</a> : <span class="id-gallery__missing">{s.kind === 'reference' ? `${s.title} (not built)` : s.title}</span>}
                    <span class="id-gallery__missing">{size}</span>
                    {f ? Object.keys(f.derived).map((st) => <a href={`/__design/${s.slug}?state=${st}`}>{st}</a>) : null}
                  </li>
                )
              })}
            </ul>
          </section>
        ))}
      </Card>
    </Page>
  )
}
