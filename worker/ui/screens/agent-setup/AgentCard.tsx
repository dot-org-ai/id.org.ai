/**
 * One card that asks for, or reports, one decision about an agent or its
 * money (docs/agent-setup): remove, pause, a higher limit, an expiry, a
 * rejected or cancelled setup, a single purchase, a charge. The fixture names
 * the tiles, the connector, and the blocks in order.
 */
import type { JSX } from 'hono/jsx/jsx-runtime'
import { rich, type Rich } from '../../agent-setup/rich'
import { Card, CardFoot, CardHead, Connector, Countdown, FootNote, Page, SingleTile, type ConnectorState, type TileContent } from '../../components'
import type { IconName } from '../../icons'
import { Blocks, Foot, footPosts, type Block, type FootProps } from './blocks'

export interface AgentCardProps {
  /** Two tiles and the connector between them, or one tile (10a, 20a). */
  tiles: { left: TileContent; right: TileContent; connector: ConnectorState } | { single: TileContent }
  title: string
  description: Rich
  blocks: Block[]
  foot?: FootProps
  /** One quiet, centred line on the page under the card, outside it (19a: whose card fields these are). */
  under?: { icon: IconName; text: string }
  /** A request that expires (12b, 19c, 19d): the header countdown, as on 5b. */
  secondsLeft?: number
  action?: string
  csrf?: string
}

export function AgentCard(p: AgentCardProps): JSX.Element {
  const head = 'single' in p.tiles ? <SingleTile content={p.tiles.single} /> : <Connector left={p.tiles.left} right={p.tiles.right} state={p.tiles.connector} />
  const hasFoot = p.foot && (p.foot.primary || p.foot.secondary || p.foot.note || p.foot.terms)
  const card = (
    <Card
      foot={
        hasFoot ? (
          <CardFoot>
            <Foot {...p.foot} />
          </CardFoot>
        ) : undefined
      }
    >
      <CardHead connector={head} title={p.title} description={rich(p.description)} />
      <Blocks blocks={p.blocks} />
    </Card>
  )
  return (
    <Page headerRight={p.secondsLeft !== undefined ? <Countdown secondsLeft={p.secondsLeft} urgent /> : undefined}>
      {p.foot && footPosts(p.foot) ? (
        <form class="id-form" method="post" action={p.action ?? ''}>
          <input type="hidden" name="csrf" value={p.csrf ?? ''} />
          {card}
        </form>
      ) : (
        card
      )}
      {p.under ? (
        <div class="id-undercard">
          <FootNote icon={p.under.icon}>{p.under.text}</FootNote>
        </div>
      ) : null}
    </Page>
  )
}
