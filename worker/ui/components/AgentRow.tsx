import type { Child } from 'hono/jsx'
import type { JSX } from 'hono/jsx/jsx-runtime'
import { Icon, type IconName } from '../icons'
import { MiniTile, type MiniTileContent } from './AppTile'
import { KeyValue, type KV } from './KeyValue'
import { Link } from './Link'
import { Chip } from './Pill'

export interface ConnectionRowProps {
  /** "Auto.dev" */
  name: string
  /** "Live · key ends in 4f2a" */
  state: string
  link: { href: string; label: string }
}

/** One product an agent is connected to: its name, a state line, one link. */
export function ConnectionRow({ name, state, link }: ConnectionRowProps): JSX.Element {
  return (
    <div class="id-connrow">
      <span class="id-rowtext id-rowtext--fit">
        <span class="id-line14">{name}</span>
        <span class="id-help">{state}</span>
      </span>
      <Link href={link.href}>{link.label}</Link>
    </div>
  )
}

export interface AgentRowProps {
  tile: MiniTileContent
  name: string
  /** "Setting up", "Paused". */
  chip?: string
  /** "Trusted · active 2 min ago" */
  line: string
  open?: boolean
  facts?: KV[]
  connections?: ConnectionRowProps[]
  /** The Pause and Remove buttons (an Actions row). */
  actions?: Child
  /** "View activity", "Spending". */
  links?: { href: string; label: string }[]
}

/** An agent in "Your agents" (10a): an expandable box. Closed, one row; open, its facts, connections and actions. */
export function AgentRow({ tile, name, chip, line, open, facts = [], connections = [], actions, links = [] }: AgentRowProps): JSX.Element {
  return (
    <details class="id-agentrow" data-x open={open ? true : undefined}>
      <summary class="id-agentrow__summary">
        <MiniTile content={tile} />
        <span class="id-rowtext">
          <span class="id-rowtext__name">
            {name}
            {chip ? <Chip>{chip}</Chip> : null}
          </span>
          <span class="id-rowtext__sub id-rowtext__sub--clip">{line}</span>
        </span>
        <span class="id-chev" data-chev>
          <Icon name="chev_r" size={16} />
        </span>
      </summary>
      <div class="id-agentrow__panel">
        {facts.length ? (
          <div class="id-agentrow__facts">
            {facts.map((f) => (
              <KeyValue {...f} />
            ))}
          </div>
        ) : null}
        {connections.length ? (
          <div class="id-stack id-stack--2">
            <div class="id-group-label">Connected to</div>
            <div>
              {connections.map((c) => (
                <ConnectionRow {...c} />
              ))}
            </div>
          </div>
        ) : null}
        {actions}
        {links.length ? (
          <div class="id-linkrow">
            {links.map((l) => (
              <Link href={l.href}>{l.label}</Link>
            ))}
          </div>
        ) : null}
      </div>
    </details>
  )
}

export interface ActivityRowProps {
  icon: IconName
  text: string
  /** A second line: what it cost, or the request it made (`mono`). */
  more?: string
  mono?: boolean
  /** Money moved: amber icon and second line. */
  money?: boolean
  /** "2:17 PM" */
  when: string
}

/** One thing an agent did (10e): icon, text, an optional second line, the time. */
export function ActivityRow({ icon, text, more, mono, money, when }: ActivityRowProps): JSX.Element {
  return (
    <div class={money ? 'id-activity id-activity--money' : 'id-activity'}>
      <span class="id-activity__icon">
        <Icon name={icon} size={16} />
      </span>
      <span class="id-activity__text">
        <span class="id-line14">{text}</span>
        {more ? <span class="id-activity__more">{mono ? <span class="id-scope">{more}</span> : more}</span> : null}
      </span>
      <span class="id-when">{when}</span>
    </div>
  )
}
