import type { JSX } from 'hono/jsx/jsx-runtime'
import { Icon } from '../icons'
import { MiniTile, type MiniTileContent } from './AppTile'
import { Link } from './Link'
import { Chip } from './Pill'

/**
 * A 4px bar: how much of a limit is used, to the whole percent. Decorative:
 * the amounts next to it say the same thing. The width comes from `data-p`
 * (one CSS rule per percent), because pages allow no inline style.
 */
export function Bar({ percent, full }: { percent: number; full?: boolean }): JSX.Element {
  const p = Math.round(Math.max(0, Math.min(100, percent)))
  return (
    <div class={full ? 'id-bar id-bar--full' : 'id-bar'} aria-hidden="true">
      <div class="id-bar__fill" data-p={String(p)}></div>
    </div>
  )
}

/** "$340.20 of $500": the amount in mono, the limit dimmer. */
export function Amount({ amount, of }: { amount: string; of?: string }): JSX.Element {
  return (
    <span class="id-amount">
      {amount}
      {of ? <span class="id-amount__of">{` of ${of}`}</span> : null}
    </span>
  )
}

/** The month's total (20a): one large tabular number with one line under it. */
export function Total({ amount, note }: { amount: string; note: string }): JSX.Element {
  return (
    <div class="id-total">
      <span class="id-total__num">{amount}</span>
      <span class="id-total__note">{note}</span>
    </div>
  )
}

export interface SpendRowProps {
  tile: MiniTileContent
  name: string
  amount: string
  limit: string
  /** 0 to 100. */
  percent: number
  /** "Auto.dev", "headless.ly · paused". */
  line: string
  href: string
}

/** Spend by agent (20a): mini tile, name, "amount of limit", the bar, one line. The whole row is a link. */
export function SpendRow({ tile, name, amount, limit, percent, line, href }: SpendRowProps): JSX.Element {
  return (
    <a class="id-moneyrow" href={href}>
      <MiniTile content={tile} />
      <span class="id-spend__main">
        <span class="id-spend__top">
          <span class="id-sstep__title">{name}</span>
          <Amount amount={amount} of={limit} />
        </span>
        <Bar percent={percent} full={percent >= 100} />
        <span class="id-help">{line}</span>
      </span>
    </a>
  )
}

export interface ChargeRowProps {
  name: string
  /** "Running": usage not yet billed. */
  chip?: string
  /** "Nov 22 · Claude Code" */
  line: string
  amount: string
  href: string
}

/** One charge (20a): name with an optional chip, one line, the amount, a chevron. The whole row links to 20c. */
export function ChargeRow({ name, chip, line, amount, href }: ChargeRowProps): JSX.Element {
  return (
    <a class="id-moneyrow id-moneyrow--charge" href={href}>
      <span class="id-rowtext">
        <span class="id-rowtext__name id-rowtext__name--plain">
          {name}
          {chip ? <Chip>{chip}</Chip> : null}
        </span>
        <span class="id-help">{line}</span>
      </span>
      <Amount amount={amount} />
      <span class="id-chev">
        <Icon name="chev_r" size={14} />
      </span>
    </a>
  )
}

export interface MethodRowProps {
  icon: 'card' | 'bank'
  /** "Visa ending 4417" */
  title: string
  /** "Expires 08/28 · charged by 3 agents" */
  sub: string
  /** "Default" */
  chip?: string
  link: { href: string; label: string }
}

/** A saved payment method (20b). */
export function MethodRow({ icon, title, sub, chip, link }: MethodRowProps): JSX.Element {
  return (
    <div class="id-method">
      <span class="id-method__mark">
        <Icon name={icon} size={16} />
      </span>
      <span class="id-rowtext">
        <span class="id-rowtext__name">
          {title}
          {chip ? <Chip>{chip}</Chip> : null}
        </span>
        <span class="id-rowtext__sub">{sub}</span>
      </span>
      <Link href={link.href}>{link.label}</Link>
    </div>
  )
}
