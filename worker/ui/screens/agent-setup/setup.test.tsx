/**
 * The setup page and its states (9a–9h, 11a–11f, 12a–12d): the rules in
 * docs/agent-setup/HANDOFF.md that the drawings can't show.
 */
import { describe, expect, it } from 'vitest'
import type { JSX } from 'hono/jsx/jsx-runtime'
import type { SetupState } from '../../agent-setup/types'
import { setupProps as P } from '../../gallery/fixtures/setup'
import { renderHtml } from '../../render'
import { AgentCard } from './AgentCard'
import { SetupApprove } from './SetupApprove'
import { SETUP_CONNECTOR, SetupPage, setupStatus, stepWhen } from './SetupPage'

async function dom(el: JSX.Element): Promise<Document> {
  return new DOMParser().parseFromString(await renderHtml(el, { title: 't' }), 'text/html')
}
const text = (d: Document, sel: string) => d.querySelector(sel)?.textContent?.replace(/\s+/g, ' ').trim()
const pages = [P.running, P.needsYou, P.stalled, P.live, P.callFailed, P.declined, P.noCard, P.liveWarn, P.cancelled, P.second, P.paused]

describe('the state table (HANDOFF.md section 4)', () => {
  it('maps every setup state to its connector; X only for what has ended or been refused', () => {
    const expected: Record<SetupState, string> = {
      awaiting_approval: 'idle',
      rejected: 'fail',
      running: 'connecting',
      needs_spend_approval: 'hold',
      needs_plan_approval: 'hold',
      needs_person: 'hold',
      needs_payment_method: 'hold',
      needs_bank_confirmation: 'hold',
      needs_wallet_approval: 'hold',
      payment_declined: 'fail',
      call_failing: 'hold',
      stalled: 'hold',
      paused: 'idle',
      in_review: 'idle',
      cancelled: 'fail',
      live: 'ok',
      live_with_warning: 'ok',
    }
    expect(SETUP_CONNECTOR).toEqual(expected)
  })
  it('header status: green while running, amber when it needs someone, none when ended or live', () => {
    expect(setupStatus('running')).toEqual({ tone: 'ok', verb: 'Updated' })
    expect(setupStatus('stalled')).toEqual({ tone: 'warn', verb: 'Last seen' })
    for (const s of ['needs_spend_approval', 'needs_payment_method', 'payment_declined', 'call_failing'] as const) expect(setupStatus(s)).toEqual({ tone: 'warn', verb: 'Updated' })
    for (const s of ['awaiting_approval', 'rejected', 'paused', 'in_review', 'cancelled', 'live', 'live_with_warning'] as const) expect(setupStatus(s)).toBeNull()
  })
  it('renders each drawn state with its connector and status', async () => {
    const cases: [typeof P.running, string, string | undefined][] = [
      [P.running, 'connecting', 'Updated 4s ago'],
      [P.needsYou, 'hold', 'Updated 12s ago'],
      [P.stalled, 'hold', 'Last seen 10 min ago'],
      [P.live, 'ok', undefined],
      [P.callFailed, 'hold', 'Updated 20s ago'],
      [P.declined, 'fail', 'Updated 8s ago'],
      [P.noCard, 'hold', 'Updated 12s ago'],
      [P.liveWarn, 'ok', undefined],
      [P.cancelled, 'fail', undefined],
      [P.paused, 'idle', undefined],
    ]
    for (const [props, connector, status] of cases) {
      const d = await dom(<SetupPage {...props} />)
      expect(d.querySelector('.id-conn')!.getAttribute('data-state'), props.title).toBe(connector)
      expect(text(d, '.id-hstatus'), props.title).toBe(status)
    }
  })
})

describe('steps', () => {
  it('a step’s right-hand label: the product’s own, a time when done, the state’s default, none when todo', () => {
    expect(stepWhen({ id: 'a', title: 't', state: 'done', at: '2026-11-22T19:14:02Z' })).toBe('2:14 PM')
    expect(stepWhen({ id: 'a', title: 't', state: 'done', at: '2026-11-22T19:14:02Z', label: 'Nov 22' })).toBe('Nov 22')
    expect(stepWhen({ id: 'a', title: 't', state: 'now' })).toBe('Now')
    expect(stepWhen({ id: 'a', title: 't', state: 'you' })).toBe('Waiting on you')
    expect(stepWhen({ id: 'a', title: 't', state: 'held' })).toBe('Paused')
    expect(stepWhen({ id: 'a', title: 't', state: 'todo' })).toBeUndefined()
  })
  it('renders whatever list the product sends, in order', async () => {
    const d = await dom(<SetupPage {...P.running} />)
    expect([...d.querySelectorAll('[role=listitem] .id-sstep__title')].map((t) => t.firstChild!.textContent)).toEqual(['Agent approved', 'Test key issued', 'First real call', 'Live key', 'Ready for production'])
  })
  it('no screen lets the agent or the person mark a step done', async () => {
    for (const props of pages) {
      const d = await dom(<SetupPage {...props} />)
      for (const b of d.querySelectorAll('[role=list] button, [role=list] input[type=checkbox]')) expect(b.matches('[data-js=copy]'), props.title).toBe(true)
    }
  })
  it('a steps-free setup (cancelled) draws no list and no rule', async () => {
    const d = await dom(<SetupPage {...P.cancelled} />)
    expect(d.querySelector('[role=list]')).toBeNull()
    expect(d.querySelector('.id-rule')).toBeNull()
  })
})

describe('keys and placeholders', () => {
  it('never renders a full key: only the last four characters', async () => {
    for (const props of pages) {
      const html = await renderHtml(<SetupPage {...props} />, { title: 't' })
      expect(html, props.title).not.toMatch(/\b(sk|pk|oai|hly_sk)_[A-Za-z0-9]{8,}/)
    }
    expect(text(await dom(<SetupPage {...P.running} />), '.id-listen__text')).toBe('Listening on test key …a91c')
  })
  it('keeps bracketed placeholders exactly as written', async () => {
    const html = await renderHtml(<SetupPage {...P.running} />, { title: 't' })
    expect(html).toContain('capped at [TEST ALLOWANCE].')
    expect(await renderHtml(<SetupApprove {...P.approve} />, { title: 't' })).toContain('capped at [TEST ALLOWANCE]. Nothing is charged.')
  })
})

describe('9a · approve', () => {
  it('shows who is signed in with Switch, the workspace, and the pays-with line', async () => {
    const d = await dom(<SetupApprove {...P.approve} />)
    expect(text(d, '.id-who .id-namesub__name')).toBe('Bryant Skarda')
    expect(text(d, '.id-who a')).toBe('Switch')
    expect(d.querySelector<HTMLSelectElement>('select[name=workspace]')!.value).toBe('ws_drivly')
    expect(text(d, '.id-payline')).toBe('Pays with Visa ending 4417Change')
    expect(d.querySelector('.id-conn')!.getAttribute('data-state')).toBe('idle')
  })
  it('posts approve or reject; the spending permission is the amber one', async () => {
    const d = await dom(<SetupApprove {...P.approve} />)
    const buttons = [...d.querySelectorAll<HTMLButtonElement>('button[name=decision]')]
    expect(buttons.map((b) => [b.value, b.textContent])).toEqual([['reject', 'Reject'], ['approve', 'Approve agent']])
    expect(d.querySelectorAll('.id-perm__icon--act')).toHaveLength(1)
    expect(text(d, '.id-perm__note')).toBe('Spends real money, up to your limit.')
  })
  it('offers to add a payment method when the workspace has none', async () => {
    const d = await dom(<SetupApprove {...P.approve} payMethod={undefined} />)
    expect(text(d, '.id-payline a')).toBe('Add a payment method')
  })
})

describe('waiting on the person', () => {
  it('9c: the spend limit sits in the step, with the pays-with line, and the action follows it', async () => {
    const d = await dom(<SetupPage {...P.needsYou} />)
    const step = d.querySelector('.id-sstep--you')!
    expect(step.querySelector('select')!.getAttribute('name')).toBe('answer_spend')
    expect(step.querySelector('.id-payline')).not.toBeNull()
    const follow = d.querySelector('[data-js=follow]')!
    expect(follow.getAttribute('data-follow')).toBe('answer_spend')
    expect(follow.textContent!.trim()).toBe('Approve $500/month')
  })
  it('11b and 11c send the person to add a card (19a), not away to billing', async () => {
    for (const props of [P.declined, P.noCard]) {
      const d = await dom(<SetupPage {...props} />)
      expect(d.querySelector('.id-btn--primary')!.getAttribute('href')).toBe('/payment-methods/new')
    }
    expect(text(await dom(<SetupPage {...P.noCard} />), '.id-foottext')).toBe('The card fields are Stripe’s. id.org.ai never sees the number.')
  })
  it('11d warns and never holds back the key: the live key step is done', async () => {
    const d = await dom(<SetupPage {...P.liveWarn} />)
    const steps = [...d.querySelectorAll('[role=listitem]')]
    expect(steps[3]!.className).toContain('id-sstep--done')
    expect(steps[4]!.className).toContain('id-sstep--you')
    expect(text(d, '.id-sstep--you .id-sstep__when')).toBe('Needs a fix')
  })
})

describe('decision cards', () => {
  it('12b follows 5b: agent left, id.org.ai right, a countdown in the header', async () => {
    const d = await dom(<AgentCard {...P.limitRaise} />)
    expect(d.querySelector('.id-header [data-js=countdown]')).not.toBeNull()
    const tiles = [...d.querySelectorAll('.id-conn .id-tile')]
    expect(tiles[0]!.querySelector('.id-mark')).toBeNull()
    expect(tiles[1]!.querySelector('.id-mark')).not.toBeNull()
    expect(d.querySelector('[data-js=follow]')!.getAttribute('data-template')).toBe('Raise to {label}')
  })
  it('11e: a rejected agent gets the X and no actions', async () => {
    const d = await dom(<AgentCard {...P.rejected} />)
    expect(d.querySelector('.id-conn')!.getAttribute('data-state')).toBe('fail')
    expect(d.querySelectorAll('.id-btn')).toHaveLength(0)
  })
})

describe('every page', () => {
  it('has one h1 and no inline styles', async () => {
    for (const props of pages) {
      const html = await renderHtml(<SetupPage {...props} />, { title: 't' })
      expect(html).not.toMatch(/\sstyle=/i)
      const d = new DOMParser().parseFromString(html, 'text/html')
      expect(d.querySelectorAll('h1')).toHaveLength(1)
    }
  })
})
