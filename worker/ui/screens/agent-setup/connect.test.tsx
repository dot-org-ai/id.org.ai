/** Connect from Claude (24a–24c): the rules in docs/agent-setup/HANDOFF.md sections 3, 5 and 6. */
import { describe, expect, it } from 'vitest'
import type { JSX } from 'hono/jsx/jsx-runtime'
import { AUTO_DEV_PRICING, connectFixtures, connectProps as P } from '../../gallery/fixtures/connect'
import { AGENT_SCREENS, fixtureSlug } from '../../gallery/agent-setup-index'
import { fixtures } from '../../gallery/fixtures'
import { renderHtml } from '../../render'
import { AgentCard } from './AgentCard'
import { chargeSummary, ConnectPay, ConnectPlan, planCards, trialLine } from './Connect'

async function dom(el: JSX.Element): Promise<Document> {
  return new DOMParser().parseFromString(await renderHtml(el, { title: 't' }), 'text/html')
}
const text = (el: Element | null | undefined) => el?.textContent?.replace(/\s+/g, ' ').trim()
const growth = AUTO_DEV_PRICING.plans[1]!

describe('24a · pick a plan', () => {
  it('everything comes from the product: the recommended plan is selected and open, the rest closed', () => {
    const cards = planCards(AUTO_DEV_PRICING.plans)
    expect(cards.map((c) => [c.name, c.price, c.priceYearly, c.selected, c.open])).toEqual([
      ['Free', '$0', undefined, false, false],
      ['Growth', '$299', '$249', true, true],
      ['Scale', '$599', '$499', false, false],
    ])
    expect(planCards(AUTO_DEV_PRICING.plans, 'scale').map((c) => c.selected)).toEqual([false, false, true])
  })
  it('the footer line shows only when the product has a trial', async () => {
    expect(trialLine(AUTO_DEV_PRICING.plans)).toBe('Growth and Scale start with 7 days for $1.')
    expect(trialLine([growth])).toBe('Growth starts with 7 days for $1.')
    expect(trialLine(AUTO_DEV_PRICING.plans.map((p) => ({ ...p, trial: undefined })))).toBeNull()
    const none = connectFixtures['24a-connect-plan']!.derived['no-trial']!
    const d = new DOMParser().parseFromString(await renderHtml(none.render(), { title: 't' }), 'text/html')
    expect(d.querySelector('.id-foottext')).toBeNull()
    expect(d.querySelector('.id-billing')).toBeNull() // no yearly price, so no billing toggle
  })
  it('shows who is signed in with Switch, and the action names the selected plan', async () => {
    const d = await dom(<ConnectPlan {...P.plan} />)
    expect(text(d.querySelector('.id-who a'))).toBe('Switch')
    expect(text(d.querySelector('.id-btn--primary'))).toBe('Continue with Growth')
    expect(d.querySelector('[data-js=follow]')!.getAttribute('data-follow')).toBe('plan')
    expect([...d.querySelectorAll('.id-conn .id-tile')].map((t) => t.textContent)).toEqual(['Cl', 'Ad'])
  })
  it('a free plan has no price note', async () => {
    const d = await dom(<ConnectPlan {...P.plan} />)
    const [free, paid] = [...d.querySelectorAll('.id-plan')]
    expect(free!.querySelector('.id-plan__note')).toBeNull()
    expect(text(paid!.querySelector('.id-plan__note'))).toBe('/month + data fees')
  })
})

describe('24b · subscribe and connect', () => {
  it('the summary changes with the plan: with a trial, and without one', () => {
    expect(chargeSummary({ plan: growth, trialEnds: 'Nov 29', feesNote: 'Per call, billed monthly' })).toEqual([
      ['Today', '$1.00 for 7 days'],
      ['From Nov 29', '$299.00/month'],
      ['Data fees', 'Per call, billed monthly'],
    ])
    expect(chargeSummary({ plan: { ...growth, trial: undefined }, feesNote: 'Per call, billed monthly' })).toEqual([
      ['Today', '$299.00'],
      ['Data fees', 'Per call, billed monthly'],
    ])
  })
  it('one button, behind the terms line; the first permission is amber because it spends', async () => {
    const d = await dom(<ConnectPay {...P.pay} />)
    expect(d.querySelector('.id-card__foot')!.firstElementChild!.matches('label.id-check--terms')).toBe(true)
    expect(d.querySelector('.id-btn--primary')!.hasAttribute('data-needs-terms')).toBe(true)
    const perms = [...d.querySelectorAll('.id-perm')]
    expect(perms[0]!.querySelector('.id-perm__icon--act')).not.toBeNull()
    expect(perms[1]!.querySelector('.id-perm__icon--act')).toBeNull()
    expect(text(perms[0]!.querySelector('.id-perm__note'))).toBe('Spends real money as it’s used.')
  })
  it('loads with the terms line unticked, the limit at No limit and alerts on', async () => {
    const d = await dom(<ConnectPay {...P.pay} termsChecked={false} />)
    expect(d.querySelector<HTMLInputElement>('input[data-terms]')!.checked).toBe(false)
    expect(d.querySelector<HTMLSelectElement>('select[name=spend_limit]')!.value).toBe('none')
    expect(d.querySelector<HTMLInputElement>('input[name=spend_alerts]')!.checked).toBe(true)
    expect(text(d.querySelector('#connect-limit-help'))).toBe('On top of the $299 plan. Past a limit, calls are refused until next month.')
  })
  it('posts the plan and billing period with the subscription', async () => {
    const d = await dom(<ConnectPay {...P.pay} />)
    expect(d.querySelector<HTMLInputElement>('input[name=plan]')!.value).toBe('growth')
    expect(d.querySelector<HTMLInputElement>('input[name=billing]')!.value).toBe('monthly')
    expect(d.querySelector('.id-btn--secondary')!.getAttribute('href')).toBe('/connect/claude/plan')
  })
})

describe('24c · connected', () => {
  it('"Back to Claude" performs the redirect; the dashboard opens in a new tab so this tab can finish', async () => {
    const d = await dom(<AgentCard {...P.done} />)
    const [back, dash] = [...d.querySelectorAll('.id-actions a')]
    expect(text(back)).toBe('Back to Claude')
    expect(back!.getAttribute('href')).toMatch(/^https:\/\/claude\.ai\/api\/mcp\/auth_callback\?/)
    expect(back!.getAttribute('target')).toBeNull()
    expect(dash!.getAttribute('target')).toBe('_blank')
    expect(dash!.getAttribute('rel')).toBe('noopener noreferrer')
    expect(d.querySelector('.id-conn')!.getAttribute('data-state')).toBe('ok')
  })
})

describe('every screen', () => {
  it('every screen except the terminal reference renders from a fixture', () => {
    const missing = AGENT_SCREENS.filter((s) => s.kind !== 'reference' && !fixtures[fixtureSlug(s)]).map((s) => s.id)
    expect(missing).toEqual([])
    expect(AGENT_SCREENS.filter((s) => s.kind === 'reference').map((s) => s.id)).toEqual(['9i'])
  })
})
