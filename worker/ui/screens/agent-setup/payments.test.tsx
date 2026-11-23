/** Paying (19a–22c): the rules in docs/agent-setup/HANDOFF.md section 6 and STRIPE.md that the drawings can't show. */
import { describe, expect, it } from 'vitest'
import type { JSX } from 'hono/jsx/jsx-runtime'
import { paymentFixtures } from '../../gallery/fixtures/payments'
import { paymentProps as P } from '../../gallery/fixtures/payments'
import { renderHtml } from '../../render'
import { AgentCard } from './AgentCard'
import { SetupPage } from './SetupPage'

async function dom(el: JSX.Element): Promise<Document> {
  return new DOMParser().parseFromString(await renderHtml(el, { title: 't' }), 'text/html')
}
const text = (el: Element | null | undefined) => el?.textContent?.replace(/\s+/g, ' ').trim()

describe('19a · add a payment method', () => {
  it('card details never touch id.org.ai: Stripe’s mount point, and no input of ours', async () => {
    const d = await dom(<AgentCard {...P.payAdd} />)
    const box = d.querySelector('[data-js=stripe-fields]')!
    expect(box.querySelectorAll('input, select, textarea')).toHaveLength(0)
    expect(text(box.querySelector('.id-stripe__note'))).toBe('These fields are Stripe’s. id.org.ai never sees your card number.')
  })
  it('keeps the consent sentence whole', async () => {
    const d = await dom(<AgentCard {...P.payAdd} />)
    expect(text(d.querySelector('.id-foottext'))).toBe('By saving, you let agents you approve for Drivly charge this card inside the limits you set. Remove it anytime.')
  })
  it('offers Card, Bank account and Link, with Card selected', async () => {
    const d = await dom(<AgentCard {...P.payAdd} />)
    expect([...d.querySelectorAll<HTMLInputElement>('input[name=method_type]')].map((r) => [r.value, r.checked])).toEqual([
      ['card', true],
      ['bank', false],
      ['link', false],
    ])
  })
})

describe('19b · a plan plus usage', () => {
  it('shows the plan and its data fees, then the per-API limit (default none) and alerts (on)', async () => {
    const d = await dom(<SetupPage {...P.planUsage} />)
    const step = d.querySelector('.id-sstep--you')!
    expect(text(step.querySelector('.id-well .id-kv'))).toBe('Growth$299/month')
    expect(step.querySelectorAll('.id-rates .id-kv')).toHaveLength(3)
    expect(step.querySelector<HTMLSelectElement>('select[name=spend_limit]')!.value).toBe('none')
    expect(step.querySelector<HTMLInputElement>('input[name=spend_alerts]')!.checked).toBe(true)
    expect(step.querySelector('.id-payline')).not.toBeNull()
    expect(d.querySelector('.id-conn')!.getAttribute('data-state')).toBe('hold')
  })
  it('loads with the terms line unticked; the primary action waits for it', async () => {
    const unticked = paymentFixtures['19b-pay-plan-usage']!.derived['unticked']!
    const d = new DOMParser().parseFromString(await renderHtml(unticked.render(), { title: 't' }), 'text/html')
    expect(d.querySelector<HTMLInputElement>('input[data-terms]')!.checked).toBe(false)
    expect(d.querySelector('.id-btn--primary')!.hasAttribute('data-needs-terms')).toBe(true)
    expect(d.querySelector('.id-btn--secondary')!.hasAttribute('data-needs-terms')).toBe(false)
  })
  it('the terms line sits at the top of the action band, above the buttons', async () => {
    const d = await dom(<SetupPage {...P.planUsage} />)
    const foot = d.querySelector('.id-card__foot')!
    expect(foot.firstElementChild!.matches('label.id-check--terms')).toBe(true)
    expect([...foot.querySelectorAll('.id-check--terms a')].map((a) => a.getAttribute('href'))).toEqual(['https://www.auto.dev/terms', 'https://www.auto.dev/privacy'])
  })
  it('renders the alerts row alone, or the limit alone, when that is all the API offers', async () => {
    const f = paymentFixtures['19b-pay-plan-usage']!.derived
    const alerts = new DOMParser().parseFromString(await renderHtml(f['alerts-only']!.render(), { title: 't' }), 'text/html')
    expect(alerts.querySelector('select[name=spend_limit]')).toBeNull()
    expect(alerts.querySelector('.id-alerts')).not.toBeNull()
    const limit = new DOMParser().parseFromString(await renderHtml(f['limit-only']!.render(), { title: 't' }), 'text/html')
    expect(limit.querySelector('.id-alerts')).toBeNull()
    expect(limit.querySelector('select[name=spend_limit]')).not.toBeNull()
  })
})

describe('two kinds of limit, never merged', () => {
  it('the agent limit (19g) and the per-API spend limit (19b) are different fields', async () => {
    const agent = await dom(<AgentCard {...P.limitReached} />)
    expect(agent.querySelector('select[name=limit]')).not.toBeNull()
    expect(agent.querySelector('select[name=spend_limit]')).toBeNull()
    const api = await dom(<SetupPage {...P.planUsage} />)
    expect(api.querySelector('select[name=spend_limit]')).not.toBeNull()
    expect(api.querySelector('select[name=limit]')).toBeNull()
  })
  it('19g: the bar is full and amber, and the action follows the new limit', async () => {
    const d = await dom(<AgentCard {...P.limitReached} />)
    expect(d.querySelector('.id-bar')!.className).toContain('id-bar--full')
    expect(text(d.querySelector('[data-js=follow]'))).toBe('Raise to $750')
    expect(d.querySelector('.id-conn')!.getAttribute('data-state')).toBe('hold')
  })
})

describe('asking the person', () => {
  it('19c: "stop asking" is off by default, and the request expires', async () => {
    const d = await dom(<AgentCard {...P.payOnce} />)
    expect(d.querySelector<HTMLInputElement>('input[name=always_allow]')!.checked).toBe(false)
    expect(d.querySelector('.id-header [data-js=countdown]')).not.toBeNull()
  })
  it('19d: id.org.ai on the left, the fingerprint tile on the right, still', async () => {
    const d = await dom(<AgentCard {...P.stepUp} />)
    const tiles = [...d.querySelectorAll('.id-conn .id-tile')]
    expect(tiles[0]!.querySelector('.id-mark')).not.toBeNull()
    expect(tiles[1]!.querySelector('svg')!.getAttribute('width')).toBe('26')
    expect(d.querySelector('.id-conn')!.getAttribute('data-state')).toBe('idle')
  })
  it('things only a person can do say so, and are never offered to the agent', async () => {
    expect(text((await dom(<SetupPage {...P.confirmBank} />)).querySelector('.id-desc'))).toContain('Claude Code can’t answer for you.')
    expect(text((await dom(<SetupPage {...P.payoutMore} />)).querySelector('.id-desc'))).toContain('An agent can’t send it for you.')
    expect(text((await dom(<SetupPage {...P.payoutSetup} />)).querySelector('.id-desc'))).toContain('Stripe has to hear who gets paid from a person.')
  })
})

describe('19f · a renewal failed after go-live', () => {
  it('holds, with an amber X on the failed try, and the key keeps working', async () => {
    const d = await dom(<SetupPage {...P.renewalFailed} />)
    expect(d.querySelector('.id-conn')!.getAttribute('data-state')).toBe('hold')
    expect(d.querySelector('.id-hstatus')).toBeNull()
    expect(text(d.querySelector('.id-sstep--fail .id-sstep__when'))).toBe('Dec 22')
    expect(text(d.querySelector('.id-foottext'))).toBe('Claude Code keeps working until Dec 29.')
  })
})

describe('20 · money views', () => {
  it('20a: each agent row and each charge row is one link; the two foot actions are quiet', async () => {
    const d = await dom(<AgentCard {...P.spending} />)
    const rows = [...d.querySelectorAll('a.id-moneyrow')]
    expect(rows).toHaveLength(6)
    expect(rows.slice(3).map((r) => r.getAttribute('href'))).toEqual(['/spending/charges/usage_autodev', '/spending/charges/ch_9a2f', '/spending/charges/ch_7c1d'])
    expect(text(d.querySelector('.id-chip'))).toBe('Running')
    expect(d.querySelectorAll('.id-btn--primary')).toHaveLength(0)
    expect([...d.querySelectorAll('.id-bar__fill')].map((b) => b.getAttribute('data-p'))).toEqual(['68', '40', '0'])
  })
  it('id.org.ai shows spend, charges, limits and methods; not calls, logs, invoices or tax', async () => {
    expect(text((await dom(<AgentCard {...P.spending} />)).querySelector('.id-foottext'))).toBe('Calls and logs for each API live in its developer dashboard.')
    expect(text((await dom(<AgentCard {...P.payMethods} />)).querySelector('.id-foottext'))).toBe('Invoices and tax details open in Stripe’s billing portal.')
  })
  it('20c traces a charge to the approval that allowed it', async () => {
    const d = await dom(<AgentCard {...P.charge} />)
    expect([...d.querySelectorAll('.id-group-label')].map((l) => l.textContent)).toEqual(['Allowed by'])
    expect(text(d.querySelectorAll('.id-well')[1]!.querySelector('.id-kv'))).toBe('Your approvalNov 22, 2:14 PM')
  })
  it('20d: four settings and one switch', async () => {
    const d = await dom(<AgentCard {...P.spendRules} />)
    expect([...d.querySelectorAll('select')].map((s) => s.getAttribute('name'))).toEqual(['new_agent_limit', 'ask_over', 'passkey_over', 'who_approves'])
    const sw = d.querySelectorAll<HTMLInputElement>('input[role=switch]')
    expect(sw).toHaveLength(1)
    expect(sw[0]!.checked).toBe(true)
  })
})

describe('21 and 22 · alternate endings and sellers', () => {
  it('21a: pay per call has three steps, no plan and no key', async () => {
    const d = await dom(<SetupPage {...P.payPerCall} />)
    expect([...d.querySelectorAll('.id-sstep__title')].map((t) => t.firstChild!.textContent)).toEqual(['Agent approved', 'First paid call', 'Ready for production'])
    expect(d.body.textContent).toContain('None. Each call carries its own payment.')
  })
  it('21b: the approval is in Link, which opens in a new tab so this page can finish', async () => {
    const d = await dom(<SetupPage {...P.payWallet} />)
    const open = d.querySelector('.id-btn--primary')!
    expect(open.getAttribute('target')).toBe('_blank')
    expect(open.getAttribute('rel')).toBe('noopener noreferrer')
  })
  it('22b: Stripe’s due date is the step’s label', async () => {
    const d = await dom(<SetupPage {...P.payoutMore} />)
    expect(text(d.querySelector('.id-sstep--you .id-sstep__when'))).toBe('Due [DATE]')
    expect(text(d.querySelector('.id-hstatus'))).toBe('Updated 1 min ago')
  })
})

describe('money is written plainly', () => {
  it('"$299/month", never "/mo"; no screen shows a full key', async () => {
    for (const [slug, f] of Object.entries(paymentFixtures)) {
      const html = await renderHtml(f.default.render(), { title: 't' })
      expect(html, slug).not.toMatch(/\/mo\b/)
      expect(html, slug).not.toMatch(/\b(sk|pk|rk)_(live|test)_[A-Za-z0-9]+/)
    }
  })
})
