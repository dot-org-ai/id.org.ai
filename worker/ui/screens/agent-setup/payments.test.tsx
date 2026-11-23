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
    // Whose fields they are is said once, with a lock, under the buttons.
    expect(box.textContent).not.toContain('id.org.ai never sees')
    expect(text(d.querySelector('.id-card__foot .id-footnote'))).toBe('The card fields are Stripe’s. id.org.ai never sees your payment information.')
    // Inside the card, a dotted rule sets the fields apart from the choice under them.
    expect(box.nextElementSibling!.matches('.id-rule')).toBe(true)
    expect(box.nextElementSibling!.nextElementSibling!.matches('label.id-check')).toBe(true)
  })
  it('says each thing once: who charges (description), the choice and that it can change (checkbox), whose fields (foot)', async () => {
    const d = await dom(<AgentCard {...P.payAdd} />)
    const card = text(d.querySelector('.id-card'))!
    const count = (phrase: RegExp) => (card.match(phrase) ?? []).length
    expect(text(d.querySelector('.id-desc'))).toBe('For Drivly. Agents you approve charge it, inside the limits you set.')
    expect(count(/inside (the|their) limit/g)).toBe(1)
    expect(count(/agents you approve/gi)).toBe(1)
    expect(text(d.querySelector('.id-check__sub'))).toBe('Change this or remove the method anytime in Payment methods.')
    expect(count(/anytime/g)).toBe(1)
    expect(count(/never sees/g)).toBe(1)
    expect(card).not.toContain('By saving')
  })
  it('leaves the consent for charging later to Stripe’s own mandate, which the element must keep showing', async () => {
    const { STRIPE_APPEARANCE } = await import('../../components/StripeFields')
    expect(JSON.stringify(STRIPE_APPEARANCE)).not.toContain('"terms"')
    const { readFileSync } = await import('node:fs')
    const script = readFileSync('worker/ui/client/lib/stripe-fields.ts', 'utf8')
    expect(script).toContain("elements.create('payment', { layout: 'tabs', ...(name && { business: { name } }) })")
    expect(script).not.toMatch(/terms\s*:/)
  })
  it('leaves the method tabs to Stripe: none of our own, and the picture shows where Stripe draws them', async () => {
    const d = await dom(<AgentCard {...P.payAdd} />)
    expect(d.querySelectorAll('input[type=radio]')).toHaveLength(0)
    const tabs = [...d.querySelectorAll('.id-stripe__picture .id-stripe__tab')]
    expect(tabs.map((t) => t.textContent)).toEqual(['Card', 'US bank account'])
    expect(tabs[0]!.className).toContain('id-stripe__tab--on')
    // As Stripe draws them: an icon over the label.
    expect(tabs.every((t) => t.querySelector('svg'))).toBe(true)
    expect(tabs[0]!.closest('[aria-hidden=true]')).not.toBeNull()
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
    // One action for now: the receipt. A refund request isn't offered.
    expect([...d.querySelectorAll('.id-card__foot .id-btn')].map((b) => text(b))).toEqual(['View receipt'])
    expect(d.querySelector('[data-actions]')).toBeNull()
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
  it('21a: pay per call has three steps and no plan; calls are billed monthly, never charged one by one', async () => {
    const d = await dom(<SetupPage {...P.payPerCall} />)
    expect([...d.querySelectorAll('.id-sstep__title')].map((t) => t.firstChild!.textContent)).toEqual(['Agent approved', 'First paid call', 'Ready for production'])
    expect(text(d.querySelector('.id-desc'))).toBe('No plan to pick. Claude Code pays only for the calls it makes, billed monthly.')
    expect([...d.querySelectorAll('.id-well .id-kv')].map((r) => text(r))).toEqual(['Price[PRICE]/call', 'BilledMonthly, for the calls made', 'Pays withVisa ending 4417', 'Spend limit$500/month'])
    expect(d.body.textContent).not.toMatch(/call was the payment|carries its own payment|stablecoin|USDC|wallet/i)
  })
  it('21b: the approval is in Link, which opens in a new tab so this page can finish', async () => {
    const d = await dom(<SetupPage {...P.payWallet} />)
    const open = d.querySelector('.id-btn--primary')!
    expect(open.getAttribute('target')).toBe('_blank')
    expect(open.getAttribute('rel')).toBe('noopener noreferrer')
  })
  it('21b: Link’s other answers each get a state: denied (X), ran out (ask again), needs the person (Link’s words)', async () => {
    const f = paymentFixtures['21b-pay-wallet']!.derived
    const render = async (k: string) => new DOMParser().parseFromString(await renderHtml(f[k]!.render(), { title: 't' }), 'text/html')
    const denied = await render('denied')
    expect(denied.querySelector('.id-conn')!.getAttribute('data-state')).toBe('fail')
    expect(text(denied.querySelector('.id-sstep--fail .id-sstep__when'))).toBe('Denied')
    const expired = await render('expired')
    expect(expired.querySelector('.id-conn')!.getAttribute('data-state')).toBe('hold')
    expect(text(expired.querySelector('.id-sstep--you .id-sstep__when'))).toBe('Ran out')
    expect(text(expired.querySelector('.id-btn--primary'))).toBe('Ask Link again')
    const action = await render('needs-action')
    expect(text(action.querySelector('.id-sstep--you .id-sstep__when'))).toBe('Link needs you')
    expect(action.querySelector('.id-btn--primary')!.getAttribute('href')).toMatch(/^https:\/\/app\.link\.com\/activity\/approve\//)
  })
  it('21b: the waiting step says when Link’s request runs out', async () => {
    const d = await dom(<SetupPage {...P.payWallet} />)
    expect(text(d.querySelector('.id-sstep--you .id-sstep__detail'))).toBe('Link is asking you to approve $299. The request runs out at 2:46 PM.')
  })
  it('22b: Stripe’s due date is the step’s label', async () => {
    const d = await dom(<SetupPage {...P.payoutMore} />)
    expect(text(d.querySelector('.id-sstep--you .id-sstep__when'))).toBe('Due [DATE]')
    expect(text(d.querySelector('.id-hstatus'))).toBe('Updated 1 min ago')
  })
})

describe('tax, when the seller charges it', () => {
  it('24b lists it in the charge summary before the person agrees; with none, there is no row', async () => {
    const { chargeSummary } = await import('./Connect')
    const { AUTO_DEV_PRICING } = await import('../../gallery/fixtures/connect')
    const plan = AUTO_DEV_PRICING.plans[1]!
    expect(chargeSummary({ plan, trialEnds: 'Nov 29', feesNote: 'Per call, billed monthly', tax: '$24.67/month, Florida sales tax' }).at(-1)).toEqual(['Tax', '$24.67/month, Florida sales tax'])
    expect(chargeSummary({ plan, trialEnds: 'Nov 29', feesNote: 'Per call, billed monthly' }).map(([k]) => k)).not.toContain('Tax')
  })
  it('19c can show tax and a total for one purchase', async () => {
    const f = paymentFixtures['19c-pay-once']!.derived['with-tax']!
    const d = new DOMParser().parseFromString(await renderHtml(f.render(), { title: 't' }), 'text/html')
    expect([...d.querySelectorAll('.id-well .id-kv__key')].map((k) => k.textContent)).toEqual(['Buying', 'From', 'Price', 'Tax', 'Total', 'Left this month'])
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
