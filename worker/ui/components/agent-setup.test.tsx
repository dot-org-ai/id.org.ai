/**
 * Markup contracts for the agent setup, payment and connect components
 * (docs/agent-setup/HANDOFF.md section 5): real controls, roles and names.
 */
import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import type { JSX } from 'hono/jsx/jsx-runtime'
import { alertsSentence, limitLabel, usd, usdExact } from '../agent-setup/format'
import { renderHtml } from '../render'
import {
  ActivityRow,
  AgentRow,
  Bar,
  Button,
  CallResult,
  Checkbox,
  CompareWell,
  Connector,
  FieldMapRow,
  HeaderStatus,
  Listening,
  PayLine,
  PlanPicker,
  PromptWell,
  SegTabs,
  Spend,
  SpendRow,
  StepItem,
  StepList,
  StripeFields,
  TermsAgree,
  ToggleRow,
  formatAgo,
  type PlanCardProps,
} from '.'

async function dom(el: JSX.Element): Promise<Document> {
  const html = await renderHtml(el, { title: 't' })
  return new DOMParser().parseFromString(html, 'text/html')
}

const css = readFileSync('worker/ui/css/agent-setup.css', 'utf8')
const plans: PlanCardProps[] = [
  { id: 'free', name: 'Free', price: '$0', summary: '1,000 calls a month', included: [{ label: 'Global VIN Decode', value: 'Included' }], selected: false, open: false },
  { id: 'growth', name: 'Growth', price: '$299', priceYearly: '$249', priceNote: '/month + data fees', summary: 'Unlimited calls', included: [{ label: 'Global VIN Decode', value: '$0.0025/call' }, { label: 'MCP server, CLI and SDK' }], selected: true, open: true },
]

describe('money wording', () => {
  it('writes whole dollars without cents, charges with them, and limits as "a month"', () => {
    expect(usd(50000)).toBe('$500')
    expect(usd(4120)).toBe('$41.20')
    expect(usd(100000)).toBe('$1,000')
    expect(usdExact(29900)).toBe('$299.00')
    expect(limitLabel(null)).toBe('No limit')
    expect(limitLabel(10000)).toBe('$100/month')
  })
  it('builds the alerts sentence from the marks', () => {
    expect(alertsSentence([10000, 50000, 100000, 200000, 500000])).toBe('Emails at $100, $500, $1,000, $2,000 and $5,000.')
  })
})

describe('StepList', () => {
  it('is a polite live list of list items; glyphs are decorative and the state is spoken', async () => {
    const d = await dom(
      <StepList label="Setup steps">
        <StepItem state="done" title="Agent approved" when="2:14 PM" detail="Trusted in Drivly." />
        <StepItem state="you" title="Approve spending" when="Waiting on you" tag="apis.email" detail="Inside the limit you set." />
        <StepItem state="todo" title="Live key" />
      </StepList>,
    )
    const list = d.querySelector('[role=list]')!
    expect(list.getAttribute('aria-live')).toBe('polite')
    expect(list.getAttribute('aria-label')).toBe('Setup steps')
    const items = [...d.querySelectorAll('[role=listitem]')]
    expect(items).toHaveLength(3)
    expect(items.map((i) => i.querySelector('.id-sstep__rail')!.getAttribute('aria-hidden'))).toEqual(['true', 'true', 'true'])
    expect(items[0]!.querySelector('.id-sr')!.textContent).toContain('Done')
    expect(items[1]!.querySelector('.id-steptag')!.textContent).toBe('apis.email')
    expect(items[2]!.querySelector('.id-sstep__when')).toBeNull()
  })
  it('has no control that could tick a step', async () => {
    const d = await dom(
      <StepList label="Setup steps">
        <StepItem state="now" title="First real call" when="Now">
          <Listening text="Listening on test key …a91c" elapsed="0:42" />
        </StepItem>
      </StepList>,
    )
    expect(d.querySelectorAll('button, input, a')).toHaveLength(0)
  })
  it('draws no rail after the last step, and a brighter one under a done step', () => {
    expect(css).toMatch(/\.id-sstep:last-child \.id-sstep__line \{\s*display: none/)
    expect(css).toMatch(/\.id-sstep--done \.id-sstep__line \{[^}]*--id-rail-done/)
  })
})

describe('evidence', () => {
  it('CallResult: green for 2xx, amber otherwise, at most three rows', async () => {
    const ok = await dom(<CallResult method="GET" path="/vin/1" status={200} result="212 ms" rows={[['a', '1'], ['b', '2'], ['c', '3'], ['d', '4']]} />)
    expect(ok.querySelector('.id-sdot')!.className).toBe('id-sdot')
    expect(ok.querySelectorAll('.id-kv')).toHaveLength(3)
    expect(ok.querySelector('.id-call__status')!.textContent).toBe('200 · 212 ms')
    const bad = await dom(<CallResult method="GET" path="/vin/1" status={400} result="INVALID_VIN_FORMAT" />)
    expect(bad.querySelector('.id-sdot')!.className).toContain('id-sdot--warn')
  })
  it('PromptWell copies exactly the text it shows', async () => {
    const d = await dom(<PromptWell label="Paste this to Claude Code" text="Follow [AGENT GUIDE URL]." />)
    expect(d.querySelector('[data-js=copy]')!.getAttribute('data-value')).toBe('Follow [AGENT GUIDE URL].')
    expect(d.querySelector('.id-prompt__text')!.textContent).toBe('Follow [AGENT GUIDE URL].')
  })
  it('CompareWell marks a running row; FieldMapRow labels its select', async () => {
    const c = await dom(<CompareWell rows={[{ name: 'Decode a VIN', text: '250 of 250 match', state: 'ok' }, { name: 'Search', text: '181 of 250 so far', state: 'running' }]} />)
    expect([...c.querySelectorAll('.id-sdot')].map((x) => x.className)).toEqual(['id-sdot', 'id-sdot id-sdot--busy'])
    const m = await dom(<FieldMapRow id="m1" name="map" column="lead_src" options={['Source', 'Skip this column']} value="Source" />)
    expect(m.querySelector('label[for=m1]')!.textContent).toBe('lead_src goes to')
    expect(m.querySelector<HTMLSelectElement>('select#m1')!.value).toBe('Source')
  })
})

describe('header status and connector hold', () => {
  it('HeaderStatus renders the server figure and the hook ago.ts ticks', async () => {
    const d = await dom(<HeaderStatus tone="warn" verb="Last seen" seconds={600} />)
    const el = d.querySelector('[data-js=ago]')!
    expect(el.getAttribute('data-seconds')).toBe('600')
    expect(el.querySelector('[data-ago-text]')!.textContent).toBe('Last seen 10 min ago')
    expect(formatAgo(4)).toBe('4s ago')
  })
  it('hold keeps the dots still and turns the middle one amber', async () => {
    const d = await dom(<Connector left={{ kind: 'icon', icon: 'bot' }} right={{ kind: 'monogram', text: 'Ad' }} state="hold" />)
    expect(d.querySelector('.id-conn')!.getAttribute('data-state')).toBe('hold')
    expect(css).toMatch(/\.id-conn\[data-state='hold'\] \.id-conn__dot--2 \{\s*background: var\(--id-accent\)/)
    expect(css).not.toMatch(/data-state='hold'[^{]*\{[^}]*animation/)
  })
})

describe('PlanPicker', () => {
  it('is a radio group with a legend; the disclosure is a separate button', async () => {
    const d = await dom(<PlanPicker name="plan" plans={plans} />)
    const group = d.querySelector('fieldset.id-plans__list')!
    expect(group.querySelector('legend')!.textContent).toBe('Plan')
    const radios = [...group.querySelectorAll<HTMLInputElement>('input[type=radio][name=plan]')]
    expect(radios.map((r) => r.checked)).toEqual([false, true])
    const more = [...group.querySelectorAll('button[data-js=disclose]')]
    expect(more).toHaveLength(2)
    for (const b of more) {
      expect(b.getAttribute('type')).toBe('button')
      expect(b.closest('label')).toBeNull() // pressing it can't change the selection
      expect(d.getElementById(b.getAttribute('aria-controls')!)).not.toBeNull()
    }
    expect(more.map((b) => b.getAttribute('aria-expanded'))).toEqual(['false', 'true'])
    expect(d.getElementById('plan-free-included')!.hasAttribute('hidden')).toBe(true)
    expect(d.getElementById('plan-growth-included')!.hasAttribute('hidden')).toBe(false)
  })
  it('billing defaults to Monthly and each card carries both prices', async () => {
    const d = await dom(<PlanPicker name="plan" plans={plans} />)
    expect(d.querySelector<HTMLInputElement>('[data-billing=monthly]')!.checked).toBe(true)
    expect(d.querySelector<HTMLInputElement>('[data-billing=yearly]')!.checked).toBe(false)
    const growth = d.querySelectorAll('.id-plan')[1]!
    expect(growth.querySelector('[data-price=monthly]')!.textContent).toBe('$299')
    expect(growth.querySelector('[data-price=yearly]')!.textContent).toBe('$249')
    expect(css).toMatch(/\.id-plans \[data-price='yearly'\]/)
  })
  it('the primary label carries the template follow.ts fills', async () => {
    const d = await dom(<Button variant="primary" follows={{ control: 'plan', template: 'Continue with {label}' }}>Continue with Growth</Button>)
    const label = d.querySelector('[data-js=follow]')!
    expect(label.getAttribute('data-follow')).toBe('plan')
    expect(label.getAttribute('data-template')).toBe('Continue with {label}')
    const picker = await dom(<PlanPicker name="plan" plans={plans} />)
    expect(picker.querySelector('input[name=plan]:checked')!.getAttribute('data-short')).toBe('Growth')
  })
})

describe('Spend block', () => {
  const marks = [10000, 50000, 100000, 200000, 500000]
  it('SpendLimit defaults to No limit and names the plan price', async () => {
    const d = await dom(<Spend id="s" planPrice="$299" limit={{ options: [null, ...marks], value: null }} />)
    const select = d.querySelector<HTMLSelectElement>('select#s-limit')!
    expect([...select.options].map((o) => o.textContent)).toEqual(['No limit', '$100/month', '$500/month', '$1,000/month', '$2,000/month', '$5,000/month'])
    expect(select.value).toBe('none')
    expect(d.getElementById(select.getAttribute('aria-describedby')!)!.textContent!.trim()).toBe('On top of the $299 plan. Past a limit, calls are refused until next month.')
    expect(d.querySelector('.id-alerts')).toBeNull()
  })
  it('SpendAlerts: the switch and the chevron are separate controls', async () => {
    const d = await dom(<Spend id="s" alerts={{ marks, on: true }} />)
    const sw = d.querySelector<HTMLInputElement>('input[role=switch]')!
    expect(sw.checked).toBe(true)
    expect(d.getElementById(sw.getAttribute('aria-labelledby')!)!.textContent!.trim()).toBe('Spend alerts')
    const chev = d.querySelector('button[data-js=disclose]')!
    expect(chev.closest('label')).toBeNull()
    expect(chev.getAttribute('aria-expanded')).toBe('false')
    const panel = d.getElementById(chev.getAttribute('aria-controls')!)!
    expect(panel.hasAttribute('hidden')).toBe(true)
    expect(panel.textContent!.trim()).toBe('Emails at $100, $500, $1,000, $2,000 and $5,000.')
    expect(d.querySelector('select')).toBeNull() // alerts only: no limit, no helper line
  })
})

describe('TermsAgree', () => {
  it('is an unticked, required checkbox whose links open in a new tab', async () => {
    const d = await dom(<TermsAgree id="t" product="Auto.dev" termsHref="https://www.auto.dev/terms" privacyHref="https://www.auto.dev/privacy" />)
    const box = d.querySelector<HTMLInputElement>('input#t')!
    expect(box.type).toBe('checkbox')
    expect(box.checked).toBe(false)
    expect(box.required).toBe(true)
    const links = [...d.querySelectorAll('a')]
    expect(links.map((a) => a.textContent)).toEqual(['Terms of Service', 'Privacy Policy'])
    for (const a of links) {
      expect(a.getAttribute('target')).toBe('_blank')
      expect(a.getAttribute('rel')).toBe('noopener noreferrer')
    }
    expect(d.querySelector('label')!.textContent!.replace(/\s+/g, ' ').trim()).toBe('I agree to Auto.dev’s Terms of Service and Privacy Policy.')
  })
  it('the primary action is marked to wait for it, and dimmed in CSS until then', async () => {
    const d = await dom(<Button variant="primary" needsTerms>Approve Growth</Button>)
    expect(d.querySelector('button')!.hasAttribute('data-needs-terms')).toBe(true)
    expect(css).toMatch(/\.id-card:has\(\[data-terms\]:not\(:checked\)\) \[data-needs-terms\]/)
  })
  it('refuses a terms link that is not https', async () => {
    const d = await dom(<TermsAgree id="t" product="X" termsHref="javascript:alert(1)" privacyHref="http://x.example/p" />)
    expect([...d.querySelectorAll('a')].map((a) => a.getAttribute('href'))).toEqual(['#', '#'])
  })
})

describe('controls', () => {
  it('ToggleRow is one labelled switch', async () => {
    const d = await dom(<ToggleRow id="r" name="receipts" checked title="Email a receipt for every charge" sub="Sent to bryant@driv.ly." />)
    const sw = d.querySelector<HTMLInputElement>('input[role=switch]')!
    expect(sw.closest('label')!.textContent).toContain('Email a receipt for every charge')
    expect(sw.checked).toBe(true)
  })
  it('SegTabs is a named group of real radios', async () => {
    const d = await dom(<SegTabs legend="Payment method type" name="m" selected="card" options={[{ value: 'card', label: 'Card' }, { value: 'bank', label: 'Bank account' }]} />)
    expect(d.querySelector('legend')!.textContent).toBe('Payment method type')
    expect([...d.querySelectorAll<HTMLInputElement>('input[type=radio]')].map((r) => r.checked)).toEqual([true, false])
  })
  it('a checkbox with a detail keeps one input and two lines', async () => {
    const d = await dom(<Checkbox id="c" name="cancel" detail="Left on, Growth keeps billing.">Also cancel the subscription</Checkbox>)
    expect(d.querySelectorAll('input[type=checkbox]')).toHaveLength(1)
    expect(d.querySelector('.id-check__sub')!.textContent).toBe('Left on, Growth keeps billing.')
  })
  it('small controls get a 44px hit area', () => {
    for (const sel of ['.id-toggle::before', '.id-billing__cell::before', '.id-chevbtn::before']) expect(css).toContain(sel)
  })
})

describe('StripeFields', () => {
  it('holds no card inputs: a mount point and an aria-hidden picture', async () => {
    const d = await dom(<StripeFields />)
    const box = d.querySelector('[data-js=stripe-fields]')!
    expect(box.querySelectorAll('input, select, textarea')).toHaveLength(0)
    expect(box.querySelector('[data-stripe-mount]')).not.toBeNull()
    expect(box.querySelector('.id-stripe__picture')!.getAttribute('aria-hidden')).toBe('true')
    expect(box.textContent).toContain('These fields are Stripe’s. id.org.ai never sees your card number.')
  })
})

describe('agents and money', () => {
  it('PayLine offers to add a method when the workspace has none', async () => {
    const has = await dom(<PayLine method="Visa ending 4417" href="/payment-methods" addHref="/payment-methods/new" />)
    expect(has.querySelector('a')!.textContent).toBe('Change')
    expect(has.querySelector('a')!.getAttribute('href')).toBe('/payment-methods')
    const none = await dom(<PayLine href="/payment-methods" addHref="/payment-methods/new" />)
    expect(none.querySelector('a')!.textContent).toBe('Add a payment method')
    expect(none.querySelector('a')!.getAttribute('href')).toBe('/payment-methods/new')
  })
  it('AgentRow is a native disclosure; ActivityRow turns amber when money moved', async () => {
    const a = await dom(<AgentRow tile={{ kind: 'monogram', text: 'Cx' }} name="Codex" chip="Setting up" line="Sandboxed · this computer" />)
    expect(a.querySelector('details > summary')).not.toBeNull()
    expect(a.querySelector('.id-chip')!.textContent).toBe('Setting up')
    const m = await dom(<ActivityRow icon="card" text="Subscribed to Growth" more="Spent money." money when="2:17 PM" />)
    expect(m.querySelector('.id-activity')!.className).toContain('id-activity--money')
  })
  it('SpendRow is one link; the bar is decorative, clamped, and amber at the limit', async () => {
    const d = await dom(<SpendRow tile={{ kind: 'icon', icon: 'bot' }} name="Claude Code" amount="$600.00" limit="$500" percent={120} line="Auto.dev" href="/agents" />)
    expect(d.querySelectorAll('a')).toHaveLength(1)
    const bar = d.querySelector('.id-bar')!
    expect(bar.getAttribute('aria-hidden')).toBe('true')
    expect(bar.className).toContain('id-bar--full')
    expect(bar.querySelector('.id-bar__fill')!.getAttribute('data-p')).toBe('100')
    const half = await dom(<Bar percent={40.4} />)
    expect(half.querySelector('.id-bar__fill')!.getAttribute('data-p')).toBe('40')
    // Every whole percent has a width rule, since no inline style is allowed.
    for (const pct of [1, 40, 68, 100]) expect(css).toContain(`.id-bar__fill[data-p='${pct}'] {\n  width: ${pct}%;`)
  })
})

describe('no red', () => {
  it('the agent setup styles use amber and green only, through tokens', () => {
    expect(css).not.toMatch(/\bred\b|oklch\(|#[0-9a-f]{3,8}\b|rgba?\(/i)
  })
})
