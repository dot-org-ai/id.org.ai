/**
 * Agents screens (5a–5d): the accessibility and form contracts in
 * docs/product-update/prompts/03-screens.md. One h1, every control labelled,
 * forms posting to the spec route with a CSRF field, a status region where
 * states change, and request data escaped. 5a, 5b and 5c stay on id.org.ai
 * (spec/motion.md#where-the-person-goes-next), so their flows run on the real
 * markup through lib/fetch-form.ts with a fake clock and a fake server.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { JSX } from 'hono/jsx/jsx-runtime'
import { renderHtml } from '../render'
import { agentsFixtures, agentsProps } from '../gallery/fixtures/agents'
import { initCountdown } from '../client/lib/countdown'
import { initFetchForm, type FetchDeps } from '../client/lib/fetch-form'
import { FAIL_SWAP_MS, SUCCESS_SWAP_MS } from '../client/lib/connector'
import { ActionApproval } from './ActionApproval'
import { AgentApprove, shortFingerprint } from './AgentApprove'
import { Claim } from './Claim'
import { ClaimRepo } from './ClaimRepo'

const { approve, action, claim, repo } = agentsProps
const EVIL = '<script>alert(1)</script>'

async function render(el: JSX.Element): Promise<{ html: string; doc: Document }> {
  const html = await renderHtml(el, { title: 't' })
  return { html, doc: new DOMParser().parseFromString(html, 'text/html') }
}

/** Every visible form control has an accessible name. */
function expectLabelled(doc: Document): void {
  for (const el of Array.from(doc.querySelectorAll<HTMLElement>('input:not([type="hidden"]), select, textarea'))) {
    const id = el.getAttribute('id')
    const named = el.hasAttribute('aria-label') || (id !== null && doc.querySelector(`label[for="${id}"]`) !== null) || el.closest('label') !== null
    expect(named, `${el.tagName} ${id ?? ''}`).toBe(true)
  }
  for (const b of Array.from(doc.querySelectorAll('button, a'))) {
    const name = b.getAttribute('aria-label') ?? b.textContent?.trim() ?? ''
    expect(name.length, b.outerHTML).toBeGreaterThan(0)
  }
}

function expectForm(doc: Document, route: RegExp): HTMLFormElement {
  const forms = Array.from(doc.querySelectorAll('form'))
  expect(forms.length).toBe(1)
  const form = forms[0]!
  expect(form.getAttribute('method')).toBe('post')
  expect(form.getAttribute('action')).toMatch(route)
  expect(form.querySelector<HTMLInputElement>('input[type="hidden"][name="csrf"]')!.value).toBe('gallery')
  return form
}

const h1s = (doc: Document) => Array.from(doc.querySelectorAll('h1')).map((h) => h.textContent)
const templates = (doc: Document | Element) => Array.from(doc.querySelectorAll('template')).map((t) => t.getAttribute('data-state'))

type Post = FetchDeps['post']
const ok: Post = async () => ({ ok: true })
const flush = () => new Promise((r) => setTimeout(r, 0))

/** Mount a screen's real markup, wire fetch-form.ts with a fake clock and server. */
async function mount(el: JSX.Element, post: Post) {
  const html = await renderHtml(el, { title: 't' })
  document.body.innerHTML = new DOMParser().parseFromString(html, 'text/html').body.innerHTML
  const timers: { fn: () => void; at: number }[] = []
  let now = 0
  const later = (fn: () => void, ms: number) => void timers.push({ fn, at: now + ms })
  const advance = (ms: number) => {
    now += ms
    for (const t of timers.filter((t) => t.at <= now)) {
      timers.splice(timers.indexOf(t), 1)
      t.fn()
    }
  }
  const go = vi.fn()
  const form = document.querySelector<HTMLFormElement>('form[data-js="fetch-form"]')!
  initFetchForm(form, { post, later, go })
  /** Submit through the button that swaps in `done`. */
  const click = (done: string) => {
    const btn = form.querySelector<HTMLButtonElement>(`button[data-done="${done}"]`)!
    form.dispatchEvent(Object.assign(new Event('submit', { bubbles: true, cancelable: true }), { submitter: btn }))
    return btn
  }
  const state = () => document.querySelector('[data-js="connector"]')!.getAttribute('data-state')
  const title = () => document.querySelector('[data-region] h1')!.textContent
  const desc = () => document.querySelector('[data-region] .id-desc')!.textContent
  const foot = () => document.querySelector('[data-region="foot"]')!
  const status = () => form.querySelector('[data-status]')!.textContent
  const buttons = () => Array.from(form.querySelectorAll('button'))
  return { form, click, advance, state, title, desc, foot, status, buttons, go }
}

afterEach(() => {
  document.body.innerHTML = ''
})

describe('every agents fixture', () => {
  const variants = Object.entries(agentsFixtures).flatMap(([slug, f]) => [
    [slug, f.default] as const,
    ...Object.entries(f.states).map(([k, v]) => [`${slug}?state=${k}`, v] as const),
    ...Object.entries(f.derived).map(([k, v]) => [`${slug}?state=${k}`, v] as const),
  ])
  it.each(variants)('%s renders one h1, labelled controls, a status region and no inline style or script', async (_name, v) => {
    const html = await renderHtml(v.render(), { title: v.title })
    expect(html).not.toMatch(/\sstyle=/i)
    expect(html).not.toMatch(/<style[\s>]/i)
    expect(html).not.toMatch(/\son[a-z]+=/i)
    for (const tag of html.match(/<script\b[^>]*>/gi) ?? []) expect(tag).toMatch(/\ssrc="/)
    const doc = new DOMParser().parseFromString(html, 'text/html')
    expect(doc.querySelectorAll('h1').length).toBe(1)
    expectLabelled(doc)
    expect(doc.querySelector('[role="status"]')).toBeTruthy()
  })

  it('loads fetch-form.js (not submit.js) on the screens that stay on id.org.ai', () => {
    for (const slug of ['5a-agent-approve', '5b-action-approval', '5c-claim']) {
      expect(agentsFixtures[slug]!.scripts, slug).toContain('fetch-form.js')
      expect(agentsFixtures[slug]!.scripts, slug).not.toContain('submit.js')
    }
  })

  it('has every result as a state, so the no-JS POST can render it', () => {
    expect(Object.keys(agentsFixtures['5a-agent-approve']!.derived)).toEqual(['approved', 'rejected'])
    expect(Object.keys(agentsFixtures['5b-action-approval']!.derived)).toEqual(['sent', 'denied', 'expired'])
    expect(Object.keys(agentsFixtures['5c-claim']!.derived)).toEqual(['claimed'])
  })
})

describe('5a · Approve an agent', () => {
  it('one h1, labelled controls, posts to /agents/approve/:agentId with csrf and both decisions', async () => {
    const { doc } = await render(<AgentApprove {...approve} />)
    expect(h1s(doc)).toEqual(['Claude Code wants to work as your agent'])
    expectLabelled(doc)
    const form = expectForm(doc, /^\/agents\/approve\/[^/]+$/)
    expect(form.getAttribute('data-js')).toBe('fetch-form')
    const decisions = Array.from(form.querySelectorAll<HTMLButtonElement>('button[name="decision"]')).map((b) => [
      b.type,
      b.value,
      b.textContent,
      b.hasAttribute('data-deny'),
      b.getAttribute('data-done'),
    ])
    expect(decisions).toEqual([
      ['submit', 'reject', 'Reject', true, 'rejected'],
      ['submit', 'approve', 'Approve agent', false, 'approved'],
    ])
    const status = doc.querySelector('[role="status"][data-status]')!
    expect(status.closest('[data-region]')).toBeNull()
  })

  it('carries the approved and rejected bodies and feet as templates beside the regions', async () => {
    const { doc } = await render(<AgentApprove {...approve} />)
    expect(templates(doc.querySelector('.id-card__body')!)).toEqual(['approved', 'rejected'])
    expect(templates(doc.querySelector('.id-card__foot')!)).toEqual(['approved', 'rejected'])
    expect(doc.querySelector('[data-region="body"]')!.parentElement).toBe(doc.querySelector('.id-card__body'))
    expect(doc.querySelector('[data-region="foot"]')!.parentElement).toBe(doc.querySelector('.id-card__foot'))
  })

  it('trust level is a labelled radio group (Trusted checked, Privileged accented); spend and expiry are selects', async () => {
    const { doc } = await render(<AgentApprove {...approve} />)
    expect(doc.querySelector('fieldset > legend')!.textContent).toBe('Trust level')
    const radios = Array.from(doc.querySelectorAll<HTMLInputElement>('input[type="radio"][name="trust_level"]'))
    expect(radios.map((r) => r.value)).toEqual(['sandboxed', 'trusted', 'privileged'])
    expect(radios.filter((r) => r.checked).map((r) => r.value)).toEqual(['trusted'])
    expect(doc.querySelector('label[for="agent-trust-privileged"] .id-accent-dot')).not.toBeNull()
    expect(doc.querySelector<HTMLSelectElement>('select[name="spend_limit"]')!.value).toBe('50')
    expect(doc.querySelector<HTMLSelectElement>('select[name="expires"]')!.value).toBe('30d')
    expect(doc.querySelector('.id-agent-limits')!.querySelectorAll('select').length).toBe(2)
  })

  it('shows the shortened fingerprint in mono and copies the full one', async () => {
    const { doc } = await render(<AgentApprove {...approve} />)
    expect(shortFingerprint(approve.agent.fingerprint)).toBe('7f3a…c21d')
    expect(doc.querySelector('.id-source__value--mono')!.textContent).toBe('ed25519 · 7f3a…c21d')
    expect(doc.querySelector('[data-js="copy"]')!.getAttribute('data-value')).toBe(approve.agent.fingerprint)
  })

  it('approved and rejected also render as pages (no JS): one h1, no buttons or templates, the verdict announced', async () => {
    const ok = (await render(<AgentApprove {...approve} state="approved" />)).doc
    expect(h1s(ok)).toEqual(['Claude Code is now your agent'])
    expect(ok.querySelectorAll('button').length).toBe(0)
    expect(templates(ok)).toEqual([])
    expect(ok.querySelector('.id-conn')!.getAttribute('data-state')).toBe('ok')
    expect(ok.querySelector('.id-desc')!.textContent).toBe('It can start working in Drivly now. You can close this tab.')
    expect(ok.querySelector('.id-desc .id-em')!.textContent).toBe('Drivly')
    // The server knows what was stored, so the page lists the policy.
    expect(Array.from(ok.querySelectorAll('.id-kv')).map((r) => r.textContent)).toEqual(['Trust levelTrusted', 'Spend limit$50 a month', 'ExpiresIn 30 days'])
    expect(ok.querySelector('.id-foottext a')!.getAttribute('href')).toBe('/account/agents')
    expect(ok.querySelector('[role="status"][data-status]')!.textContent).toBe('Claude Code approved.')
    const no = (await render(<AgentApprove {...approve} state="rejected" />)).doc
    expect(h1s(no)).toEqual(['Claude Code wasn’t approved'])
    expect(no.querySelectorAll('button').length).toBe(0)
    expect(no.querySelector('.id-conn')!.getAttribute('data-state')).toBe('fail')
    expect(no.querySelector('.id-foottext')!.textContent).toBe('Rejected by mistake? Ask Claude Code to connect again.')
    expect(no.querySelector('[role="status"][data-status]')!.textContent).toBe('Claude Code rejected.')
  })

  it('escapes request data', async () => {
    const { html } = await render(<AgentApprove {...approve} agent={{ ...approve.agent, name: EVIL, host: EVIL }} workspace={EVIL} />)
    expect(html).not.toContain(EVIL)
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;')
  })
})

describe('5a on fetch-form.ts', () => {
  it('Approve: busy at once, done on the server OK, approved 2150ms later with focus on the new title', async () => {
    let resolve!: (r: { ok: boolean }) => void
    const post = vi.fn<Post>(() => new Promise((r) => (resolve = r)))
    const m = await mount(<AgentApprove {...approve} />, post)
    const btn = m.click('approved')
    expect(m.state()).toBe('connecting')
    expect(btn.getAttribute('aria-busy')).toBe('true')
    expect(btn.textContent).toBe('Approving…')
    expect(m.status()).toBe('Approving…')
    for (const b of m.buttons()) expect(b.disabled).toBe(true)
    expect(post.mock.calls[0]![1]!.value).toBe('approve')
    resolve({ ok: true })
    await flush()
    expect(m.state()).toBe('done')
    m.advance(SUCCESS_SWAP_MS - 1)
    expect(m.title()).toBe('Claude Code wants to work as your agent')
    m.advance(1)
    expect(m.title()).toBe('Claude Code is now your agent')
    expect(m.state()).toBe('ok')
    expect(m.foot().textContent).toBe('Changed your mind? Pause or remove it')
    expect(m.foot().querySelectorAll('button').length).toBe(0)
    // The template was rendered before the person picked, so it names no policy.
    expect(document.querySelector('[data-region="body"] .id-kv')).toBeNull()
    expect(document.activeElement).toBe(document.querySelector('[data-region] h1'))
  })

  it('Reject: broken at once, both disabled, rejected after 1820ms once the server agreed', async () => {
    const post = vi.fn(ok)
    const m = await mount(<AgentApprove {...approve} />, post)
    m.click('rejected')
    expect(m.state()).toBe('broken')
    for (const b of m.buttons()) expect(b.disabled).toBe(true)
    await flush()
    expect(post.mock.calls[0]![1]!.value).toBe('reject')
    m.advance(FAIL_SWAP_MS - 1)
    expect(m.title()).toBe('Claude Code wants to work as your agent')
    m.advance(1)
    expect(m.title()).toBe('Claude Code wasn’t approved')
    expect(m.state()).toBe('fail')
    expect(m.foot().textContent).toBe('Rejected by mistake? Ask Claude Code to connect again.')
  })

  it('leaves at once when the server answers with a redirect (a Privileged agent needs a passkey first)', async () => {
    const m = await mount(<AgentApprove {...approve} />, async () => ({ ok: true, redirect: '/step-up?continue=%2Fagents%2Fapprove%2Fagt_7f3ac21d' }))
    m.click('approved')
    await flush()
    expect(m.go).toHaveBeenCalledWith('/step-up?continue=%2Fagents%2Fapprove%2Fagt_7f3ac21d')
  })

  it('a failure with no template gives the buttons back', async () => {
    const m = await mount(<AgentApprove {...approve} />, async () => ({ ok: false, error: 'server_error' }))
    m.click('approved')
    await flush()
    expect(m.state()).toBe('broken')
    m.advance(FAIL_SWAP_MS)
    expect(m.status()).toBe('Something went wrong. Try again.')
    for (const b of m.buttons()) expect(b.disabled).toBe(false)
  })
})

describe('5b · Approve an action', () => {
  it('one h1, labelled controls, posts to /approvals/:requestId with csrf, deny and approve', async () => {
    const { doc } = await render(<ActionApproval {...action} />)
    expect(h1s(doc)).toEqual(['Susan wants to send an email'])
    expectLabelled(doc)
    const form = expectForm(doc, /^\/approvals\/[^/]+$/)
    expect(form.getAttribute('data-js')).toBe('fetch-form')
    const decisions = Array.from(form.querySelectorAll<HTMLButtonElement>('button[name="decision"]')).map((b) => [b.value, b.hasAttribute('data-deny'), b.getAttribute('data-done')])
    expect(decisions).toEqual([
      ['deny', true, 'denied'],
      ['approve', false, 'sent'],
    ])
    const always = form.querySelector<HTMLInputElement>('input[type="checkbox"][name="always_allow"]')!
    expect(doc.querySelector(`label[for="${always.id}"]`)!.textContent).toBe('Always allow Susan to send renewal emails')
    expect(templates(doc.querySelector('.id-card__foot')!)).toEqual(['sent', 'denied'])
  })

  it('the header counts down; the status region sits inside the form but outside the card, so the expiry is announced after the swap', async () => {
    const { doc } = await render(<ActionApproval {...action} />)
    const cd = doc.querySelector('header [data-js="countdown"]')!
    expect(cd.getAttribute('data-seconds-left')).toBe(String(action.secondsLeft))
    expect(cd.getAttribute('data-expired-template')).toBe('expired')
    expect(cd.hasAttribute('data-announce')).toBe(true)
    expect(cd.getAttribute('data-urgent-at')).toBe('60')
    expect(cd.textContent).toBe('4:32 left')
    const status = doc.querySelector('[role="status"][data-status]')!
    expect(status.closest('.id-card')).toBeNull()
    expect(status.closest('form')).not.toBeNull()
  })

  it('carries the expired template: the 7b error card with the approval copy and the agent’s tile', async () => {
    const { doc } = await render(<ActionApproval {...action} />)
    const tpls = doc.querySelectorAll<HTMLTemplateElement>('template[data-state="expired"]')
    expect(tpls.length).toBe(1)
    // Inside the body region, so a decision swapping in removes it.
    expect(tpls[0]!.parentElement!.getAttribute('data-region')).toBe('body')
    const card = tpls[0]!.content.querySelector('.id-card')!
    expect(card.querySelector('h1')!.textContent).toBe('This request expired')
    expect(card.querySelector('.id-desc')!.textContent).toBe('Unanswered requests expire as a no, so nothing happened. The agent can ask again.')
    expect(card.querySelector('.id-conn')!.getAttribute('data-state')).toBe('fail')
    expect(Array.from(card.querySelectorAll('.id-conn .id-tile')).map((t) => t.textContent)[1]).toBe('Su')
  })

  it('renders the expired card as the expired state, with no form or countdown', async () => {
    const { doc } = await render(<ActionApproval {...action} state="expired" />)
    expect(h1s(doc)).toEqual(['This request expired'])
    expect(doc.querySelector('form')).toBeNull()
    expect(doc.querySelector('[data-js="countdown"]')).toBeNull()
    expect(doc.querySelector('.id-conn')!.getAttribute('data-state')).toBe('fail')
    expect(doc.querySelector('.id-card__foot a.id-btn')!.getAttribute('href')).toBe('/')
  })

  it('sent and denied also render as pages (no JS): no countdown, no buttons, the verdict announced', async () => {
    const sent = (await render(<ActionApproval {...action} state="sent" />)).doc
    expect(h1s(sent)).toEqual(['Sent'])
    expect(sent.querySelector('.id-desc')!.textContent).toBe('Susan sent the email to 412 customers in Q3 renewals.')
    expect(sent.querySelector('.id-desc .id-em')!.textContent).toBe('Susan')
    expect(sent.querySelector('.id-conn')!.getAttribute('data-state')).toBe('ok')
    expect(sent.querySelector('.id-foottext')!.textContent).toBe('You can close this tab.')
    expect(sent.querySelector('[data-js="countdown"]')).toBeNull()
    expect(sent.querySelectorAll('button').length).toBe(0)
    expect(templates(sent)).toEqual([])
    expect(sent.querySelector('[role="status"][data-status]')!.textContent).toBe('Sent.')
    const denied = (await render(<ActionApproval {...action} state="denied" />)).doc
    expect(h1s(denied)).toEqual(['Not sent'])
    expect(denied.querySelector('.id-desc')!.textContent).toBe('Susan won’t send it. Nothing left headless.ly.')
    expect(Array.from(denied.querySelectorAll('.id-desc .id-em')).map((e) => e.textContent)).toEqual(['Susan', 'headless.ly'])
    expect(denied.querySelector('.id-conn')!.getAttribute('data-state')).toBe('fail')
    expect(denied.querySelector('.id-foottext')!.textContent).toBe('Denied by mistake? Susan can ask again from headless.ly.')
    expect(denied.querySelectorAll('button').length).toBe(0)
  })

  it('runs the connector agent → id.org.ai', async () => {
    const { doc } = await render(<ActionApproval {...action} />)
    const tiles = Array.from(doc.querySelectorAll('.id-conn .id-tile'))
    expect(tiles[0]!.textContent).toBe('Su')
    expect(tiles[1]!.querySelector('svg')).not.toBeNull()
  })

  it('escapes request data', async () => {
    const { html } = await render(<ActionApproval {...action} action={{ ...action.action, subject: EVIL, excerpt: EVIL, to: EVIL }} agent={{ ...action.agent, name: EVIL }} alwaysAllowLabel={EVIL} />)
    expect(html).not.toContain(EVIL)
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;')
  })
})

describe('5b on fetch-form.ts and countdown.ts', () => {
  afterEach(() => {
    vi.clearAllTimers()
    vi.useRealTimers()
  })

  it('Approve and send: busy at once, done on the server OK, sent 2150ms later', async () => {
    const post = vi.fn(ok)
    const m = await mount(<ActionApproval {...action} />, post)
    const btn = m.click('sent')
    expect(m.state()).toBe('connecting')
    expect(btn.textContent).toBe('Sending…')
    expect(m.status()).toBe('Sending…')
    await flush()
    expect(post.mock.calls[0]![1]!.value).toBe('approve')
    expect(m.state()).toBe('done')
    m.advance(SUCCESS_SWAP_MS - 1)
    expect(m.title()).toBe('Susan wants to send an email')
    m.advance(1)
    expect(m.title()).toBe('Sent')
    expect(m.state()).toBe('ok')
    expect(m.desc()).toBe('Susan sent the email to 412 customers in Q3 renewals.')
    expect(m.foot().textContent).toBe('You can close this tab.')
    expect(document.activeElement).toBe(document.querySelector('[data-region] h1'))
  })

  it('Deny: broken at once, both disabled, not sent after 1820ms once the server agreed', async () => {
    const post = vi.fn(ok)
    const m = await mount(<ActionApproval {...action} />, post)
    m.click('denied')
    expect(m.state()).toBe('broken')
    for (const b of m.buttons()) expect(b.disabled).toBe(true)
    await flush()
    expect(post.mock.calls[0]![1]!.value).toBe('deny')
    m.advance(FAIL_SWAP_MS - 1)
    expect(m.title()).toBe('Susan wants to send an email')
    m.advance(1)
    expect(m.title()).toBe('Not sent')
    expect(m.state()).toBe('fail')
    expect(m.foot().textContent).toBe('Denied by mistake? Susan can ask again from headless.ly.')
  })

  it('at 0 the countdown swaps the card for the expired error card and announces it outside the card', async () => {
    await mount(<ActionApproval {...action} />, ok)
    vi.useFakeTimers()
    let now = 0
    initCountdown(document.querySelector<HTMLElement>('[data-js="countdown"]')!, () => now)
    now = action.secondsLeft * 1000
    vi.advanceTimersByTime(1000)
    expect(document.querySelectorAll('.id-card').length).toBe(1)
    expect(document.querySelector('.id-card h1')!.textContent).toBe('This request expired')
    expect(document.querySelector('.id-card .id-conn')!.getAttribute('data-state')).toBe('fail')
    const outside = Array.from(document.querySelectorAll('[data-status]')).filter((s) => !s.closest('.id-card'))
    expect(outside.map((s) => s.textContent)).toEqual(['This request expired.'])
  })

  it('once a decision has swapped in, the countdown can no longer replace it', async () => {
    const m = await mount(<ActionApproval {...action} />, ok)
    m.click('sent')
    await flush()
    m.advance(SUCCESS_SWAP_MS)
    expect(m.title()).toBe('Sent')
    expect(document.querySelector('template[data-state="expired"]')).toBeNull()
    vi.useFakeTimers()
    let now = 0
    initCountdown(document.querySelector<HTMLElement>('[data-js="countdown"]')!, () => now)
    now = action.secondsLeft * 1000
    vi.advanceTimersByTime(1000)
    expect(m.title()).toBe('Sent')
    expect(document.querySelectorAll('.id-card').length).toBe(1)
  })
})

describe('5c · Claim agent work', () => {
  it('one h1, labelled controls, posts to /claim/:token with csrf; the repo path is a link to 5d', async () => {
    const { doc } = await render(<Claim {...claim} />)
    expect(h1s(doc)).toEqual(['Claude set up headless.ly for you'])
    expectLabelled(doc)
    const form = expectForm(doc, /^\/claim\/[^/]+$/)
    expect(form.getAttribute('data-js')).toBe('fetch-form')
    const primary = form.querySelector('button[type="submit"]')!
    expect(primary.textContent).toBe('Claim workspace')
    expect(primary.getAttribute('data-done')).toBe('claimed')
    expect(doc.querySelector('a.id-btn')!.getAttribute('href')).toBe('/claim/clm_7Kx9m2/repo')
    expect(Array.from(doc.querySelectorAll('select[name="org_id"] option')).map((o) => o.textContent)).toEqual(['Drivly', '.do Industries', 'New workspace…'])
    const status = doc.querySelector('[role="status"][data-status]')!
    expect(status.closest('[data-region]')).toBeNull()
    expect(templates(doc)).toEqual(['claimed', 'claimed'])
  })

  it('claimed also renders as a page (no JS): the connector at ok, the workspace named, a link to the app', async () => {
    const { doc } = await render(<Claim {...claim} state="claimed" claimedInto="Drivly" />)
    expect(h1s(doc)).toEqual(['Your workspace is claimed'])
    expect(doc.querySelector('.id-conn')!.getAttribute('data-state')).toBe('ok')
    expect(doc.querySelector('.id-desc')!.textContent).toBe('headless.ly now lives in Drivly, with everything Claude set up and no sandbox limits.')
    expect(Array.from(doc.querySelectorAll('.id-desc .id-em')).map((e) => e.textContent)).toEqual(['headless.ly', 'Drivly'])
    const link = doc.querySelector('.id-foottext a')!
    expect([link.textContent, link.getAttribute('href')]).toEqual(['Open headless.ly', 'https://headless.ly'])
    expect(doc.querySelectorAll('button, select').length).toBe(0)
    expect(templates(doc)).toEqual([])
    expect(doc.querySelector('[role="status"][data-status]')!.textContent).toBe('Workspace claimed.')
  })

  it('escapes request data', async () => {
    const { html } = await render(<Claim {...claim} app={EVIL} stats={[{ n: '1', label: EVIL }]} />)
    expect(html).not.toContain(EVIL)
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;')
    const claimed = await render(<Claim {...claim} state="claimed" app={EVIL} claimedInto={EVIL} />)
    expect(claimed.html).not.toContain(EVIL)
  })
})

describe('5c on fetch-form.ts', () => {
  it('Claim workspace: busy at once, posts the chosen workspace, claimed 2150ms later', async () => {
    const post = vi.fn(ok)
    const m = await mount(<Claim {...claim} />, post)
    const btn = m.click('claimed')
    expect(m.state()).toBe('connecting')
    expect(btn.textContent).toBe('Claiming…')
    expect(m.status()).toBe('Claiming…')
    await flush()
    expect(post.mock.calls[0]![0]!.querySelector<HTMLSelectElement>('select[name="org_id"]')!.value).toBe('org_drivly')
    expect(m.state()).toBe('done')
    m.advance(SUCCESS_SWAP_MS - 1)
    expect(m.title()).toBe('Claude set up headless.ly for you')
    m.advance(1)
    expect(m.title()).toBe('Your workspace is claimed')
    expect(m.state()).toBe('ok')
    // Rendered before the person picked, so the template names no workspace.
    expect(m.desc()).toBe('headless.ly is yours now, with everything Claude set up and no sandbox limits.')
    expect(m.foot().querySelector('a')!.getAttribute('href')).toBe('https://headless.ly')
    expect(document.activeElement).toBe(document.querySelector('[data-region] h1'))
  })

  it('leaves for 5a at once when the agent still waits for approval', async () => {
    const m = await mount(<Claim {...claim} />, async () => ({ ok: false, redirect: '/agents/approve/agt_7f3ac21d' }))
    m.click('claimed')
    await flush()
    expect(m.go).toHaveBeenCalledWith('/agents/approve/agt_7f3ac21d')
  })
})

describe('5d · Claim from a repository', () => {
  it('one h1, labelled controls, a live status list polled from the status URL', async () => {
    const { doc } = await render(<ClaimRepo {...repo} />)
    expect(h1s(doc)).toEqual(['Claim from a repository'])
    expectLabelled(doc)
    const poll = doc.querySelector('[data-js="claim-status"]')!
    expect(poll.getAttribute('data-status-url')).toBe('/api/claim/clm_7Kx9m2/status')
    expect(poll.querySelector('[aria-live="polite"]')).not.toBeNull()
    const current = Array.from(doc.querySelectorAll('.id-status')).map((r) => r.classList.contains('id-status--current'))
    expect(current).toEqual([true, false, false])
    expect(doc.querySelector('.id-conn')!.getAttribute('data-state')).toBe('connecting')
    expect(doc.querySelector('.id-status__sub')!.textContent).toBe('Watching dot-do/headless-crm')
  })

  it('copies the command and holds the workflow in a disclosure', async () => {
    const { doc } = await render(<ClaimRepo {...repo} />)
    expect(doc.querySelector('[data-js="copy"]')!.getAttribute('data-value')).toBe('npx id.org.ai claim clm_7Kx9m2')
    expect(doc.querySelector('details summary')!.textContent).toBe('.github/workflows/id.yml')
    expect(doc.querySelector('details pre')!.textContent).toBe(repo.workflowYaml)
    expect(doc.querySelector('.id-foottext a')!.getAttribute('href')).toBe('/claim/clm_7Kx9m2')
  })

  it('claimed: the connector at ok, Claimed current, no polling', async () => {
    const { doc } = await render(<ClaimRepo {...repo} status="claimed" />)
    expect(doc.querySelector('.id-conn')!.getAttribute('data-state')).toBe('ok')
    expect(Array.from(doc.querySelectorAll('.id-status')).map((r) => r.classList.contains('id-status--current'))).toEqual([false, false, true])
    expect(doc.querySelector('[data-js="claim-status"]')).toBeNull()
  })

  it('escapes request data', async () => {
    const { html } = await render(<ClaimRepo {...repo} repo={EVIL} workflowYaml={EVIL} />)
    expect(html).not.toContain(EVIL)
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;')
  })
})
