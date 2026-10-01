/**
 * Agents screens (5a–5d): the accessibility and form contracts in
 * docs/product-update/prompts/03-screens.md. One h1, every control labelled,
 * forms posting to the spec route with a CSRF field, a status region where
 * states change, and request data escaped.
 */
import { describe, expect, it } from 'vitest'
import type { JSX } from 'hono/jsx/jsx-runtime'
import { renderHtml } from '../render'
import { agentsProps } from '../gallery/fixtures/agents'
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

describe('5a · Approve an agent', () => {
  it('one h1, labelled controls, posts to /agents/approve/:agentId with csrf and both decisions', async () => {
    const { doc } = await render(<AgentApprove {...approve} />)
    expect(h1s(doc)).toEqual(['Claude Code wants to work as your agent'])
    expectLabelled(doc)
    const form = expectForm(doc, /^\/agents\/approve\/[^/]+$/)
    const decisions = Array.from(form.querySelectorAll<HTMLButtonElement>('button[name="decision"]')).map((b) => [b.type, b.value, b.textContent])
    expect(decisions).toEqual([
      ['submit', 'reject', 'Reject'],
      ['submit', 'approve', 'Approve agent'],
    ])
    expect(doc.querySelector('[role="status"][data-status]')).not.toBeNull()
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
  })

  it('shows the shortened fingerprint in mono and copies the full one', async () => {
    const { doc } = await render(<AgentApprove {...approve} />)
    expect(shortFingerprint(approve.agent.fingerprint)).toBe('7f3a…c21d')
    expect(doc.querySelector('.id-source__value--mono')!.textContent).toBe('ed25519 · 7f3a…c21d')
    expect(doc.querySelector('[data-js="copy"]')!.getAttribute('data-value')).toBe(approve.agent.fingerprint)
  })

  it('approved and rejected render in place: one h1, no form, the verdict announced', async () => {
    const ok = (await render(<AgentApprove {...approve} state="approved" />)).doc
    expect(h1s(ok)).toEqual(['Claude Code is now your agent'])
    expect(ok.querySelector('form')).toBeNull()
    expect(ok.querySelector('.id-conn')!.getAttribute('data-state')).toBe('ok')
    expect(ok.querySelector('[role="status"][data-status]')!.textContent).toBe('Claude Code approved.')
    const no = (await render(<AgentApprove {...approve} state="rejected" />)).doc
    expect(h1s(no)).toEqual(['Claude Code wasn’t approved'])
    expect(no.querySelector('.id-conn')!.getAttribute('data-state')).toBe('fail')
  })

  it('escapes request data', async () => {
    const { html } = await render(<AgentApprove {...approve} agent={{ ...approve.agent, name: EVIL, host: EVIL }} />)
    expect(html).not.toContain(EVIL)
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;')
  })
})

describe('5b · Approve an action', () => {
  it('one h1, labelled controls, posts to /approvals/:requestId with csrf, deny and approve', async () => {
    const { doc } = await render(<ActionApproval {...action} />)
    expect(h1s(doc)).toEqual(['Susan wants to send an email'])
    expectLabelled(doc)
    const form = expectForm(doc, /^\/approvals\/[^/]+$/)
    expect(Array.from(form.querySelectorAll<HTMLButtonElement>('button[name="decision"]')).map((b) => b.value)).toEqual(['deny', 'approve'])
    const always = form.querySelector<HTMLInputElement>('input[type="checkbox"][name="always_allow"]')!
    expect(doc.querySelector(`label[for="${always.id}"]`)!.textContent).toBe('Always allow Susan to send renewal emails')
  })

  it('the header counts down; the status region sits outside the card so the expiry is announced after the swap', async () => {
    const { doc } = await render(<ActionApproval {...action} />)
    const cd = doc.querySelector('header [data-js="countdown"]')!
    expect(cd.getAttribute('data-expires-at')).toBe(action.expiresAt)
    expect(cd.getAttribute('data-urgent-at')).toBe('60')
    expect(cd.textContent).toBe('4:32 left')
    const status = doc.querySelector('[role="status"][data-status]')!
    expect(status.closest('.id-card')).toBeNull()
  })

  it('carries the expired template (7b shape), and renders it as the expired state', async () => {
    const { doc } = await render(<ActionApproval {...action} />)
    const tpl = doc.querySelector<HTMLTemplateElement>('template[data-state="expired"]')!
    expect(tpl.content.querySelector('h1')!.textContent).toBe('This request expired')
    const expired = (await render(<ActionApproval {...action} state="expired" />)).doc
    expect(h1s(expired)).toEqual(['This request expired'])
    expect(expired.querySelector('form')).toBeNull()
    expect(expired.querySelector('[data-js="countdown"]')).toBeNull()
    expect(expired.querySelector('.id-conn')!.getAttribute('data-state')).toBe('fail')
  })

  it('runs the connector agent → id.org.ai', async () => {
    const { doc } = await render(<ActionApproval {...action} />)
    const tiles = Array.from(doc.querySelectorAll('.id-conn .id-tile'))
    expect(tiles[0]!.textContent).toBe('Su')
    expect(tiles[1]!.querySelector('svg')).not.toBeNull()
  })

  it('escapes request data', async () => {
    const { html } = await render(<ActionApproval {...action} action={{ ...action.action, subject: EVIL, excerpt: EVIL }} alwaysAllowLabel={EVIL} />)
    expect(html).not.toContain(EVIL)
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;')
  })
})

describe('5c · Claim agent work', () => {
  it('one h1, labelled controls, posts to /claim/:token with csrf; the repo path is a link to 5d', async () => {
    const { doc } = await render(<Claim {...claim} />)
    expect(h1s(doc)).toEqual(['Claude set up headless.ly for you'])
    expectLabelled(doc)
    const form = expectForm(doc, /^\/claim\/[^/]+$/)
    expect(form.querySelector('button[type="submit"]')!.textContent).toBe('Claim workspace')
    expect(doc.querySelector('a.id-btn')!.getAttribute('href')).toBe('/claim/clm_7Kx9m2/repo')
    expect(Array.from(doc.querySelectorAll('select[name="org_id"] option')).map((o) => o.textContent)).toEqual(['Drivly', '.do Industries', 'New workspace…'])
    expect(doc.querySelector('[role="status"][data-status]')).not.toBeNull()
  })

  it('escapes request data', async () => {
    const { html } = await render(<Claim {...claim} app={EVIL} stats={[{ n: '1', label: EVIL }]} />)
    expect(html).not.toContain(EVIL)
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;')
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

describe('agents screens', () => {
  it('render without inline styles or inline scripts', async () => {
    for (const el of [
      <AgentApprove {...approve} />,
      <AgentApprove {...approve} state="approved" />,
      <ActionApproval {...action} />,
      <ActionApproval {...action} state="expired" />,
      <Claim {...claim} />,
      <ClaimRepo {...repo} />,
    ]) {
      const { html } = await render(el)
      expect(html).not.toMatch(/\sstyle=/i)
      expect(html).not.toMatch(/\son[a-z]+=/i)
      for (const tag of html.match(/<script\b[^>]*>/gi) ?? []) expect(tag).toMatch(/\ssrc="/)
    }
  })
})
