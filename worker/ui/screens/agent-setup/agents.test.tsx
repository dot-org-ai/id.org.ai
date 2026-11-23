/** Agents and policy (10a–10e, 13a, 13b): the rules in docs/agent-setup/HANDOFF.md the drawings can't show. */
import { describe, expect, it } from 'vitest'
import type { JSX } from 'hono/jsx/jsx-runtime'
import { agentsManageProps as P } from '../../gallery/fixtures/agents-manage'
import { renderHtml } from '../../render'
import { AgentCard } from './AgentCard'

async function dom(el: JSX.Element): Promise<Document> {
  return new DOMParser().parseFromString(await renderHtml(el, { title: 't' }), 'text/html')
}
const text = (el: Element | null | undefined) => el?.textContent?.replace(/\s+/g, ' ').trim()

describe('10a · your agents', () => {
  it('lists each agent as an expandable row; the open one links to activity and spending', async () => {
    const d = await dom(<AgentCard {...P.agents} />)
    const rows = [...d.querySelectorAll('details.id-agentrow')]
    expect(rows.map((r) => r.hasAttribute('open'))).toEqual([true, false, false])
    expect([...rows[0]!.querySelectorAll('.id-linkrow a')].map((a) => [a.textContent, a.getAttribute('href')])).toEqual([
      ['View activity', '/agents/ag_7f3a/activity'],
      ['Spending', '/spending'],
    ])
    expect([...d.querySelectorAll('.id-chip')].map((c) => c.textContent)).toEqual(['Setting up', 'Paused'])
  })
  it('shows only a key’s last four characters, and id.org.ai offers no key controls', async () => {
    const d = await dom(<AgentCard {...P.agents} />)
    expect(text(d.querySelector('.id-connrow'))).toBe('Auto.devLive · key ends in 4f2aOpen dashboard')
    expect(d.body.textContent).not.toMatch(/rotate|reveal|show key/i)
  })
  it('one tile, no connector, and the signed-in account with Switch', async () => {
    const d = await dom(<AgentCard {...P.agents} />)
    expect(d.querySelector('.id-conn')).toBeNull()
    expect(d.querySelectorAll('.id-head .id-tile')).toHaveLength(1)
    expect(text(d.querySelector('.id-who a'))).toBe('Switch')
  })
})

describe('remove and pause', () => {
  it('10b: cancelling the subscription is a choice, unticked', async () => {
    const d = await dom(<AgentCard {...P.remove} />)
    const box = d.querySelector<HTMLInputElement>('input[name=cancel_subscription]')!
    expect(box.type).toBe('checkbox')
    expect(box.checked).toBe(false)
    expect(d.querySelector<HTMLButtonElement>('button[name=decision]')!.value).toBe('remove')
  })
  it('10d: resume defaults to when the person resumes it', async () => {
    const d = await dom(<AgentCard {...P.pause} />)
    expect(d.querySelector<HTMLSelectElement>('select[name=resume]')!.value).toBe('manual')
  })
  it('10c keeps the bracketed placeholder and copies exactly what it shows', async () => {
    const d = await dom(<AgentCard {...P.empty} />)
    expect(d.querySelector('[data-js=copy]')!.getAttribute('data-value')).toBe('Set up Auto.dev through apis.ax. Follow [AGENT GUIDE URL].')
  })
})

describe('10e · activity', () => {
  it('amber only where money moved', async () => {
    const d = await dom(<AgentCard {...P.activity} />)
    const rows = [...d.querySelectorAll('.id-activity')]
    expect(rows).toHaveLength(6)
    expect(rows.filter((r) => r.classList.contains('id-activity--money')).map((r) => text(r.querySelector('.id-line14')))).toEqual(['Subscribed to Growth at $299/month'])
  })
  it('both foot actions are quiet', async () => {
    const d = await dom(<AgentCard {...P.activity} />)
    expect(d.querySelectorAll('.id-btn--primary')).toHaveLength(0)
    expect(d.querySelectorAll('.id-btn--secondary')).toHaveLength(2)
  })
})

describe('workspace policy', () => {
  it('13a: blocked by policy shows the X, and the agent can continue on the test key', async () => {
    const d = await dom(<AgentCard {...P.blocked} />)
    expect(d.querySelector('.id-conn')!.getAttribute('data-state')).toBe('fail')
    expect(d.querySelector('.id-btn--secondary')!.getAttribute('href')).toBe('/setup/su_8f2k')
    expect(text(d.querySelector('.id-footnote'))).toBe('Admins get an email and can approve in one click.')
  })
  it('13b: the admin is shown without Switch; approving defaults to this agent only', async () => {
    const d = await dom(<AgentCard {...P.adminApprove} />)
    expect(d.querySelector('.id-who a')).toBeNull()
    expect(d.querySelector<HTMLInputElement>('input[name=approve_for]:checked')!.value).toBe('agent')
    expect(d.querySelector('legend')!.textContent).toBe('Approve for')
  })
})
