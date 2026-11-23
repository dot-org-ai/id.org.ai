/** Workflows on the setup page (16a–18c) and the directory run (15a–15e): docs/agent-setup/HANDOFF.md section 3. */
import { describe, expect, it } from 'vitest'
import type { JSX } from 'hono/jsx/jsx-runtime'
import { directoryProps as D } from '../../gallery/fixtures/directory'
import { workflowProps as W } from '../../gallery/fixtures/workflows'
import { renderHtml } from '../../render'
import { SetupApprove } from './SetupApprove'
import { SetupPage } from './SetupPage'

async function dom(el: JSX.Element): Promise<Document> {
  return new DOMParser().parseFromString(await renderHtml(el, { title: 't' }), 'text/html')
}
const text = (el: Element | null | undefined) => el?.textContent?.replace(/\s+/g, ' ').trim()

describe('the same page runs every workflow', () => {
  it('needs_person holds the connector, whatever the product needs', async () => {
    for (const p of [D.pickReview, W.migDecide, W.migSwitch, W.saasMap]) {
      const d = await dom(<SetupPage {...p} />)
      expect(d.querySelector('.id-conn')!.getAttribute('data-state'), p.title).toBe('hold')
      expect(text(d.querySelector('.id-sstep--you .id-sstep__when')), p.title).toBe('Waiting on you')
    }
  })
  it('in review is still, with no header status', async () => {
    const d = await dom(<SetupPage {...D.inReview} />)
    expect(d.querySelector('.id-conn')!.getAttribute('data-state')).toBe('idle')
    expect(d.querySelector('.id-hstatus')).toBeNull()
    expect(text(d.querySelector('.id-sstep--now .id-sstep__when'))).toBe('In review')
  })
})

describe('16 · migration', () => {
  it('16a: a running comparison blinks, a finished one is green', async () => {
    const d = await dom(<SetupPage {...W.migRunning} />)
    expect([...d.querySelectorAll('.id-compare__state')].map((s) => [text(s), s.querySelector('.id-sdot')!.className])).toEqual([
      ['250 of 250 match', 'id-sdot'],
      ['181 of 250 so far', 'id-sdot id-sdot--busy'],
    ])
  })
  it('16b: the person’s choice is a radio group that posts with the step’s id', async () => {
    const d = await dom(<SetupPage {...W.migDecide} />)
    const radios = [...d.querySelectorAll<HTMLInputElement>('input[type=radio][name=answer_mapped]')]
    expect(radios.map((r) => [r.value, r.checked])).toEqual([
      ['keep', true],
      ['replace', false],
    ])
    expect(radios[0]!.closest('fieldset')!.querySelector('legend')!.textContent).toBe('Calls mapped')
    expect(d.querySelector<HTMLButtonElement>('.id-btn--primary')!.value).toBe('answer')
  })
  it('16d: the old key is the person’s to retire, so that step is never ticked for them', async () => {
    const d = await dom(<SetupPage {...W.migDone} />)
    const last = [...d.querySelectorAll('[role=listitem]')].pop()!
    expect(last.className).toContain('id-sstep--todo')
    expect(text(last.querySelector('.id-sstep__detail'))).toBe('Yours to do, in MarketCheck.')
    expect(d.querySelector('.id-conn')!.getAttribute('data-state')).toBe('ok')
  })
})

describe('17 · one job across several APIs', () => {
  it('17a: one limit covers all three, and each spending permission is amber', async () => {
    const d = await dom(<SetupApprove {...W.jobApprove} />)
    expect(text(d.querySelector('label[for=setup-spend]'))).toBe('Spend limit, all three')
    expect(d.querySelectorAll('.id-perm')).toHaveLength(4)
    expect(d.querySelectorAll('.id-perm__icon--act')).toHaveLength(2)
    expect(d.querySelector('.id-payline')).toBeNull()
  })
  it('17b: each step is tagged with its API, and the right tile is the layers icon', async () => {
    const d = await dom(<SetupPage {...W.jobRunning} />)
    expect([...d.querySelectorAll('.id-steptag')].map((t) => t.textContent)).toEqual(['[YOUR DOMAIN API]', '[YOUR DOMAIN API]', 'apis.email', 'apis.email'])
    const right = [...d.querySelectorAll('.id-conn .id-tile')][1]!
    expect(right.querySelector('svg')).not.toBeNull()
    expect(right.textContent).toBe('')
  })
})

describe('18 · headless SaaS', () => {
  it('18a: each unmatched column gets a labelled select that posts with the step’s id', async () => {
    const d = await dom(<SetupPage {...W.saasMap} />)
    const selects = [...d.querySelectorAll<HTMLSelectElement>('.id-fieldmap select')]
    expect(selects.map((s) => [s.name, s.value])).toEqual([
      ['answer_import_lead_src', 'Source'],
      ['answer_import_acct_mgr', 'Owner'],
    ])
    expect(selects.map((s) => text(d.querySelector(`label[for="${s.id}"]`)))).toEqual(['lead_src goes to', 'acct_mgr goes to'])
  })
  it('18b: the gate is a real event, and the page says a test event doesn’t count', async () => {
    const d = await dom(<SetupPage {...W.saasRunning} />)
    expect(text(d.querySelector('.id-listen__text'))).toBe('Listening on [YOUR WEBHOOK URL]')
    expect(d.body.textContent).toContain('A test event sent by the agent doesn’t count.')
  })
})

describe('15 · apis.directory', () => {
  it('15b: the only time the person is asked, and paying never changes a score', async () => {
    const d = await dom(<SetupPage {...D.pickReview} />)
    expect([...d.querySelectorAll<HTMLButtonElement>('button[name=decision]')].map((b) => [b.value, text(b)])).toEqual([
      ['free', 'Keep it free'],
      ['fast', 'Pay $100'],
    ])
    expect(text(d.querySelector('.id-foottext'))).toBe('Paying changes the wait, never a score.')
    expect(text(d.querySelector('.id-call__status'))).toBe('200 · [MS] ms')
  })
})
