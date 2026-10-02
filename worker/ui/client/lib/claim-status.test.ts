import { afterEach, describe, expect, it, vi } from 'vitest'
import { POLL_MS, initClaimStatus } from './claim-status'

afterEach(() => (document.body.innerHTML = ''))

function mount() {
  document.body.innerHTML = `<div class="id-card"><div class="id-conn" data-js="connector" data-state="connecting"></div>
    <div data-js="claim-status" data-status-url="/api/claim/clm_x/status"><span data-status-text></span>
      <div class="id-status id-status--current"><span class="id-status__title">Waiting for a push</span></div><div class="id-status"><span class="id-status__title">Pending on a branch</span></div><div class="id-status"><span class="id-status__title">Claimed</span></div>
    </div></div>`
  return document.querySelector<HTMLElement>('[data-js="claim-status"]')!
}

describe('claim-status.ts', () => {
  it('polls every 5s and moves the current row, then done on claimed', async () => {
    const root = mount()
    const replies = ['unclaimed', 'pending', 'claimed']
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({ status: replies.shift() })))
    let tick: () => void = () => {}
    let stopped = false
    initClaimStatus(root, fetchImpl as unknown as typeof fetch, (fn, ms) => {
      expect(ms).toBe(POLL_MS)
      tick = fn
      return () => (stopped = true)
    })
    const current = () => Array.from(root.querySelectorAll('.id-status')).findIndex((r) => r.classList.contains('id-status--current'))
    tick()
    await vi.waitFor(() => expect(fetchImpl).toHaveBeenCalledTimes(1))
    expect(current()).toBe(0)
    tick()
    await vi.waitFor(() => expect(current()).toBe(1))
    expect(root.querySelector('[data-status-text]')!.textContent).toBe('Pending on a branch')
    tick()
    await vi.waitFor(() => expect(current()).toBe(2))
    expect(document.querySelector('[data-js="connector"]')!.getAttribute('data-state')).toBe('done')
    expect(stopped).toBe(true)
  })

  it('keeps polling through a network error', async () => {
    const root = mount()
    let tick: () => void = () => {}
    initClaimStatus(root, (async () => Promise.reject(new Error('offline'))) as unknown as typeof fetch, (fn) => {
      tick = fn
      return () => {}
    })
    tick()
    await new Promise((r) => setTimeout(r, 0))
    expect(document.querySelector('[data-js="connector"]')!.getAttribute('data-state')).toBe('connecting')
  })
})
