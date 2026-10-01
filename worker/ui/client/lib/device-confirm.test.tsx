import { afterEach, describe, expect, it, vi } from 'vitest'
import { renderHtml } from '../../render'
import { DeviceConfirm } from '../../screens/DeviceConfirm'
import { deviceFixtures } from '../../gallery/fixtures/devices'
import { initDeviceConfirm, swap, type DeviceConfirmDeps } from './device-confirm'

/** The real 4b markup from the gallery fixture, with a fake clock and a fake server. */
async function mount(post: DeviceConfirmDeps['post']) {
  const html = await renderHtml(deviceFixtures['4b-device-confirm']!.default.render(), { title: 't' })
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
  const form = document.querySelector<HTMLFormElement>('form[data-js="device-confirm"]')!
  initDeviceConfirm(form, { post, later })
  const click = (value: 'approve' | 'deny') => {
    const btn = form.querySelector<HTMLButtonElement>(`button[value="${value}"]`)!
    form.dispatchEvent(Object.assign(new Event('submit', { bubbles: true, cancelable: true }), { submitter: btn }))
  }
  const state = () => document.querySelector('[data-js="connector"]')!.getAttribute('data-state')
  const title = () => document.querySelector('[data-region] h1')!.textContent
  const status = () => document.querySelector('[data-status]')!.textContent
  return { form, click, advance, state, title, status }
}

const flush = () => new Promise((r) => setTimeout(r, 0))

afterEach(() => (document.body.innerHTML = ''))

void DeviceConfirm

describe('device-confirm.ts (motion.md#device-confirm-4b-the-reference-state-machine)', () => {
  it('Confirm: busy at once, done on the server OK, signed 2150ms later', async () => {
    let resolve!: (ok: boolean) => void
    const m = await mount(() => new Promise((r) => (resolve = r)))
    m.click('approve')
    expect(m.state()).toBe('connecting')
    const confirm = m.form.querySelector<HTMLButtonElement>('button[value="approve"]')!
    expect(confirm.getAttribute('aria-busy')).toBe('true')
    expect(confirm.textContent).toBe('Confirming…')
    expect(m.form.querySelector<HTMLButtonElement>('button[value="deny"]')!.disabled).toBe(true)
    expect(m.status()).toBe('Confirming…')
    resolve(true)
    await flush()
    expect(m.state()).toBe('done')
    m.advance(2149)
    expect(m.title()).toBe('Confirm sign-in on auto.dev CLI')
    m.advance(1)
    expect(m.title()).toBe('auto.dev CLI is signed in')
    expect(m.state()).toBe('ok')
    expect(document.querySelector('.id-card__foot')!.textContent).toContain('Sign this device out')
    expect(m.status()).toBe('Signed in')
  })

  it('Confirm refused: broken, then the error content 1820ms later', async () => {
    const m = await mount(async () => false)
    m.click('approve')
    await flush()
    expect(m.state()).toBe('broken')
    m.advance(1820)
    expect(m.status()).toBe('Something went wrong.')
  })

  it('Cancel: broken at once, both disabled, cancelled after 1820ms once the deny succeeded', async () => {
    const post = vi.fn(async () => true)
    const m = await mount(post)
    m.click('deny')
    expect(m.state()).toBe('broken')
    for (const b of m.form.querySelectorAll('button')) expect(b.disabled).toBe(true)
    await flush()
    expect(post).toHaveBeenCalledWith(m.form, 'deny')
    m.advance(1819)
    expect(m.title()).toBe('Confirm sign-in on auto.dev CLI')
    m.advance(1)
    expect(m.title()).toBe('Sign-in cancelled')
    expect(m.state()).toBe('fail')
  })

  it('Cancel waits for a slow deny past 1820ms', async () => {
    let resolve!: (ok: boolean) => void
    const m = await mount(() => new Promise((r) => (resolve = r)))
    m.click('deny')
    m.advance(5000)
    expect(m.title()).toBe('Confirm sign-in on auto.dev CLI')
    resolve(true)
    await flush()
    expect(m.title()).toBe('Sign-in cancelled')
  })

  it('a failed deny shows the error instead of cancelled', async () => {
    const m = await mount(async () => false)
    m.click('deny')
    await flush()
    m.advance(1820)
    expect(m.title()).toBe('Confirm sign-in on auto.dev CLI')
    expect(m.status()).toBe('Something went wrong.')
  })

  it('ignores a second submit', async () => {
    const post = vi.fn(async () => true)
    const m = await mount(post)
    m.click('approve')
    m.click('deny')
    await flush()
    expect(post).toHaveBeenCalledTimes(1)
  })

  it('swap() replaces each region from its sibling template', async () => {
    await mount(async () => true)
    expect(swap(document.querySelector('.id-card')!, 'nope')).toBe(false)
    expect(swap(document.querySelector('.id-card')!, 'cancelled')).toBe(true)
  })
})
