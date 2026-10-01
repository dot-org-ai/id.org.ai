import { afterEach, describe, expect, it, vi } from 'vitest'
import { renderHtml } from '../../render'
import { deviceFixtures } from '../../gallery/fixtures/devices'
import { initFetchForm, swap, type FetchDeps } from './fetch-form'

type Post = FetchDeps['post']

/** The real 4b markup from the gallery fixture, with a fake clock and a fake server. */
async function mount(post: Post, extraTemplates = '') {
  const html = await renderHtml(deviceFixtures['4b-device-confirm']!.default.render(), { title: 't' })
  document.body.innerHTML = new DOMParser().parseFromString(html, 'text/html').body.innerHTML
  if (extraTemplates) document.querySelector('[data-region="body"]')!.insertAdjacentHTML('afterend', extraTemplates)
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
  const click = (value: 'approve' | 'deny') => {
    const btn = form.querySelector<HTMLButtonElement>(`button[value="${value}"]`)!
    form.dispatchEvent(Object.assign(new Event('submit', { bubbles: true, cancelable: true }), { submitter: btn }))
  }
  const state = () => document.querySelector('[data-js="connector"]')!.getAttribute('data-state')
  const title = () => document.querySelector('[data-region] h1')!.textContent
  const status = () => document.querySelector('[data-status]')!.textContent
  return { form, click, advance, state, title, status, go }
}

const flush = () => new Promise((r) => setTimeout(r, 0))
const ok: Post = async () => ({ ok: true })

afterEach(() => (document.body.innerHTML = ''))

describe('4b on lib/fetch-form.ts (motion.md#device-confirm-4b-the-reference-state-machine)', () => {
  it('Confirm: busy at once, done on the server OK, signed 2150ms later, focus on the new title', async () => {
    let resolve!: (r: { ok: boolean }) => void
    const m = await mount(() => new Promise((r) => (resolve = r)))
    m.click('approve')
    expect(m.state()).toBe('connecting')
    const confirm = m.form.querySelector<HTMLButtonElement>('button[value="approve"]')!
    expect(confirm.getAttribute('aria-busy')).toBe('true')
    expect(confirm.textContent).toBe('Confirming…')
    expect(m.form.querySelector<HTMLButtonElement>('button[value="deny"]')!.disabled).toBe(true)
    expect(m.status()).toBe('Confirming…')
    resolve({ ok: true })
    await flush()
    expect(m.state()).toBe('done')
    m.advance(2149)
    expect(m.title()).toBe('Confirm sign-in on auto.dev CLI')
    m.advance(1)
    expect(m.title()).toBe('auto.dev CLI is signed in')
    expect(m.state()).toBe('ok')
    expect(document.querySelector('.id-card__foot')!.textContent).toContain('Sign this device out')
    expect(document.activeElement).toBe(document.querySelector('[data-region] h1'))
  })

  it('posts the clicked decision', async () => {
    const post = vi.fn(ok)
    const m = await mount(post)
    m.click('approve')
    await flush()
    expect(post.mock.calls[0]![1]!.value).toBe('approve')
  })

  it('a refusal with a matching template: broken, then the 7b copy 1820ms later', async () => {
    const m = await mount(async () => ({ ok: false, error: 'expired' }), '<template data-state="error-expired"><h1>This code expired</h1></template>')
    m.click('approve')
    await flush()
    expect(m.state()).toBe('broken')
    m.advance(1819)
    expect(m.title()).toBe('Confirm sign-in on auto.dev CLI')
    m.advance(1)
    expect(m.title()).toBe('This code expired')
  })

  it('a refusal with no template gives the buttons back, so Try again works', async () => {
    const post = vi.fn(async () => ({ ok: false, error: 'server_error' }))
    const m = await mount(post)
    // 4b ships a generic `error` template; take it out to reach the no-template path.
    for (const t of document.querySelectorAll('template[data-state="error"]')) t.remove()
    m.click('approve')
    await flush()
    m.advance(1820)
    expect(m.status()).toBe('Something went wrong. Try again.')
    for (const b of m.form.querySelectorAll('button')) expect(b.disabled).toBe(false)
    m.click('approve')
    await flush()
    expect(post).toHaveBeenCalledTimes(2)
  })

  it('Cancel: broken at once, both disabled, cancelled after 1820ms once the deny succeeded', async () => {
    const post = vi.fn(ok)
    const m = await mount(post)
    m.click('deny')
    expect(m.state()).toBe('broken')
    for (const b of m.form.querySelectorAll('button')) expect(b.disabled).toBe(true)
    await flush()
    expect(post.mock.calls[0]![1]!.value).toBe('deny')
    m.advance(1819)
    expect(m.title()).toBe('Confirm sign-in on auto.dev CLI')
    m.advance(1)
    expect(m.title()).toBe('Sign-in cancelled')
    expect(m.state()).toBe('fail')
  })

  it('Cancel waits for a slow deny past 1820ms', async () => {
    let resolve!: (r: { ok: boolean }) => void
    const m = await mount(() => new Promise((r) => (resolve = r)))
    m.click('deny')
    m.advance(5000)
    expect(m.title()).toBe('Confirm sign-in on auto.dev CLI')
    resolve({ ok: true })
    await flush()
    expect(m.title()).toBe('Sign-in cancelled')
  })

  it('a failed deny shows the cancel error, not cancelled, and nothing before 1820ms', async () => {
    const m = await mount(async () => ({ ok: false, error: 'server_error' }), '<template data-state="error-cancel"><h1>We couldn’t cancel this request</h1></template>')
    m.click('deny')
    await flush()
    m.advance(1819)
    expect(m.title()).toBe('Confirm sign-in on auto.dev CLI')
    m.advance(1)
    expect(m.title()).toBe('We couldn’t cancel this request')
  })

  it('ignores a second submit while one is in flight', async () => {
    const post = vi.fn(ok)
    const m = await mount(post)
    m.click('approve')
    m.click('deny')
    await flush()
    expect(post).toHaveBeenCalledTimes(1)
  })

  it('leaves at once when the server answers with a redirect (D7)', async () => {
    const m = await mount(async () => ({ ok: true, redirect: 'https://app.example/cb?code=x' }))
    m.click('approve')
    await flush()
    expect(m.go).toHaveBeenCalledWith('https://app.example/cb?code=x')
  })

  it('swap() replaces each region from its sibling template', async () => {
    await mount(ok)
    expect(swap(document.querySelector('.id-card')!, 'nope')).toBe(false)
    expect(swap(document.querySelector('.id-card')!, 'cancelled')).toBe(true)
  })
})
