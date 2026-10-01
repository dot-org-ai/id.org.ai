import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { renderHtml } from '../../render'
import { CopyButton } from '../../components'
import { COPIED_MS, initCopy } from './copy'

async function mount(copied = false): Promise<HTMLButtonElement> {
  const html = await renderHtml(<CopyButton value="chatgpt.com/oauth/codex/client.json" copied={copied} />, { title: 't' })
  document.body.innerHTML = new DOMParser().parseFromString(html, 'text/html').body.innerHTML
  return document.querySelector('button')!
}

/** The clipboard stub resolves in a microtask; flush a few without touching the fake clock. */
const settle = async () => {
  for (let i = 0; i < 5; i++) await Promise.resolve()
}

beforeEach(() => vi.useFakeTimers())
afterEach(() => {
  vi.useRealTimers()
  document.documentElement.removeAttribute('data-frozen')
})

describe('copy.ts', () => {
  it('unhides itself (hidden without JS)', async () => {
    const btn = await mount()
    expect(btn.hidden).toBe(true)
    initCopy(btn, { writeText: vi.fn(async () => {}) })
    expect(btn.hidden).toBe(false)
  })

  it('writes the value, shows the check and announces, then reverts after 1.5s', async () => {
    const btn = await mount()
    const writeText = vi.fn(async () => {})
    initCopy(btn, { writeText })
    btn.click()
    await settle()
    expect(btn.hasAttribute('data-copied')).toBe(true)
    expect(writeText).toHaveBeenCalledWith('chatgpt.com/oauth/codex/client.json')
    expect(btn.nextElementSibling!.textContent).toBe('Copied')
    vi.advanceTimersByTime(COPIED_MS - 1)
    expect(btn.hasAttribute('data-copied')).toBe(true)
    vi.advanceTimersByTime(1)
    expect(btn.hasAttribute('data-copied')).toBe(false)
    expect(btn.nextElementSibling!.textContent).toBe('')
  })

  it('restarts the timer on a second click', async () => {
    const btn = await mount()
    initCopy(btn, { writeText: vi.fn(async () => {}) })
    btn.click()
    await settle()
    expect(btn.hasAttribute('data-copied')).toBe(true)
    vi.advanceTimersByTime(1000)
    btn.click()
    await settle()
    vi.advanceTimersByTime(1000)
    expect(btn.hasAttribute('data-copied')).toBe(true)
    vi.advanceTimersByTime(500)
    expect(btn.hasAttribute('data-copied')).toBe(false)
  })

  it('never resets a server-rendered copied state', async () => {
    const btn = await mount(true)
    initCopy(btn, { writeText: vi.fn(async () => {}) })
    vi.advanceTimersByTime(5000)
    expect(btn.hasAttribute('data-copied')).toBe(true)
  })

  it('does nothing visible when the clipboard refuses', async () => {
    const btn = await mount()
    initCopy(btn, { writeText: vi.fn(async () => Promise.reject(new Error('denied'))) })
    btn.click()
    await settle()
    expect(btn.hasAttribute('data-copied')).toBe(false)
  })
})
