import { afterEach, describe, expect, it, vi } from 'vitest'
import { formatCountdown, initCountdown } from './countdown'

afterEach(() => {
  vi.useRealTimers()
  document.body.innerHTML = ''
})

function mount(secondsLeft: number, attrs = ''): { el: HTMLElement; text: () => string } {
  vi.useFakeTimers()
  vi.setSystemTime(new Date('2026-10-01T12:00:00Z'))
  const expires = new Date(Date.now() + secondsLeft * 1000).toISOString()
  document.body.innerHTML = `<span data-status></span><div><span data-js="countdown" data-expires-at="${expires}" data-suffix=" left" ${attrs}><span data-countdown-text></span></span><a data-countdown-done hidden>Resend code</a></div>`
  const el = document.querySelector<HTMLElement>('[data-js="countdown"]')!
  initCountdown(el)
  return { el, text: () => el.querySelector('[data-countdown-text]')!.textContent ?? '' }
}

describe('formatCountdown', () => {
  it('is m:ss with no leading zero on minutes', () => {
    expect(formatCountdown(272)).toBe('4:32')
    expect(formatCountdown(42)).toBe('0:42')
    expect(formatCountdown(0)).toBe('0:00')
    expect(formatCountdown(-5)).toBe('0:00')
  })
})

describe('countdown.ts', () => {
  it('ticks every second', () => {
    const c = mount(272)
    expect(c.text()).toBe('4:32 left')
    vi.advanceTimersByTime(1000)
    expect(c.text()).toBe('4:31 left')
  })

  it('turns urgent at 60s only when asked (5b), and announces once', () => {
    const c = mount(62, 'data-urgent-at="60"')
    expect(c.el.hasAttribute('data-urgent')).toBe(false)
    vi.advanceTimersByTime(2000)
    expect(c.el.hasAttribute('data-urgent')).toBe(true)
    expect(document.querySelector('[data-status]')!.textContent).toBe('One minute left.')
  })

  it('never turns urgent without data-urgent-at (the 1b resend timer)', () => {
    const c = mount(30)
    expect(c.el.hasAttribute('data-urgent')).toBe(false)
  })

  it('at 0 reveals the done sibling (1b: "Resend code") and announces expiry', () => {
    const c = mount(2)
    vi.advanceTimersByTime(2000)
    expect(c.el.hidden).toBe(true)
    expect(document.querySelector<HTMLElement>('[data-countdown-done]')!.hidden).toBe(false)
    expect(document.querySelector('[data-status]')!.textContent).toBe('This request expired.')
  })
})
