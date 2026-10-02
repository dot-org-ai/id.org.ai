import { afterEach, describe, expect, it, vi } from 'vitest'
import { formatCountdown, initCountdown } from './countdown'

afterEach(() => {
  vi.useRealTimers()
  document.body.innerHTML = ''
})

function mount(secondsLeft: number, attrs = ''): { el: HTMLElement; text: () => string; status: () => string } {
  vi.useFakeTimers()
  document.body.innerHTML = `<span data-status></span><div><span data-js="countdown" data-seconds-left="${secondsLeft}" data-suffix=" left" ${attrs}><span data-countdown-text></span></span><a data-countdown-done hidden>Resend code</a></div>`
  const el = document.querySelector<HTMLElement>('[data-js="countdown"]')!
  initCountdown(el, () => Date.now())
  return {
    el,
    text: () => el.querySelector('[data-countdown-text]')!.textContent ?? '',
    status: () => document.querySelector('[data-status]')!.textContent ?? '',
  }
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
  it('ticks every second from the server-rendered seconds, not the client clock', () => {
    const c = mount(272)
    expect(c.text()).toBe('4:32 left')
    vi.advanceTimersByTime(1000)
    expect(c.text()).toBe('4:31 left')
  })

  it('turns urgent at 60s only when asked (5b)', () => {
    const c = mount(62, 'data-urgent-at="60"')
    expect(c.el.hasAttribute('data-urgent')).toBe(false)
    vi.advanceTimersByTime(2000)
    expect(c.el.hasAttribute('data-urgent')).toBe(true)
  })

  it('announces once at 60s and once at expiry, only with data-announce (5b)', () => {
    const c = mount(61, 'data-urgent-at="60" data-announce')
    expect(c.status()).toBe('')
    vi.advanceTimersByTime(1000)
    expect(c.status()).toBe('One minute left.')
    document.querySelector('[data-status]')!.textContent = ''
    vi.advanceTimersByTime(30_000)
    expect(c.status()).toBe('')
    vi.advanceTimersByTime(30_000)
    expect(c.status()).toBe('This request expired.')
  })

  it('the 1b resend timer stays quiet and never turns urgent', () => {
    const c = mount(61)
    vi.advanceTimersByTime(61_000)
    expect(c.status()).toBe('')
    expect(c.el.hasAttribute('data-urgent')).toBe(false)
  })

  it('at 0 reveals the done sibling (1b: "Resend code") and stops', () => {
    const c = mount(2)
    vi.advanceTimersByTime(2000)
    expect(c.el.hidden).toBe(true)
    expect(document.querySelector<HTMLElement>('[data-countdown-done]')!.hidden).toBe(false)
    expect(vi.getTimerCount()).toBe(0)
  })

  it('at 0 swaps the expired template in for the card (5b)', () => {
    vi.useFakeTimers()
    document.body.innerHTML = `<header><span data-js="countdown" data-seconds-left="1" data-expired-template="expired"><span data-countdown-text></span></span></header>
      <main><div class="id-card">form</div></main><template data-state="expired"><div class="id-card"><h1>This request expired</h1></div></template>`
    initCountdown(document.querySelector<HTMLElement>('[data-js="countdown"]')!, () => Date.now())
    vi.advanceTimersByTime(1000)
    expect(document.querySelector('main h1')!.textContent).toBe('This request expired')
  })

  it('stops, hides and stays quiet once a decision has replaced the expired template (5b)', () => {
    vi.useFakeTimers()
    document.body.innerHTML = `<span data-status></span><header><span data-js="countdown" data-seconds-left="61" data-announce data-expired-template="expired"><span data-countdown-text></span></span></header>
      <main><div class="id-card"><div data-region="body">form<template data-state="expired"><div class="id-card"><h1>This request expired</h1></div></template></div></div></main>`
    const el = document.querySelector<HTMLElement>('[data-js="countdown"]')!
    initCountdown(el, () => Date.now())
    // fetch-form swaps the body region for the "Sent" result; the expired template goes with it.
    document.querySelector('[data-region="body"]')!.innerHTML = '<h1>Sent</h1>'
    document.querySelector('[data-status]')!.textContent = 'Sent.'
    vi.advanceTimersByTime(1000)
    expect(el.hidden).toBe(true)
    expect(vi.getTimerCount()).toBe(0)
    vi.advanceTimersByTime(120_000)
    expect(document.querySelector('[data-status]')!.textContent).toBe('Sent.')
    expect(document.querySelector('main h1')!.textContent).toBe('Sent')
  })

  /** 5b's shape: the countdown in the header, a fetch-form card whose body region holds the expired template. */
  function mountInFlight(secondsLeft: number) {
    vi.useFakeTimers()
    document.body.innerHTML = `<span data-status></span><header><span data-js="countdown" data-seconds-left="${secondsLeft}" data-announce data-expired-template="expired"><span data-countdown-text></span></span></header>
      <main><form data-js="fetch-form"><div class="id-card"><div data-region="body"><h1>Approve</h1><template data-state="expired"><div class="id-card"><h1>This request expired</h1></div></template></div>
      <div data-region="foot"><button>Deny</button><button>Approve and send</button></div></div></form></main>`
    const el = document.querySelector<HTMLElement>('[data-js="countdown"]')!
    initCountdown(el, () => Date.now())
    // fetch-form disables every button while a decision is in flight.
    for (const b of document.querySelectorAll('button')) b.disabled = true
    return { el, h1: () => document.querySelector('main h1')!.textContent, status: () => document.querySelector('[data-status]')!.textContent }
  }

  it('reaching 0 while a decision is in flight doesn’t expire the page; the landed decision stands (5b)', () => {
    const c = mountInFlight(2)
    vi.advanceTimersByTime(2000)
    expect(c.h1()).toBe('Approve')
    expect(c.status()).not.toBe('This request expired.')
    // The server said OK; 2150ms after it, fetch-form swaps "Sent" in.
    document.querySelector('[data-region="body"]')!.innerHTML = '<h1>Sent</h1>'
    vi.advanceTimersByTime(1000)
    expect(c.h1()).toBe('Sent')
    expect(c.el.hidden).toBe(true)
    expect(vi.getTimerCount()).toBe(0)
  })

  it('…and if the decision fails (buttons come back), the page expires then', () => {
    const c = mountInFlight(1)
    vi.advanceTimersByTime(3000)
    expect(c.h1()).toBe('Approve')
    for (const b of document.querySelectorAll('button')) b.disabled = false
    vi.advanceTimersByTime(1000)
    expect(c.h1()).toBe('This request expired')
    expect(c.status()).toBe('This request expired.')
    expect(vi.getTimerCount()).toBe(0)
  })

  it('a countdown already at 0 expires once and never starts a timer', () => {
    vi.useFakeTimers()
    document.body.innerHTML = `<span data-status></span><span data-js="countdown" data-seconds-left="0" data-announce><span data-countdown-text></span></span>`
    const el = document.querySelector<HTMLElement>('[data-js="countdown"]')!
    initCountdown(el, () => Date.now())
    expect(document.querySelector('[data-status]')!.textContent).toBe('This request expired.')
    expect(vi.getTimerCount()).toBe(0)
  })
})
