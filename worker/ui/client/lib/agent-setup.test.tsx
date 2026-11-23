import { describe, expect, it, vi, afterEach } from 'vitest'
import { formatAgo, initAgo } from './ago'
import { initDisclose } from './disclose'
import { initFollow } from './follow'
import { initStripeFields } from './stripe-fields'
import { initTerms } from './terms'

afterEach(() => {
  document.body.innerHTML = ''
  document.documentElement.removeAttribute('data-frozen')
  vi.useRealTimers()
})

describe('disclose', () => {
  it('shows and hides its panel and keeps aria-expanded in step', () => {
    document.body.innerHTML = '<button aria-expanded="false" aria-controls="p"></button><div id="p" hidden></div>'
    const btn = document.querySelector('button')!
    const panel = document.getElementById('p')!
    initDisclose(btn)
    btn.click()
    expect(btn.getAttribute('aria-expanded')).toBe('true')
    expect(panel.hidden).toBe(false)
    btn.click()
    expect(btn.getAttribute('aria-expanded')).toBe('false')
    expect(panel.hidden).toBe(true)
  })
})

describe('follow', () => {
  it('the primary label follows the selected plan; opening a plan does not select it', () => {
    document.body.innerHTML = `<form>
      <input type="radio" name="plan" value="free" data-short="Free">
      <input type="radio" name="plan" value="growth" data-short="Growth" checked>
      <button type="button" id="more" aria-expanded="false" aria-controls="x"></button><div id="x" hidden></div>
      <button><span data-follow="plan" data-template="Continue with {label}">Continue with Growth</span></button></form>`
    const label = document.querySelector<HTMLElement>('[data-follow]')!
    initFollow(label)
    expect(label.textContent).toBe('Continue with Growth')
    const free = document.querySelector<HTMLInputElement>('[value=free]')!
    free.checked = true
    free.dispatchEvent(new Event('change', { bubbles: true }))
    expect(label.textContent).toBe('Continue with Free')
    initDisclose(document.querySelector<HTMLButtonElement>('#more')!)
    document.querySelector<HTMLButtonElement>('#more')!.click()
    expect(free.checked).toBe(true)
    expect(label.textContent).toBe('Continue with Free')
  })
  it('follows a select, using the option’s short label when it has one', () => {
    document.body.innerHTML = `<form><select name="limit">
      <option value="750" data-short="$750" selected>$750 a month</option><option value="none">No limit</option></select>
      <button><span data-follow="limit" data-template="Raise to {label}">Raise to $750</span></button></form>`
    const label = document.querySelector<HTMLElement>('[data-follow]')!
    initFollow(label)
    expect(label.textContent).toBe('Raise to $750')
    const select = document.querySelector('select')!
    select.value = 'none'
    select.dispatchEvent(new Event('change'))
    expect(label.textContent).toBe('Raise to No limit')
  })
})

describe('terms', () => {
  it('keeps the primary action disabled until the box is ticked, and again when unticked', () => {
    document.body.innerHTML = '<form><input type="checkbox" data-terms><button data-needs-terms>Approve</button><button>Not now</button></form>'
    const box = document.querySelector('input')!
    const [primary, secondary] = [...document.querySelectorAll('button')]
    initTerms(box)
    expect(primary!.disabled).toBe(true)
    expect(secondary!.disabled).toBe(false)
    box.checked = true
    box.dispatchEvent(new Event('change'))
    expect(primary!.disabled).toBe(false)
    box.checked = false
    box.dispatchEvent(new Event('change'))
    expect(primary!.disabled).toBe(true)
  })
})

describe('ago', () => {
  it('formats seconds, minutes and hours', () => {
    expect(formatAgo(4)).toBe('4s ago')
    expect(formatAgo(600)).toBe('10 min ago')
    expect(formatAgo(7200)).toBe('2 h ago')
  })
  it('counts up from the server figure every second', () => {
    vi.useFakeTimers()
    document.body.innerHTML = '<span data-seconds="58" data-verb="Updated"><span data-ago-text>Updated 58s ago</span></span>'
    initAgo(document.body.firstElementChild as HTMLElement)
    vi.advanceTimersByTime(2000)
    expect(document.querySelector('[data-ago-text]')!.textContent).toBe('Updated 1 min ago')
  })
  it('never ticks on a frozen page', () => {
    vi.useFakeTimers()
    document.documentElement.setAttribute('data-frozen', '')
    document.body.innerHTML = '<span data-seconds="4" data-verb="Updated"><span data-ago-text>Updated 4s ago</span></span>'
    initAgo(document.body.firstElementChild as HTMLElement)
    vi.advanceTimersByTime(5000)
    expect(document.querySelector('[data-ago-text]')!.textContent).toBe('Updated 4s ago')
  })
})

describe('stripe fields', () => {
  const html = (attrs: string) => `<div ${attrs}><div data-stripe-mount hidden></div><div data-stripe-picture></div></div>`
  it('leaves the picture in place without a key, a client secret or Stripe.js', () => {
    document.body.innerHTML = html('')
    const box = document.body.firstElementChild as HTMLElement
    const make = vi.fn()
    initStripeFields(box, make)
    expect(make).not.toHaveBeenCalled()
    expect(box.querySelector<HTMLElement>('[data-stripe-picture]')!.hidden).toBe(false)
  })
  it('mounts Stripe’s Payment Element and removes the picture when it has both', () => {
    document.body.innerHTML = html('data-publishable-key="pk_test_x" data-client-secret="seti_x"')
    const box = document.body.firstElementChild as HTMLElement
    const mount = vi.fn()
    const create = vi.fn(() => ({ mount }))
    const make = vi.fn(() => ({ elements: () => ({ create }) }))
    initStripeFields(box, make)
    expect(make).toHaveBeenCalledWith('pk_test_x')
    expect(create).toHaveBeenCalledWith('payment', expect.anything())
    expect(mount).toHaveBeenCalledWith(box.querySelector('[data-stripe-mount]'))
    expect(box.querySelector<HTMLElement>('[data-stripe-picture]')!.hidden).toBe(true)
  })
})
