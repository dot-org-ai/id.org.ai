import { afterEach, describe, expect, it, vi } from 'vitest'
import { enhance, isFrozen } from './dom'

afterEach(() => {
  document.documentElement.removeAttribute('data-frozen')
  document.body.innerHTML = ''
})

describe('isFrozen', () => {
  it('reads <html data-frozen>', () => {
    expect(isFrozen()).toBe(false)
    document.documentElement.setAttribute('data-frozen', '')
    expect(isFrozen()).toBe(true)
  })
})

describe('enhance', () => {
  it('initialises each [data-js] element once', () => {
    document.body.innerHTML = '<div data-js="x"></div><div data-js="x"></div><div data-js="y"></div>'
    const init = vi.fn()
    enhance('x', init)
    enhance('x', init)
    expect(init).toHaveBeenCalledTimes(2)
  })
})
