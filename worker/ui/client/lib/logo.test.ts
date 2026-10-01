import { afterEach, describe, expect, it } from 'vitest'
import { initLogo } from './logo'

afterEach(() => (document.body.innerHTML = ''))

function mount(complete: boolean): HTMLElement {
  document.body.innerHTML = '<div data-js="logo" data-monogram="Cx"><img src="https://example.invalid/logo.png"></div>'
  const img = document.querySelector('img')!
  Object.defineProperty(img, 'complete', { value: complete })
  Object.defineProperty(img, 'naturalWidth', { value: 0 })
  return document.querySelector<HTMLElement>('[data-js="logo"]')!
}

describe('logo.ts', () => {
  it('falls back to the monogram when the logo fails to load', () => {
    const tile = mount(false)
    initLogo(tile)
    expect(tile.querySelector('img')).not.toBeNull()
    tile.querySelector('img')!.dispatchEvent(new Event('error'))
    expect(tile.textContent).toBe('Cx')
    expect(tile.querySelector('img')).toBeNull()
  })

  it('falls back at once when the logo already failed before the script ran', () => {
    const tile = mount(true)
    initLogo(tile)
    expect(tile.textContent).toBe('Cx')
  })
})
