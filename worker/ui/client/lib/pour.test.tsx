import type { JSX } from 'hono/jsx/jsx-runtime'
import { afterEach, describe, expect, it } from 'vitest'
import { renderHtml } from '../../render'
import { Header, OrgMark } from '../../components'
import { initPour } from './pour'

async function mount(el: JSX.Element): Promise<SVGSVGElement> {
  const html = await renderHtml(el, { title: 't' })
  document.body.innerHTML = new DOMParser().parseFromString(html, 'text/html').body.innerHTML
  return document.querySelector('svg')!
}

afterEach(() => (document.body.innerHTML = ''))

describe('pour.ts', () => {
  it('the header mark pours on load: six marks in groups, data-pour="load"', async () => {
    const mark = await mount(<Header />)
    expect(mark.dataset.js).toBe('pour')
    expect(mark.getAttribute('data-pour')).toBe('load')
    expect(mark.querySelectorAll(':scope > g.id-mark__mk > ellipse')).toHaveLength(6)
  })

  it('other marks stay still and plain (tiles, footer, emails)', async () => {
    const mark = await mount(<OrgMark size={28} />)
    expect(mark.hasAttribute('data-pour')).toBe(false)
    expect(mark.querySelector('g')).toBeNull()
  })

  it('settles when the load pour has already ended, then pours again on hover until the last mark lands', async () => {
    const mark = await mount(<Header />)
    initPour(mark)
    expect(mark.hasAttribute('data-pour')).toBe(false)
    const brand = mark.closest('a')!
    brand.dispatchEvent(new Event('mouseenter'))
    expect(mark.getAttribute('data-pour')).toBe('hover')
    mark.firstElementChild!.dispatchEvent(new Event('animationend'))
    expect(mark.getAttribute('data-pour')).toBe('hover')
    mark.lastElementChild!.dispatchEvent(new Event('animationend'))
    expect(mark.hasAttribute('data-pour')).toBe(false)
  })
})
