import { afterEach, describe, expect, it } from 'vitest'
import { renderHtml } from '../../render'
import { CodeInput } from '../../components'
import { initCodeInput, normalise } from './code-input'

async function mount(length: 6 | 8, value = ''): Promise<{ group: HTMLElement; boxes: HTMLInputElement[] }> {
  const html = await renderHtml(<CodeInput length={length} value={value} label="Enter the code" />, { title: 't' })
  document.body.innerHTML = new DOMParser().parseFromString(html, 'text/html').body.innerHTML
  const group = document.querySelector<HTMLElement>('[data-js="code-input"]')!
  initCodeInput(group)
  return { group, boxes: Array.from(group.querySelectorAll('input')) }
}

function type(box: HTMLInputElement, value: string) {
  box.value = value
  box.dispatchEvent(new Event('input', { bubbles: true }))
}

function paste(box: HTMLInputElement, text: string) {
  const e = new Event('paste', { bubbles: true, cancelable: true }) as Event & { clipboardData: { getData: () => string } }
  Object.defineProperty(e, 'clipboardData', { value: { getData: () => text } })
  box.dispatchEvent(e)
}

afterEach(() => (document.body.innerHTML = ''))

describe('normalise', () => {
  it('accepts device codes with or without the hyphen or spaces, uppercased, alphabet only', () => {
    for (const raw of ['WDJB-MJHT', 'wdjbmjht', 'WDJB MJHT']) expect(normalise(raw, true).join('')).toBe('WDJBMJHT')
    expect(normalise('W0O1', true).join('')).toBe('W') // 0, O and 1 aren't in the alphabet
    expect(normalise('48 29-13', false).join('')).toBe('482913')
    expect(normalise('4a8', false).join('')).toBe('48')
  })
})

describe('code-input.ts', () => {
  it('focuses the first empty box on load', async () => {
    const { boxes } = await mount(6, '48')
    expect(document.activeElement).toBe(boxes[2])
  })

  it('does not autofocus when frozen', async () => {
    document.documentElement.setAttribute('data-frozen', '')
    await mount(6)
    expect(document.activeElement).toBe(document.body)
    document.documentElement.removeAttribute('data-frozen')
  })

  it('advances on typing and goes back on Backspace in an empty box', async () => {
    const { boxes } = await mount(6)
    type(boxes[0]!, '4')
    expect(document.activeElement).toBe(boxes[1])
    boxes[1]!.dispatchEvent(new KeyboardEvent('keydown', { key: 'Backspace', bubbles: true, cancelable: true }))
    expect(document.activeElement).toBe(boxes[0])
    expect(boxes[0]!.value).toBe('')
  })

  it('ignores characters outside the code (digits only for 6, the alphabet for 8)', async () => {
    const { boxes } = await mount(6)
    type(boxes[0]!, 'x')
    expect(boxes[0]!.value).toBe('')
  })

  it('arrow keys move between boxes', async () => {
    const { boxes } = await mount(6)
    boxes[2]!.focus()
    boxes[2]!.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowLeft', bubbles: true, cancelable: true }))
    expect(document.activeElement).toBe(boxes[1])
    boxes[1]!.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowRight', bubbles: true, cancelable: true }))
    expect(document.activeElement).toBe(boxes[2])
  })

  it('paste fills every box, from any box, and uppercases device codes', async () => {
    const { boxes } = await mount(8)
    paste(boxes[3]!, 'wdjb-mjht')
    expect(boxes.map((b) => b.value).join('')).toBe('WDJBMJHT')
    expect(document.activeElement).toBe(boxes[7])
  })

  it('never submits on its own', async () => {
    const { group, boxes } = await mount(6)
    const form = document.createElement('form')
    let submitted = false
    form.addEventListener('submit', (e) => {
      submitted = true
      e.preventDefault()
    })
    form.appendChild(group)
    document.body.appendChild(form)
    paste(boxes[0]!, '482913')
    expect(submitted).toBe(false)
  })
})
