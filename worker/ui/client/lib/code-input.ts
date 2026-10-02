/**
 * Code boxes (components.md#code-input): typing advances, Backspace on an
 * empty box goes back, arrows move, and pasting a whole code fills every box
 * ("WDJB-MJHT", "wdjbmjht" and "WDJB MJHT" all work; device codes uppercase).
 * Never auto-submits. Focuses the first empty box on load, except when frozen.
 */
import { isFrozen } from './dom'

const DEVICE_ALPHABET = /[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]/

export function normalise(raw: string, device: boolean): string[] {
  const chars = raw.replace(/[\s-]/g, '').toUpperCase().split('')
  return chars.filter((c) => (device ? DEVICE_ALPHABET.test(c) : /\d/.test(c)))
}

export function initCodeInput(group: HTMLElement): void {
  const boxes = Array.from(group.querySelectorAll<HTMLInputElement>('input.id-code__box'))
  const device = group.dataset.length === '8'
  const focusAt = (i: number) => boxes[Math.max(0, Math.min(boxes.length - 1, i))]?.focus()
  const fill = (start: number, chars: string[]) => {
    let i = start
    for (const c of chars) {
      if (i >= boxes.length) break
      boxes[i]!.value = c
      i++
    }
    focusAt(i < boxes.length ? i : boxes.length - 1)
  }

  boxes.forEach((box, i) => {
    // Typing over a filled box replaces its character.
    box.addEventListener('focus', () => box.select())
    box.addEventListener('input', () => {
      const chars = normalise(box.value, device)
      if (chars.length === 0) {
        box.value = ''
        return
      }
      if (chars.length > 1) {
        box.value = ''
        fill(i, chars)
        return
      }
      box.value = chars[0]!
      if (i < boxes.length - 1) focusAt(i + 1)
    })
    box.addEventListener('keydown', (e) => {
      if (e.key === 'Backspace' && box.value === '' && i > 0) {
        e.preventDefault()
        boxes[i - 1]!.value = ''
        focusAt(i - 1)
      } else if (e.key === 'ArrowLeft') {
        e.preventDefault()
        focusAt(i - 1)
      } else if (e.key === 'ArrowRight') {
        e.preventDefault()
        focusAt(i + 1)
      }
    })
    box.addEventListener('paste', (e) => {
      const text = e.clipboardData?.getData('text') ?? ''
      const chars = normalise(text, device)
      if (chars.length === 0) return
      e.preventDefault()
      fill(chars.length >= boxes.length ? 0 : i, chars)
    })
  })

  if (!isFrozen()) {
    const firstEmpty = boxes.find((b) => b.value === '')
    firstEmpty?.focus()
  }
}

