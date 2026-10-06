/**
 * Phones and touch screens (owner direction, 2026-10-06): the head connector
 * shrinks on phones, and form controls follow mobile practice: 16px text so
 * iOS Safari doesn't zoom the page when a field takes focus, 48px controls on
 * phones, a visible focus ring, and autofill that keeps the card's colours.
 *
 * `pnpm test:phone` checks the same things in real Chromium and WebKit against
 * the gallery; these guard the rules in the gate.
 */
import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

const css = readFileSync('worker/ui/ui.css', 'utf8')

/** The bodies of every `@media <query> { … }` block, joined. */
function media(query: string): string {
  const head = `@media ${query} {`
  let out = ''
  for (let at = css.indexOf(head); at !== -1; at = css.indexOf(head, at + 1)) {
    let depth = 0
    for (let i = at + head.length - 1; i < css.length; i++) {
      if (css[i] === '{') depth++
      else if (css[i] === '}' && --depth === 0) {
        out += css.slice(at + head.length, i)
        break
      }
    }
  }
  return out
}

describe('phones (<= 480px)', () => {
  const phone = media('(max-width: 480px)')

  it('show the middle three connector dots: the middle one still becomes the verdict', () => {
    expect(phone).toMatch(/\.id-conn__dot--0,\s*\.id-conn__dot--4\s*{\s*display:\s*none;/)
    expect(phone).not.toMatch(/\.id-conn__dot--[123]\b[^{]*{\s*display:\s*none/)
  })

  it('scale the head tiles to 48px (56 × 0.857), connector ring included', () => {
    expect(phone).toMatch(/\.id-tile-wrap\s*{\s*zoom:\s*0\.857;/)
  })

  it('make inputs, selects and md buttons 48px tall, like the action band', () => {
    expect(phone).toMatch(/\.id-input:not\(\.id-textarea\),\s*\.id-btn:not\(\.id-btn--sm\)\s*{\s*min-height:\s*var\(--id-control-h-phone\);/)
  })

  it('give a checkbox row a 44px target', () => {
    expect(phone).toMatch(/\.id-check\s*{\s*min-height:\s*44px;/)
  })
})

describe('phones and touch screens', () => {
  // Landscape iPhones are wider than 480px, so coarse pointers get the same text size.
  const touch = media('(max-width: 480px), (pointer: coarse)')

  it('set field text to 16px so iOS Safari does not zoom on focus', () => {
    expect(touch).toMatch(/\.id-input,\s*\.id-select option\s*{\s*font-size:\s*16px;/)
  })

  it('give each option in the styled list a 44px row', () => {
    expect(touch).toMatch(/\.id-select option\s*{\s*min-height:\s*44px;/)
  })
})

describe('every screen size', () => {
  it('rings a focused field the way a focused code box is ringed', () => {
    expect(css).toMatch(/\.id-input:focus\s*{\s*border-color:\s*var\(--id-select\);\s*box-shadow:\s*var\(--id-sh-input\),\s*var\(--id-ring\);/)
  })

  it('drops the native field styling (iOS inner shadow and corners)', () => {
    const input = css.match(/\n\.id-input\s*{([^}]*)}/)?.[1] ?? ''
    expect(input).toMatch(/-webkit-appearance:\s*none;/)
    expect(input).toMatch(/\bappearance:\s*none;/)
  })

  it('keeps autofilled fields on the card colours in Chrome, Safari and Firefox', () => {
    const rule = css.match(/\.id-input:-webkit-autofill\s*{([^}]*)}/)?.[1] ?? ''
    expect(rule).toMatch(/-webkit-text-fill-color:\s*var\(--id-fg\);/)
    expect(rule).toMatch(/box-shadow:\s*var\(--id-sh-input\),\s*inset 0 0 0 100px var\(--id-panel\);/)
    expect(rule).toMatch(/filter:\s*none;/)
    expect(css).toMatch(/\.id-input:-webkit-autofill:focus\s*{\s*box-shadow:\s*var\(--id-sh-input\),\s*inset 0 0 0 100px var\(--id-panel\),\s*var\(--id-ring\);/)
  })

  it('turns off the grey tap flash and iOS text inflation', () => {
    expect(css).toMatch(/\nhtml\s*{\s*-webkit-text-size-adjust:\s*100%;\s*text-size-adjust:\s*100%;/)
    const body = css.match(/\nbody\s*{([^}]*)}/)?.[1] ?? ''
    expect(body).toMatch(/-webkit-tap-highlight-color:\s*transparent;/)
  })

  it('never stops people zooming', () => {
    const render = readFileSync('worker/ui/render.tsx', 'utf8')
    expect(render).toMatch(/<meta name="viewport" content="width=device-width, initial-scale=1" \/>/)
    expect(render).not.toMatch(/maximum-scale|user-scalable/)
  })
})
