import { describe, expect, it } from 'vitest'
import { renderHtml } from '../../render'
import { Connector } from '../../components'
import { CROSS, F_AT, FAIL_SWAP_MS, RISE, S_AT, ST, SUCCESS_SWAP_MS, T0, WAVE, connectorState, setConnector } from './connector'

describe('connector timings (motion.md#timing-constants)', () => {
  it('derive from the pulse', () => {
    expect(WAVE).toBe(2000)
    expect(RISE).toBe(0.14 * WAVE)
    expect(CROSS).toBe(RISE + 4 * ST)
    expect(S_AT).toBe(CROSS + 50)
    expect(F_AT).toBe(RISE + 2 * ST + 30)
    expect(SUCCESS_SWAP_MS).toBe(T0 + S_AT + 400 + 600)
    expect(SUCCESS_SWAP_MS).toBe(2150)
    expect(FAIL_SWAP_MS).toBe(1820)
  })
})

describe('setConnector', () => {
  it('switches data-state on the connector inside a root', async () => {
    const html = await renderHtml(<Connector left={{ kind: 'org' }} right={{ kind: 'icon', icon: 'terminal' }} />, { title: 't' })
    document.body.innerHTML = new DOMParser().parseFromString(html, 'text/html').body.innerHTML
    expect(connectorState(document.body)).toBe('idle')
    for (const s of ['connecting', 'done', 'broken', 'ok', 'fail', 'idle'] as const) {
      setConnector(document.body, s)
      expect(connectorState(document.body)).toBe(s)
    }
  })

  it('every state shares one markup: both glyphs and the ring are always present', async () => {
    const html = await renderHtml(<Connector left={{ kind: 'org' }} right={{ kind: 'monogram', text: 'Cx' }} state="ok" />, { title: 't' })
    const doc = new DOMParser().parseFromString(html, 'text/html')
    expect(doc.querySelectorAll('.id-conn__dot').length).toBe(5)
    expect(doc.querySelector('.id-conn__glyph--check')).not.toBeNull()
    expect(doc.querySelector('.id-conn__glyph--x')).not.toBeNull()
    expect(doc.querySelector('.id-conn__ring')).not.toBeNull()
    expect(doc.querySelector('.id-conn')!.getAttribute('aria-hidden')).toBe('true')
  })
})
