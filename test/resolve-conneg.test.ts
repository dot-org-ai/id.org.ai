/**
 * Pure-unit tests for the ported conneg selector (worker/resolve/conneg.ts).
 * No worker / DO - auto-globbed by the workers pool but exercises only pure fns.
 */
import { describe, it, expect } from 'vitest'
import { negotiate, alternatesHeader, FACE_CONTENT_TYPE, type Face } from '../worker/resolve/conneg'

const AVAILABLE: Face[] = ['html', 'jsonld', 'json']

function req(headers: Record<string, string>): Request {
  return new Request('https://id.org.ai/vin/1HGCM82633A004352', { headers })
}

describe('negotiate - extension forces', () => {
  it('honours a .json extension and strips it', () => {
    const r = negotiate(req({}), '/vin/1HGCM82633A004352.json', { available: AVAILABLE })
    expect(r.face).toBe('json')
    expect(r.cleanPath).toBe('/vin/1HGCM82633A004352')
    expect(r.forced).toBe('extension')
  })

  it('honours a .jsonld extension', () => {
    const r = negotiate(req({}), '/01/09506000134352.jsonld', { available: AVAILABLE })
    expect(r.face).toBe('jsonld')
    expect(r.cleanPath).toBe('/01/09506000134352')
  })
})

describe('negotiate - Accept header', () => {
  it('application/ld+json → jsonld', () => {
    const r = negotiate(req({ accept: 'application/ld+json' }), '/vin/x', { available: AVAILABLE })
    expect(r.face).toBe('jsonld')
    expect(r.forced).toBe('accept')
  })

  it('application/json → json', () => {
    const r = negotiate(req({ accept: 'application/json' }), '/vin/x', { available: AVAILABLE })
    expect(r.face).toBe('json')
  })

  it('text/html → html (the redirect face)', () => {
    const r = negotiate(req({ accept: 'text/html' }), '/vin/x', { available: AVAILABLE })
    expect(r.face).toBe('html')
  })

  it('linkset Accept does NOT select linkset in stage 1 (not available) - falls through to default', () => {
    const r = negotiate(req({ accept: 'application/linkset+json' }), '/vin/x', { available: AVAILABLE })
    expect(r.face).not.toBe('linkset')
  })
})

describe('negotiate - client-class defaults', () => {
  it('browser via Sec-Fetch-Mode navigate → html', () => {
    const r = negotiate(req({ 'sec-fetch-mode': 'navigate' }), '/vin/x', { available: AVAILABLE })
    expect(r.face).toBe('html')
    expect(r.forced).toContain('browser')
  })

  it('bare client (no Accept, no Sec-Fetch) → jsonld default', () => {
    const r = negotiate(req({}), '/vin/x', { available: AVAILABLE })
    expect(r.face).toBe('jsonld')
    expect(r.forced).toContain('default')
  })

  it('agent UA with md unavailable → falls to jsonld default (md deferred)', () => {
    const r = negotiate(req({ 'user-agent': 'claude-bot/1.0' }), '/vin/x', { available: AVAILABLE })
    expect(r.face).toBe('jsonld')
  })
})

describe('alternatesHeader + content types', () => {
  it('advertises the two body faces with correct types', () => {
    const h = alternatesHeader('/vin/1HGCM82633A004352', ['jsonld', 'json'])
    expect(h).toContain('/vin/1HGCM82633A004352.jsonld>; rel="alternate"; type="application/ld+json"')
    expect(h).toContain('/vin/1HGCM82633A004352.json>; rel="alternate"; type="application/json"')
  })

  it('maps every face to a charset-qualified content type', () => {
    expect(FACE_CONTENT_TYPE.jsonld).toBe('application/ld+json; charset=utf-8')
    expect(FACE_CONTENT_TYPE.json).toBe('application/json; charset=utf-8')
  })
})
