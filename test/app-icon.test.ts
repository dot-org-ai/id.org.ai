/**
 * worker/utils/app-icon.ts: the icon an app's own site declares (logos.md), for
 * the trusted-account apps that have no client metadata. Only hosts on
 * TRUSTED_ACCOUNT_DOMAINS are fetched; the answer is cached in KV.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { env, fetchMock } from 'cloudflare:test'
import { pickIcon, siteIcon } from '../worker/utils/app-icon'

const PAGE = 'https://app.example/deck'

describe('pickIcon', () => {
  it('takes an SVG first, then the largest size; apple-touch-icon counts as 180', () => {
    const head = `
      <link rel="icon" href="/favicon-32.png" sizes="32x32">
      <link rel="apple-touch-icon" href="/touch.png">
      <link rel="icon" href="/icon-512.png" sizes="512x512">`
    expect(pickIcon(head, PAGE)).toBe('https://app.example/icon-512.png')
    expect(pickIcon(head + '<link rel="icon" type="image/svg+xml" href="/mark.svg">', PAGE)).toBe('https://app.example/mark.svg')
    expect(pickIcon('<link rel="shortcut icon" href="/favicon.ico"><link rel="apple-touch-icon" href="/touch.png">', PAGE)).toBe('https://app.example/touch.png')
  })

  it('keeps an image data: icon as declared, with its entities decoded', () => {
    const data = 'data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%2F%3E'
    expect(pickIcon(`<link rel="icon" type="image/svg+xml" href="${data}">`, PAGE)).toBe(data)
    expect(pickIcon('<link rel="icon" href="/i.png?a=1&amp;b=2">', PAGE)).toBe('https://app.example/i.png?a=1&b=2')
  })

  it('ignores what a tile can’t or shouldn’t load: http, javascript:, other data:, mask icons, stylesheets', () => {
    const head = `
      <link rel="icon" href="http://app.example/insecure.png">
      <link rel="icon" href="javascript:alert(1)">
      <link rel="icon" href="data:text/html,hi">
      <link rel="mask-icon" href="/mask.svg">
      <link rel="stylesheet" href="/site.css">`
    expect(pickIcon(head, PAGE)).toBeUndefined()
  })
})

describe('siteIcon', () => {
  beforeAll(() => {
    fetchMock.activate()
    fetchMock.disableNetConnect()
  })
  afterAll(() => fetchMock.deactivate())

  it('never fetches a host that isn’t a trusted-account app', async () => {
    // net connect is off and nothing is mocked: a fetch would throw, and this is still undefined
    expect(await siteIcon(env, 'evil.example')).toBeUndefined()
    expect(await env.SESSIONS.get('app-icon:evil.example')).toBeNull()
  })

  it('reads a trusted app’s home page once, then answers from the cache', async () => {
    fetchMock
      .get('https://startup.games')
      .intercept({ path: '/' })
      .reply(200, '<html><head><link rel="icon" type="image/svg+xml" href="/logo.svg"></head><body>…</body></html>', { headers: { 'content-type': 'text/html' } })
    expect(await siteIcon(env, 'startup.games')).toBe('https://startup.games/logo.svg')
    // no second intercept: this one comes from KV
    expect(await siteIcon(env, 'startup.games')).toBe('https://startup.games/logo.svg')
  })

  it('falls back to /favicon.ico, and a failed fetch is not cached', async () => {
    await env.SESSIONS.delete('app-icon:pitch.startups.studio')
    // nothing mocked: the fetch fails, nothing is cached, and the page shows the mail icon
    expect(await siteIcon(env, 'pitch.startups.studio')).toBeUndefined()
    expect(await env.SESSIONS.get('app-icon:pitch.startups.studio')).toBeNull()
    const pitch = fetchMock.get('https://pitch.startups.studio')
    pitch.intercept({ path: '/' }).reply(200, '<html><head><title>Deck</title></head></html>', { headers: { 'content-type': 'text/html' } })
    pitch.intercept({ path: '/favicon.ico', method: 'HEAD' }).reply(200, '', { headers: { 'content-type': 'image/x-icon' } })
    expect(await siteIcon(env, 'pitch.startups.studio')).toBe('https://pitch.startups.studio/favicon.ico')
  })
})
