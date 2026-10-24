/**
 * worker/utils/sign-in-route.ts: which way a known address signs in.
 */
import { describe, it, expect } from 'vitest'
import { routeForMx, signInRouteFor } from '../worker/utils/sign-in-route'
import { continueOrigins } from '../worker/routes/login-email'

/** A DoH stand-in answering MX hosts per domain, counting lookups. */
function doh(answers: Record<string, string[]>) {
  const calls: string[] = []
  const fetch = async (input: RequestInfo | URL) => {
    const name = new URL(String(input)).searchParams.get('name')!
    calls.push(name)
    const hosts = answers[name]
    if (!hosts) return new Response('', { status: 503 })
    return Response.json({ Status: 0, Answer: hosts.map((h, i) => ({ name, type: 15, data: `${i * 10} ${h}.` })) })
  }
  return { fetch, calls }
}

describe('signInRouteFor', () => {
  it('gmail and googlemail go to Google with no lookup', async () => {
    const d = doh({})
    expect(await signInRouteFor('Someone@Gmail.com', { fetch: d.fetch })).toBe('google')
    expect(await signInRouteFor('a@googlemail.com', { fetch: d.fetch })).toBe('google')
    expect(d.calls).toEqual([])
  })

  it('Microsoft consumer domains go to Microsoft with no lookup', async () => {
    const d = doh({})
    for (const domain of ['outlook.com', 'hotmail.com', 'live.com', 'msn.com']) expect(await signInRouteFor(`a@${domain}`, { fetch: d.fetch })).toBe('microsoft')
    expect(d.calls).toEqual([])
  })

  it('reads Google Workspace and Microsoft 365 from MX', async () => {
    const d = doh({
      'gws.example': ['aspmx.l.google.com', 'alt1.aspmx.l.google.com'],
      'smtp-google.example': ['smtp.google.com'],
      'm365.example': ['m365-example.mail.protection.outlook.com'],
      'own.example': ['mx1.own.example'],
    })
    expect(await signInRouteFor('a@gws.example', { fetch: d.fetch })).toBe('google')
    expect(await signInRouteFor('a@smtp-google.example', { fetch: d.fetch })).toBe('google')
    expect(await signInRouteFor('a@m365.example', { fetch: d.fetch })).toBe('microsoft')
    expect(await signInRouteFor('a@own.example', { fetch: d.fetch })).toBe('email')
  })

  it('caches a domain for an hour', async () => {
    const d = doh({ 'cached.example': ['aspmx.l.google.com'] })
    const now = 1_000_000
    expect(await signInRouteFor('a@cached.example', { fetch: d.fetch, now })).toBe('google')
    expect(await signInRouteFor('b@cached.example', { fetch: d.fetch, now: now + 59 * 60_000 })).toBe('google')
    expect(d.calls).toEqual(['cached.example'])
    await signInRouteFor('c@cached.example', { fetch: d.fetch, now: now + 61 * 60_000 })
    expect(d.calls).toEqual(['cached.example', 'cached.example'])
  })

  it('falls back to the email code on a failed or thrown lookup, and on a malformed address', async () => {
    expect(await signInRouteFor('a@down.example', { fetch: doh({}).fetch })).toBe('email')
    expect(await signInRouteFor('a@throws.example', { fetch: async () => { throw new Error('timeout') } })).toBe('email')
    expect(await signInRouteFor('nodomain', { fetch: doh({}).fetch })).toBe('email')
  })
})

describe('routeForMx', () => {
  it('needs the provider’s own domain, not a look-alike', () => {
    expect(routeForMx(['mx.notgoogle.com'])).toBeNull()
    expect(routeForMx(['google.com.evil.example'])).toBeNull()
    expect(routeForMx(['ASPMX.L.GOOGLE.COM.'])).toBe('google')
  })
})

describe('continueOrigins (1b form-action)', () => {
  it('adds an absolute continue’s origin, or an authorize continue’s redirect_uri origin, and nothing for a local path', () => {
    const own = 'https://id.org.ai'
    expect(continueOrigins('/dash/profile', own)).toEqual([])
    expect(continueOrigins('https://headless.ly/after', own)).toEqual(['https://headless.ly'])
    const authorize = `${own}/oauth/authorize?client_id=cid_trusted_account_v1&redirect_uri=${encodeURIComponent('https://pitch.startups.studio/auth/callback')}`
    expect(continueOrigins(authorize, own)).toEqual(['https://pitch.startups.studio'])
    expect(continueOrigins(`${own}/oauth/authorize?redirect_uri=javascript%3Aalert(1)`, own)).toEqual([])
  })
})
