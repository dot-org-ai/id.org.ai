/**
 * Email verification-code fallback — unit tests.
 *
 * This path is what a Zebra viewer uses when their tenant blocks consent to an
 * unapproved app, so it is the one path that MUST work with no cooperation
 * from anybody's IT department. Tested end to end at the module level:
 * throttling, transport calls, error classification, principal mapping.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import {
  workosMagicAuthChannel,
  emailCodePrincipal,
  allowEmailCodeSend,
  isPlausibleEmail,
  isPlausibleCode,
  normalizeEmail,
} from '../src/sdk/federation/email-code'
import type { ThrottleStore } from '../src/sdk/federation/email-code'
import { FederationError } from '../src/sdk/federation/types'

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

/** In-memory ThrottleStore — the same seam the worker backs with the DO. */
function memoryStore(): ThrottleStore {
  const map = new Map<string, { count: number; windowStartedAt: number }>()
  return {
    async get(key) {
      return map.get(key)
    },
    async put(key, value) {
      map.set(key, value)
    },
  }
}

const channelConfig = { apiKey: 'sk_test_workos', clientId: 'client_test' }

// ── Input validation ──────────────────────────────────────────────────────

describe('input validation', () => {
  it('accepts ordinary corporate addresses', () => {
    expect(isPlausibleEmail('alice@zebra.com')).toBe(true)
    expect(isPlausibleEmail('alice.anders@na.zebra.com')).toBe(true)
    expect(isPlausibleEmail('a+tag@zebra.co.uk')).toBe(true)
  })

  it('rejects obvious non-addresses', () => {
    expect(isPlausibleEmail('alice')).toBe(false)
    expect(isPlausibleEmail('alice@zebra')).toBe(false)
    expect(isPlausibleEmail('alice @zebra.com')).toBe(false)
    expect(isPlausibleEmail('')).toBe(false)
  })

  it('normalises case and surrounding whitespace', () => {
    expect(normalizeEmail('  Alice@Zebra.COM ')).toBe('alice@zebra.com')
  })

  it('accepts only 6-digit codes', () => {
    expect(isPlausibleCode('123456')).toBe(true)
    expect(isPlausibleCode(' 123456 ')).toBe(true)
    expect(isPlausibleCode('12345')).toBe(false)
    expect(isPlausibleCode('abcdef')).toBe(false)
  })
})

// ── Send throttling ───────────────────────────────────────────────────────

describe('allowEmailCodeSend', () => {
  it('permits the default budget then refuses', async () => {
    const store = memoryStore()
    for (let i = 0; i < 5; i++) {
      expect(await allowEmailCodeSend(store, 'alice@zebra.com')).toBe(true)
    }
    expect(await allowEmailCodeSend(store, 'alice@zebra.com')).toBe(false)
  })

  it('counts case variants of the same address together', async () => {
    const store = memoryStore()
    await allowEmailCodeSend(store, 'alice@zebra.com', { max: 2 })
    await allowEmailCodeSend(store, 'ALICE@ZEBRA.COM', { max: 2 })
    expect(await allowEmailCodeSend(store, 'Alice@Zebra.com', { max: 2 })).toBe(false)
  })

  it('budgets each address separately', async () => {
    const store = memoryStore()
    await allowEmailCodeSend(store, 'alice@zebra.com', { max: 1 })
    expect(await allowEmailCodeSend(store, 'bob@zebra.com', { max: 1 })).toBe(true)
  })

  it('reopens the budget after the window elapses', async () => {
    const store = memoryStore()
    expect(await allowEmailCodeSend(store, 'alice@zebra.com', { max: 1, windowMs: 1 })).toBe(true)
    await new Promise((r) => setTimeout(r, 5))
    expect(await allowEmailCodeSend(store, 'alice@zebra.com', { max: 1, windowMs: 1 })).toBe(true)
  })
})

// ── WorkOS Magic Auth transport ───────────────────────────────────────────

describe('workosMagicAuthChannel.send', () => {
  let mockFetch: ReturnType<typeof vi.fn>

  beforeEach(() => {
    mockFetch = vi.fn()
    vi.stubGlobal('fetch', mockFetch)
  })
  afterEach(() => vi.restoreAllMocks())

  it('posts the normalised email to the magic_auth endpoint with the API key', async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ id: 'magic_auth_1', expires_at: '2026-07-29T12:00:00Z' }))
    const result = await workosMagicAuthChannel(channelConfig).send('  Alice@Zebra.com ')

    const [url, options] = mockFetch.mock.calls[0]
    expect(url).toBe('https://api.workos.com/user_management/magic_auth')
    expect(options.headers.Authorization).toBe('Bearer sk_test_workos')
    expect(JSON.parse(options.body as string)).toEqual({ email: 'alice@zebra.com' })
    expect(result.id).toBe('magic_auth_1')
    expect(result.expiresAt).toBe(Date.parse('2026-07-29T12:00:00Z'))
  })

  it('retries the legacy /magic_auth/send path on a 404 rather than failing the viewer', async () => {
    mockFetch.mockResolvedValueOnce(new Response('', { status: 404 })).mockResolvedValueOnce(jsonResponse({}))
    await workosMagicAuthChannel(channelConfig).send('alice@zebra.com')

    expect(mockFetch).toHaveBeenCalledTimes(2)
    expect(mockFetch.mock.calls[1][0]).toBe('https://api.workos.com/user_management/magic_auth/send')
  })

  it('surfaces a genuine upstream failure as a FederationError', async () => {
    mockFetch.mockResolvedValueOnce(new Response('upstream exploded', { status: 500 }))
    await expect(workosMagicAuthChannel(channelConfig).send('alice@zebra.com')).rejects.toMatchObject({
      kind: 'upstream-error',
    })
  })
})

describe('workosMagicAuthChannel.verify', () => {
  let mockFetch: ReturnType<typeof vi.fn>

  beforeEach(() => {
    mockFetch = vi.fn()
    vi.stubGlobal('fetch', mockFetch)
  })
  afterEach(() => vi.restoreAllMocks())

  it('exchanges the code through the magic-auth grant and returns the subject', async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({ user: { id: 'user_01H', email: 'alice@zebra.com', first_name: 'Alice', last_name: 'Anders' } }),
    )
    const result = await workosMagicAuthChannel(channelConfig).verify('Alice@Zebra.com', '123456')

    const [url, options] = mockFetch.mock.calls[0]
    expect(url).toBe('https://api.workos.com/user_management/authenticate')
    const body = new URLSearchParams(options.body as string)
    expect(body.get('grant_type')).toBe('urn:workos:oauth:grant-type:magic-auth')
    expect(body.get('email')).toBe('alice@zebra.com')
    expect(body.get('code')).toBe('123456')
    expect(result.subject).toBe('user_01H')
    expect(result.name).toBe('Alice Anders')
  })

  it('classifies a wrong or expired code as access-denied, not an outage', async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ code: 'invalid_one_time_code' }, 400))
    await expect(workosMagicAuthChannel(channelConfig).verify('alice@zebra.com', '000000')).rejects.toMatchObject({
      kind: 'access-denied',
      upstreamCode: 'invalid_one_time_code',
    })
  })

  it('classifies a 500 as an upstream error so the UI can say "try again"', async () => {
    mockFetch.mockResolvedValueOnce(new Response('boom', { status: 500 }))
    await expect(workosMagicAuthChannel(channelConfig).verify('alice@zebra.com', '123456')).rejects.toMatchObject({
      kind: 'upstream-error',
    })
  })
})

// ── Principal mapping ─────────────────────────────────────────────────────

describe('emailCodePrincipal', () => {
  it('records email-code assurance honestly — never federated-idp', () => {
    const principal = emailCodePrincipal('Alice@Zebra.com', { subject: 'user_01H', name: 'Alice Anders' })
    expect(principal.provenance.assurance).toBe('email-code')
    expect(principal.provenance.provider).toBe('email-code')
  })

  it('keys the principal on the email, not on the transport user id', () => {
    const principal = emailCodePrincipal('alice@zebra.com', { subject: 'user_01H' })
    expect(principal.identityId).toBe('human:email:alice@zebra.com')
    // The transport subject is kept as evidence, in provenance.
    expect(principal.provenance.subject).toBe('user_01H')
  })

  it('is stable across casing so one mailbox is one principal', () => {
    const a = emailCodePrincipal('Alice@Zebra.com', {})
    const b = emailCodePrincipal('alice@zebra.com', {})
    expect(a.identityId).toBe(b.identityId)
  })

  it('names the broker as issuer — no IdP asserted anything here', () => {
    const principal = emailCodePrincipal('alice@zebra.com', {})
    expect(principal.provenance.issuer).toBe('https://id.org.ai')
    expect(principal.provenance.tenantId).toBeUndefined()
  })

  it('derives the email domain a gate keys on', () => {
    expect(emailCodePrincipal('alice@zebra.com', {}).provenance.emailDomain).toBe('zebra.com')
  })

  it('falls back to the transport subject when no user id is returned', () => {
    expect(emailCodePrincipal('alice@zebra.com', {}).provenance.subject).toBe('alice@zebra.com')
  })

  it('rejects a non-address', () => {
    expect(() => emailCodePrincipal('alice', {})).toThrow(FederationError)
  })

  it('produces a DIFFERENT principal id from the Microsoft path for the same human', () => {
    // Deliberate: the two paths carry different assurance, so they are
    // different principals. A gate that wants to treat them as one person keys
    // on the verified email, which both carry.
    const viaEmail = emailCodePrincipal('alice@zebra.com', {})
    expect(viaEmail.identityId.startsWith('human:email:')).toBe(true)
    expect(viaEmail.identityId.startsWith('human:ms:')).toBe(false)
    expect(viaEmail.email).toBe('alice@zebra.com')
  })
})
