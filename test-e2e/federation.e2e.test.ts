/**
 * Flow 8: Upstream federation — Microsoft Entra + email-code fallback.
 *
 * Runs against a LIVE id.org.ai (or a preview URL via ID_URL). Three layers,
 * each skipping cleanly when its prerequisite is absent, so this file is safe
 * to run at any point in the rollout and tells you exactly how far along it is:
 *
 *   A. Discovery       — /federation/status. Needs only a deploy.
 *   B. Authorization   — /federation/microsoft/start builds a correct Entra
 *                        request. Needs MICROSOFT_CLIENT_ID set. Proves the
 *                        request is well-formed WITHOUT any Microsoft account:
 *                        everything up to the moment Entra shows a login page
 *                        is ours, and this asserts all of it.
 *   C. Email fallback  — the full loop: request a code at a @emails.do address,
 *                        poll ClickHouse for the mail, submit the code, and
 *                        check the issued token. Needs CLICKHOUSE_PASSWORD.
 *
 * What NO test here can cover, by construction: whether Zebra's own tenant
 * consent policy admits our app. That is a decision made inside a directory we
 * have no access to, discoverable only when a zebra.com user actually signs in.
 * Layer C is the mitigation, which is why it is tested hardest.
 */

import { describe, it, expect, beforeAll } from 'vitest'
import { waitForEmail, extractVerificationCode } from './helpers/email'

const ID_URL = process.env.ID_URL || 'https://id.org.ai'

/** A mailbox the ClickHouse email harness can read. */
const TEST_MAILBOX = process.env.E2E_FEDERATION_EMAIL || 'e2e-federation-test@emails.do'

const hasClickHouse = !!process.env.CLICKHOUSE_PASSWORD && !!process.env.CLICKHOUSE_URL

interface FederationStatus {
  microsoft: {
    configured: boolean
    tenant: string
    redirectUri: string
    allowedTenants: string[] | null
    confidentialClient: boolean
  }
  emailCode: { configured: boolean }
}

let status: FederationStatus | null = null
let deployed = false

beforeAll(async () => {
  const res = await fetch(`${ID_URL}/federation/status`).catch(() => null)
  if (res?.ok) {
    status = (await res.json()) as FederationStatus
    deployed = true
  } else {
    console.warn(
      `[federation-e2e] ${ID_URL}/federation/status returned ${res?.status ?? 'no response'} — ` +
        'the federation routes are not deployed to this target yet. All layers will skip.',
    )
  }
})

// ── A. Discovery ──────────────────────────────────────────────────────────

describe('A. /federation/status', () => {
  it('is reachable and reports both paths', () => {
    if (!deployed) return expect(deployed).toBe(false) // documented skip
    expect(status).toBeTruthy()
    expect(typeof status!.microsoft.configured).toBe('boolean')
    expect(typeof status!.emailCode.configured).toBe('boolean')
  })

  it('advertises the exact redirect URI the Entra app registration must contain', () => {
    if (!deployed) return
    expect(status!.microsoft.redirectUri).toBe(`${ID_URL}/federation/microsoft/callback`)
  })

  it('leaks no secret material', async () => {
    if (!deployed) return
    const text = await (await fetch(`${ID_URL}/federation/status`)).text()
    expect(text).not.toMatch(/sk_live|sk_test|client_secret/i)
  })
})

// ── B. Authorization request ──────────────────────────────────────────────

describe('B. GET /federation/microsoft/start', () => {
  it('redirects to Entra with a correct, minimal-scope PKCE request', async () => {
    if (!deployed) return
    if (!status!.microsoft.configured) {
      console.warn('[federation-e2e] Microsoft not configured on this target — skipping layer B.')
      return
    }

    const res = await fetch(`${ID_URL}/federation/microsoft/start?continue=/`, { redirect: 'manual' })
    expect(res.status).toBe(302)

    const location = new URL(res.headers.get('location')!)
    expect(location.hostname).toBe('login.microsoftonline.com')
    expect(location.pathname).toContain('/oauth2/v2.0/authorize')
    // The three things a locked-down tenant judges us on:
    expect(location.searchParams.get('scope')).toBe('openid profile email')
    expect(location.searchParams.get('code_challenge_method')).toBe('S256')
    expect(location.searchParams.get('response_type')).toBe('code')
    expect(location.searchParams.get('redirect_uri')).toBe(status!.microsoft.redirectUri)
    expect(location.searchParams.get('state')).toBeTruthy()
    expect(location.searchParams.get('nonce')).toBeTruthy()
  })

  it('rejects a forged callback state', async () => {
    if (!deployed || !status!.microsoft.configured) return
    const res = await fetch(`${ID_URL}/federation/microsoft/callback?code=x&state=forged`, { redirect: 'manual' })
    expect(res.status).toBe(400)
  })
})

// ── C. Email-code fallback, full loop ─────────────────────────────────────

describe('C. email-code fallback (full loop)', () => {
  it('sends a code, accepts it, and issues an id.org.ai token at email-code assurance', async () => {
    if (!deployed) return
    if (!hasClickHouse) {
      console.warn('[federation-e2e] No ClickHouse credentials — skipping the live mailbox loop.')
      return
    }
    if (!status!.emailCode.configured) {
      console.warn('[federation-e2e] Email fallback not configured on this target — skipping layer C.')
      return
    }

    const sentAt = Date.now()

    const sendRes = await fetch(`${ID_URL}/federation/email/send`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: TEST_MAILBOX }),
    })
    expect(sendRes.status).toBe(200)

    const mail = await waitForEmail(TEST_MAILBOX, { afterTs: sentAt, timeoutMs: 90_000 })
    const code = extractVerificationCode(mail.text || mail.html)
    expect(code, `no 6-digit code in the mail body: ${mail.subject}`).toBeTruthy()

    const verifyRes = await fetch(`${ID_URL}/federation/email/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: TEST_MAILBOX, code, continue: '/' }),
    })
    expect(verifyRes.status).toBe(200)
    const verified = (await verifyRes.json()) as { ok: boolean; assurance: string }
    expect(verified.ok).toBe(true)
    // Honest assurance, on the wire.
    expect(verified.assurance).toBe('email-code')

    // The cookie carries an id.org.ai JWT that /auth/verify accepts, and whose
    // projection names the assurance a downstream gate must branch on.
    const cookie = verifyRes.headers
      .getSetCookie()
      .find((c) => c.startsWith('auth='))
    expect(cookie, 'no auth cookie was set').toBeTruthy()
    const jwt = cookie!.split(';')[0]!.slice('auth='.length)

    const check = await fetch(`${ID_URL}/auth/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: jwt }),
    })
    expect(check.status).toBe(200)
    const projected = (await check.json()) as {
      valid: boolean
      identity: { sub: string; email?: string; assurance?: string; emailDomain?: string }
    }
    expect(projected.valid).toBe(true)
    expect(projected.identity.assurance).toBe('email-code')
    expect(projected.identity.email).toBe(TEST_MAILBOX)
    expect(projected.identity.emailDomain).toBe(TEST_MAILBOX.split('@')[1])
  })

  it('refuses a wrong code', async () => {
    if (!deployed || !status!.emailCode.configured) return
    const res = await fetch(`${ID_URL}/federation/email/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: TEST_MAILBOX, code: '000000' }),
    })
    expect([400, 401]).toContain(res.status)
  })

  it('throttles repeated sends to the same mailbox', async () => {
    if (!deployed || !status!.emailCode.configured || !hasClickHouse) return
    // The budget is 5/hour; the loop above already spent one.
    let sawThrottle = false
    for (let i = 0; i < 8; i++) {
      const res = await fetch(`${ID_URL}/federation/email/send`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: TEST_MAILBOX }),
      })
      if (res.status === 429) {
        sawThrottle = true
        break
      }
    }
    expect(sawThrottle).toBe(true)
  })
})
