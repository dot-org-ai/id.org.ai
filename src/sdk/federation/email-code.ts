/**
 * Email verification-code fallback.
 *
 * ## Why this exists
 *
 * A corporate Entra tenant may refuse to let its users consent to an app the
 * tenant has not pre-approved. That refusal happens INSIDE the customer's
 * directory, is invisible to us until a viewer hits it, and cannot be fixed
 * from our side — only their IT can approve the app. For a deck we want a
 * named viewer to open today, "ask your IT department" is not a flow.
 *
 * So: prove control of the work mailbox instead. A code lands in
 * `alice@zebra.com`'s inbox, she types it back, and we mint the SAME principal
 * shape as the Microsoft path — with `assurance: 'email-code'` recorded, and
 * the capability ceiling that goes with it (L1, not L2). Lower assurance is
 * written down, never rounded up.
 *
 * ## Transport
 *
 * Delivery + code verification ride on WorkOS Magic Auth, which id.org.ai is
 * already credentialed for (`WORKOS_API_KEY` / `WORKOS_CLIENT_ID` are live
 * secrets on the worker). No new email vendor, no new secret, no SPF/DKIM
 * work to do before the deck can go out. The `EmailCodeChannel` interface
 * keeps that a swap, not a rewrite: a future transport implements two methods.
 *
 * A deliberate consequence: WorkOS owns the code (generation, TTL, attempt
 * limiting). We do not mint or store a code ourselves — there is exactly one
 * place a code can be checked, so there is no second implementation to get
 * wrong. What we DO own is per-email send throttling (see `SendThrottle`),
 * because nothing upstream stops a stranger pointing our send endpoint at
 * someone else's inbox.
 *
 * Portable: no cloudflare imports.
 */
import { FederationError, emailDomainOf } from './types'
import type { FederatedPrincipal, FederationProvenance } from './types'

const WORKOS_API = 'https://api.workos.com'

// ── The channel seam ──────────────────────────────────────────────────────

export interface EmailCodeSendResult {
  /** Opaque handle for the pending code, when the transport issues one. */
  id?: string
  /** Epoch ms the code stops being accepted, when the transport reports it. */
  expiresAt?: number
}

export interface EmailCodeVerifyResult {
  /**
   * Transport-side stable subject for this human (a WorkOS `user_*` id).
   * Optional: a transport that only says yes/no is still usable — the email
   * itself is then the subject.
   */
  subject?: string
  /** Display name, if the transport knows one. */
  name?: string
}

/**
 * Two methods: put a code in a mailbox, and tell me whether a returned code is
 * the one you sent. Everything else about the fallback lives above this line.
 */
export interface EmailCodeChannel {
  send(email: string): Promise<EmailCodeSendResult>
  verify(email: string, code: string): Promise<EmailCodeVerifyResult>
}

// ── Send throttling ───────────────────────────────────────────────────────

/**
 * Minimal storage port for throttle counters — the worker backs this with the
 * IdentityDO, tests back it with a Map.
 */
export interface ThrottleStore {
  get(key: string): Promise<{ count: number; windowStartedAt: number } | undefined>
  put(key: string, value: { count: number; windowStartedAt: number }): Promise<void>
}

export interface SendThrottleOptions {
  /** Max sends per window per email. Default 5. */
  max?: number
  /** Window length in ms. Default 1 hour. */
  windowMs?: number
}

/**
 * Enforce a per-email send budget. Returns `false` when the caller must refuse
 * to send. Keyed on the normalised email so casing games do not buy extra
 * sends.
 */
export async function allowEmailCodeSend(
  store: ThrottleStore,
  email: string,
  options: SendThrottleOptions = {},
): Promise<boolean> {
  const max = options.max ?? 5
  const windowMs = options.windowMs ?? 60 * 60 * 1000
  const key = `emailcode-throttle:${normalizeEmail(email)}`
  const now = Date.now()

  const current = await store.get(key)
  if (!current || now - current.windowStartedAt >= windowMs) {
    await store.put(key, { count: 1, windowStartedAt: now })
    return true
  }
  if (current.count >= max) return false

  await store.put(key, { count: current.count + 1, windowStartedAt: current.windowStartedAt })
  return true
}

// ── WorkOS Magic Auth transport ───────────────────────────────────────────

export interface WorkOSMagicAuthConfig {
  apiKey: string
  clientId: string
}

/**
 * WorkOS Magic Auth as an `EmailCodeChannel`.
 *
 * Send uses `POST /user_management/magic_auth` (creates the code, sends the
 * mail, creates the WorkOS user if new). WorkOS previously exposed this as
 * `POST /user_management/magic_auth/send`; when the primary returns 404/405 we
 * retry the legacy path rather than fail a viewer over an API version.
 */
export function workosMagicAuthChannel(config: WorkOSMagicAuthConfig): EmailCodeChannel {
  return {
    async send(email: string): Promise<EmailCodeSendResult> {
      const normalized = normalizeEmail(email)

      let response = await fetch(`${WORKOS_API}/user_management/magic_auth`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${config.apiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email: normalized }),
      })

      if (response.status === 404 || response.status === 405) {
        response = await fetch(`${WORKOS_API}/user_management/magic_auth/send`, {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${config.apiKey}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ email: normalized }),
        })
      }

      if (!response.ok) {
        const body = await response.text()
        throw new FederationError('upstream-error', `Could not send the verification code: ${truncate(body)}`)
      }

      const json = (await response.json().catch(() => ({}))) as { id?: string; expires_at?: string }
      return {
        id: json.id,
        expiresAt: json.expires_at ? Date.parse(json.expires_at) : undefined,
      }
    },

    async verify(email: string, code: string): Promise<EmailCodeVerifyResult> {
      const response = await fetch(`${WORKOS_API}/user_management/authenticate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'urn:workos:oauth:grant-type:magic-auth',
          client_id: config.clientId,
          client_secret: config.apiKey,
          email: normalizeEmail(email),
          code,
        }).toString(),
      })

      if (!response.ok) {
        const body = await response.text()
        // WorkOS reports a wrong/expired code as a 400 with a code of
        // `invalid_one_time_code` / `magic_auth_code_expired`. Both are the
        // viewer's problem to retry, not an outage — classify them apart from
        // a genuine upstream failure so the UI can say "wrong code".
        if (response.status === 400 || response.status === 401) {
          throw new FederationError('access-denied', 'That code is not valid or has expired', extractWorkOSCode(body))
        }
        throw new FederationError('upstream-error', `Verification failed: ${truncate(body)}`)
      }

      const json = (await response.json()) as {
        user?: { id?: string; email?: string; first_name?: string; last_name?: string }
      }
      const name = [json.user?.first_name, json.user?.last_name].filter(Boolean).join(' ')
      return {
        subject: json.user?.id,
        name: name || undefined,
      }
    },
  }
}

// ── Principal mapping ─────────────────────────────────────────────────────

/**
 * Map a verified mailbox into the broker's principal shape.
 *
 * The identity id is derived from the EMAIL, not from the transport's user id,
 * so switching transports later does not fork every principal. The transport's
 * subject is kept in provenance where it belongs — as evidence, not as the key.
 *
 * `issuer` is the broker's own origin: no external IdP asserted anything here.
 * Saying `https://id.org.ai` is the honest statement that we are vouching for a
 * mailbox check we performed ourselves.
 */
export function emailCodePrincipal(
  email: string,
  verification: EmailCodeVerifyResult,
  brokerOrigin = 'https://id.org.ai',
): FederatedPrincipal {
  const normalized = normalizeEmail(email)
  if (!normalized.includes('@')) {
    throw new FederationError('invalid-token', 'Not a valid email address')
  }

  const provenance: FederationProvenance = {
    provider: 'email-code',
    issuer: brokerOrigin,
    subject: verification.subject ?? normalized,
    assurance: 'email-code',
    verifiedAt: Date.now(),
    emailDomain: emailDomainOf(normalized),
    displayName: verification.name,
  }

  return {
    identityId: `human:email:${normalized}`,
    email: normalized,
    name: verification.name?.trim() || normalized.split('@')[0]!,
    provenance,
  }
}

// ── Validation helpers ────────────────────────────────────────────────────

/**
 * Deliberately permissive: one `@`, a dot in the domain, no whitespace. A
 * stricter regex rejects valid corporate addresses far more often than it
 * catches anything useful — the mailbox either receives the code or it does not.
 */
export function isPlausibleEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@.]+\.[^\s@]+$/.test(email.trim())
}

export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase()
}

/** Codes are 6 digits as issued by WorkOS Magic Auth. */
export function isPlausibleCode(code: string): boolean {
  return /^\d{6}$/.test(code.trim())
}

function truncate(s: string, max = 200): string {
  return s.length > max ? `${s.slice(0, max)}…` : s
}

function extractWorkOSCode(body: string): string | undefined {
  try {
    const parsed = JSON.parse(body) as { code?: string; error?: string }
    return parsed.code ?? parsed.error
  } catch {
    return undefined
  }
}
