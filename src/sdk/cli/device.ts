/**
 * OAuth 2.0 Device Authorization Grant (RFC 8628)
 *
 * Uses id.org.ai's own OAuth device flow endpoint.
 */

import { CANONICAL_API_ORIGIN } from '../auth/index.js'
import { cleanText, openableUrl, parseUserCode } from './untrusted.js'

export interface DeviceAuthorizationResponse {
  device_code: string
  user_code: string
  verification_uri: string
  verification_uri_complete: string
  expires_in: number
  interval: number
}

export interface TokenResponse {
  access_token: string
  token_type: string
  expires_in?: number
  refresh_token?: string
  scope?: string
}

export type TokenError = 'authorization_pending' | 'slow_down' | 'access_denied' | 'expired_token' | 'unknown'

/** The API the CLI talks to. The confirm link is opened only on this origin. */
export const API_BASE = process.env.ID_ORG_AI_URL || CANONICAL_API_ORIGIN

/** What the person reads when a reply can't be parsed. The reply itself is never quoted. */
const UNREADABLE_REPLY = "the server sent a reply the CLI can't read"

const DEVICE_CODE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code'

/** RFC 8628 §3.2: poll every 5 seconds when the server names no interval. */
export const DEFAULT_INTERVAL = 5
/** A code's life when the server names none (it always should). */
export const DEFAULT_EXPIRES_IN = 600

/** `value` when it is a usable number of seconds, else `fallback`. */
export function secondsOr(value: unknown, fallback: number): number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : fallback
}

/** RFC 8628 §3.5: each slow_down adds 5 seconds to the interval, for good. */
const SLOW_DOWN_STEP_MS = 5_000
/** A dropped connection is retried with exponential backoff, up to this wait… */
const MAX_BACKOFF_MS = 60_000
/** …this many times in a row before the poll gives up. */
const MAX_NETWORK_FAILURES = 5

/** A failed device-flow request: `code` is the OAuth error, or `network_error`. */
export class DeviceFlowError extends Error {
  readonly code: string
  readonly description?: string

  constructor(message: string, code: string, description?: string) {
    super(message)
    this.name = 'DeviceFlowError'
    this.code = code
    this.description = description
  }
}

/**
 * A user code as people read it: `XXXX-XXXX`. Accepts the code with or
 * without its hyphen (or with a space); a code of another length is left as sent.
 */
export function formatUserCode(code: string): string {
  const bare = code.replace(/[\s-]/g, '').toUpperCase()
  return bare.length === 8 ? `${bare.slice(0, 4)}-${bare.slice(4)}` : code.trim()
}

const OS_NAMES: Record<string, string> = {
  darwin: 'macOS',
  win32: 'Windows',
  linux: 'Linux',
  freebsd: 'FreeBSD',
  openbsd: 'OpenBSD',
  netbsd: 'NetBSD',
  sunos: 'SunOS',
  aix: 'AIX',
  android: 'Android',
}

/**
 * The `device_name` the confirm page shows: OS and short hostname,
 * e.g. "macOS · bryants-mbp".
 */
export function deviceName(platform: string, hostname: string): string {
  const os = OS_NAMES[platform] ?? platform
  const host = hostname.trim().split('.')[0]
  return host ? `${os} · ${host}` : os
}

export interface AuthorizeDeviceOptions {
  /** OS and hostname for the confirm page (see deviceName). Sent only when given. */
  deviceName?: string
  scope?: string
}

/**
 * Initiate device authorization flow
 */
export async function authorizeDevice(
  clientId: string,
  headers?: Record<string, string>,
  options: AuthorizeDeviceOptions = {},
): Promise<DeviceAuthorizationResponse> {
  const form = new URLSearchParams({
    client_id: clientId,
    scope: options.scope ?? 'openid profile email',
  })
  if (options.deviceName) form.set('device_name', options.deviceName)

  let response: Response
  try {
    response = await fetch(`${API_BASE}/oauth/device`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...headers },
      body: form.toString(),
    })
  } catch {
    throw new DeviceFlowError(`Couldn't reach ${API_BASE}.`, 'network_error')
  }

  if (!response.ok) {
    const text = await response.text().catch(() => '')
    const body = parseOAuthError(text)
    throw new DeviceFlowError(`Device authorization failed: ${response.status} - ${cleanText(text)}`, body.error ?? `http_${response.status}`, body.error_description)
  }

  try {
    return (await response.json()) as DeviceAuthorizationResponse
  } catch {
    // V8's SyntaxError quotes the body, so it is not passed on.
    throw new DeviceFlowError('Device authorization failed: the reply is not JSON', 'invalid_response', UNREADABLE_REPLY)
  }
}

/** A device authorization reply, checked and cleaned: what `login` uses and prints. */
export interface DeviceGrant {
  deviceCode: string
  /** The user code as `XXXX-XXXX`, checked against the code alphabet. */
  userCode: string
  /** The confirm link as printed: normalised when it is safe, else cleaned (see untrusted.ts). */
  url: string
  /** The same link when it is safe to open and copy (https on the API's origin); else undefined. */
  link?: string
  /** Seconds the code lives (default 600). */
  expiresIn: number
  /** Seconds between polls (default 5). */
  interval: number
}

export type ParsedDeviceAuthorization = { ok: true; grant: DeviceGrant } | { ok: false; error: string }

/**
 * Check and clean a device authorization reply (RFC 8628 §3.2) before any of
 * it reaches the terminal or the browser. The user code must be 8 characters
 * of the code alphabet (XXXX-XXXX); anything else is a protocol error, and its
 * value is never echoed. The confirm link is kept for opening only when it is
 * https (or loopback http) on `apiBase`'s origin; otherwise it is only shown,
 * cleaned.
 */
export function parseDeviceAuthorization(reply: unknown, apiBase: string = API_BASE): ParsedDeviceAuthorization {
  const body = (reply && typeof reply === 'object' ? reply : {}) as Record<string, unknown>
  const userCode = parseUserCode(body.user_code)
  if (!userCode) return { ok: false, error: 'the server sent an invalid user code' }
  const complete = body.verification_uri_complete
  const raw = typeof complete === 'string' && complete ? complete : body.verification_uri
  const deviceCode = body.device_code
  if (typeof deviceCode !== 'string' || !deviceCode || typeof raw !== 'string' || !raw) {
    return { ok: false, error: 'the server sent an invalid reply' }
  }
  const link = openableUrl(raw, apiBase) ?? undefined
  return {
    ok: true,
    grant: {
      deviceCode,
      userCode,
      url: link ?? cleanText(raw),
      link,
      expiresIn: secondsOr(body.expires_in, DEFAULT_EXPIRES_IN),
      interval: secondsOr(body.interval, DEFAULT_INTERVAL),
    },
  }
}

/** An OAuth error body's `error` and `error_description`, cleaned for printing. */
function parseOAuthError(text: string): { error?: string; error_description?: string } {
  try {
    const body = JSON.parse(text) as unknown
    if (body && typeof body === 'object') {
      const { error, error_description } = body as Record<string, unknown>
      return {
        error: cleanText(error) || undefined,
        error_description: cleanText(error_description) || undefined,
      }
    }
  } catch {
    // not JSON
  }
  return {}
}

export type DevicePollResult =
  | { status: 'approved'; tokens: TokenResponse }
  | { status: 'denied' }
  | { status: 'expired' }
  | { status: 'aborted' }
  | { status: 'error'; error: string; description?: string }

export interface PollDeviceTokenOptions {
  clientId: string
  deviceCode: string
  /** Seconds between polls, from the authorization response (default 5). */
  interval?: number
  /** Seconds the code lives, from the authorization response (default 600). */
  expiresIn?: number
  headers?: Record<string, string>
  /** Stops the poll; it then resolves `aborted`. */
  signal?: AbortSignal
}

/** Resolves after `ms`, or early (false) when `signal` aborts. */
function wait(ms: number, signal?: AbortSignal): Promise<boolean> {
  if (signal?.aborted) return Promise.resolve(false)
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort)
      resolve(true)
    }, ms)
    const onAbort = () => {
      clearTimeout(timer)
      resolve(false)
    }
    signal?.addEventListener('abort', onAbort, { once: true })
  })
}

/**
 * Poll the token endpoint until the person decides or the code runs out
 * (RFC 8628 §3.4–3.5):
 * - waits `interval` before each poll, never past the code's expiry;
 * - `authorization_pending`: poll again;
 * - `slow_down`: add 5 seconds to the interval for this and every later poll;
 * - `access_denied` → denied; `expired_token`, or the clock running out → expired;
 * - a dropped connection or a 5xx: back off exponentially, up to five in a row;
 * - anything else → error, with the server's description.
 */
export async function pollDeviceToken(options: PollDeviceTokenOptions): Promise<DevicePollResult> {
  const { signal } = options
  const deadline = Date.now() + secondsOr(options.expiresIn, DEFAULT_EXPIRES_IN) * 1000
  let intervalMs = secondsOr(options.interval, DEFAULT_INTERVAL) * 1000
  let failures = 0

  while (true) {
    const backoff = failures ? Math.min(Math.max(intervalMs, 1000) * 2 ** failures, MAX_BACKOFF_MS) : intervalMs
    const left = deadline - Date.now()
    if (left <= 0) return { status: 'expired' }
    if (!(await wait(Math.min(backoff, left), signal))) return { status: 'aborted' }
    if (Date.now() >= deadline) return { status: 'expired' }

    let response: Response
    try {
      response = await fetch(`${API_BASE}/oauth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...options.headers },
        body: new URLSearchParams({
          grant_type: DEVICE_CODE_GRANT,
          device_code: options.deviceCode,
          client_id: options.clientId,
        }).toString(),
        signal,
      })
    } catch {
      if (signal?.aborted) return { status: 'aborted' }
      if (++failures >= MAX_NETWORK_FAILURES) {
        return { status: 'error', error: 'network_error', description: `Couldn't reach ${API_BASE}.` }
      }
      continue
    }

    if (response.ok) {
      // A body that isn't JSON would throw V8's SyntaxError, which quotes it.
      const tokens = (await response.json().catch(() => null)) as TokenResponse | null
      if (!tokens || typeof tokens !== 'object' || typeof tokens.access_token !== 'string' || !tokens.access_token) {
        return { status: 'error', error: 'invalid_response', description: UNREADABLE_REPLY }
      }
      return { status: 'approved', tokens }
    }

    const body = parseOAuthError(await response.text().catch(() => ''))
    if (response.status >= 500 && !body.error) {
      if (++failures >= MAX_NETWORK_FAILURES) {
        return { status: 'error', error: 'server_error', description: `${API_BASE} answered ${response.status}.` }
      }
      continue
    }
    failures = 0

    switch (body.error) {
      case 'authorization_pending':
        continue
      case 'slow_down':
        intervalMs += SLOW_DOWN_STEP_MS
        continue
      case 'access_denied':
        return { status: 'denied' }
      case 'expired_token':
        return { status: 'expired' }
      default:
        return { status: 'error', error: body.error ?? `http_${response.status}`, description: body.error_description }
    }
  }
}

/**
 * Poll for tokens after device authorization.
 * Kept for existing callers: resolves the tokens, or throws on any other outcome.
 */
export async function pollForTokens(
  clientId: string,
  deviceCode: string,
  interval: number = 5,
  expiresIn: number = 600,
  headers?: Record<string, string>,
): Promise<TokenResponse> {
  const result = await pollDeviceToken({ clientId, deviceCode, interval, expiresIn, headers })
  switch (result.status) {
    case 'approved':
      return result.tokens
    case 'denied':
      throw new Error('Access denied by user')
    case 'expired':
      throw new Error('Device code expired')
    case 'aborted':
      throw new Error('Device authorization aborted')
    case 'error':
      throw new Error(`Token polling failed: ${result.description ?? result.error}`)
  }
}
