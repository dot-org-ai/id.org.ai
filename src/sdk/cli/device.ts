/**
 * OAuth 2.0 Device Authorization Grant (RFC 8628)
 *
 * Uses id.org.ai's own OAuth device flow endpoint.
 */

import { CANONICAL_API_ORIGIN } from '../auth/index.js'

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

const API_BASE = process.env.ID_ORG_AI_URL || CANONICAL_API_ORIGIN

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
    throw new DeviceFlowError(`Device authorization failed: ${response.status} - ${text}`, body.error ?? `http_${response.status}`, body.error_description)
  }

  return (await response.json()) as DeviceAuthorizationResponse
}

function parseOAuthError(text: string): { error?: string; error_description?: string } {
  try {
    const body = JSON.parse(text) as unknown
    if (body && typeof body === 'object') {
      const { error, error_description } = body as Record<string, unknown>
      return {
        error: typeof error === 'string' ? error : undefined,
        error_description: typeof error_description === 'string' ? error_description : undefined,
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

    if (response.ok) return { status: 'approved', tokens: (await response.json()) as TokenResponse }

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
