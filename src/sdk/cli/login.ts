/**
 * `login`: the device flow (RFC 8628) with the 4a output
 * (docs/product-update/spec/cli-output.md).
 *
 * The text comes from login-output.ts; this file does the I/O around it: the
 * requests, the spinner, the `c` and `o` keys and the in-place redraws. Every
 * stream, the browser and the clipboard come in through `io`, so tests drive it
 * with a fake terminal and a mocked fetch.
 *
 * Nothing the server sends is printed, opened or stored as sent: the device
 * reply is parsed (parseDeviceAuthorization), userinfo is cleaned (getUser),
 * and tokens are stored only when made of token characters (storedTokenData).
 * The link opened and copied is not the server's: the CLI builds it from the
 * API origin and the checked user code, and opens it only when that origin is
 * https, or http on loopback (device.ts, untrusted.ts).
 */

import { API_BASE, authorizeDevice, parseDeviceAuthorization, pollDeviceToken, DeviceFlowError } from './device.js'
import type { DeviceAuthorizationResponse, DevicePollResult } from './device.js'
import { getUser, storedTokenData, UNUSABLE_TOKEN } from './auth.js'
import { originOf } from './untrusted.js'
import type { TokenStorage } from './storage.js'
import {
  SPINNER_INTERVAL_MS,
  codeBlock,
  fit,
  headerBlock,
  hintLine,
  outcomeBlock,
  outcomeLines,
  outputMode,
  paint,
  paintLines,
  waitingLine,
} from './login-output.js'
import type { BrowserState, Line, LoginApp, LoginOutcome } from './login-output.js'

/** 0 signed in · 1 denied, expired or failed · 2 usage error · 130 interrupted (Ctrl-C). */
export const EXIT = { ok: 0, failed: 1, usage: 2, interrupted: 130 } as const

export interface TerminalOutput {
  write(text: string): unknown
  isTTY?: boolean
  columns?: number
}

/** The parts of process.stdin the keys need. */
export interface KeyInput {
  isTTY?: boolean
  setRawMode?(mode: boolean): unknown
  setEncoding?(encoding: BufferEncoding): unknown
  on(event: 'data', listener: (chunk: string | Buffer) => void): unknown
  off(event: 'data', listener: (chunk: string | Buffer) => void): unknown
  resume(): unknown
  pause(): unknown
}

export interface LoginIO {
  stdout: TerminalOutput
  stdin?: KeyInput
  env: Record<string, string | undefined>
  /** Open the link in the default browser; resolves whether it did. */
  openUrl(url: string): Promise<boolean>
  /** Copy to the clipboard; resolves whether it did. */
  copyText(text: string): Promise<boolean>
}

export interface LoginOptions {
  clientId: string
  app: LoginApp
  storage: TokenStorage
  io: LoginIO
  /** "macOS · bryants-mbp", sent as `device_name` for the confirm page. */
  deviceName?: string
  /** "Stored in": by default the storage's file, with ~ for home. */
  storageLabel?: string
  headers?: Record<string, string>
  /** Aborting (SIGINT) stops the wait; runLogin then resolves EXIT.interrupted. */
  signal?: AbortSignal
}

export type LoginArgs = { ok: true; account: boolean } | { ok: false; error: string }

/**
 * `login` flags. `--account` signs in again, as whichever account the person
 * picks in the browser (the "Switch" line); plain `login` does too, so it is
 * accepted rather than required. Anything unknown is a usage error (exit 2).
 */
export function parseLoginArgs(args: string[]): LoginArgs {
  let account = false
  for (const arg of args) {
    if (arg === '--account') account = true
    else if (arg === '--debug') continue
    else if (arg.startsWith('-')) return { ok: false, error: `Unknown option for login: ${arg}` }
    else return { ok: false, error: `Unexpected argument for login: ${arg}` }
  }
  return { ok: true, account }
}

const HIDE_CURSOR = '\x1b[?25l'
const SHOW_CURSOR = '\x1b[?25h'
const ERASE_LINE = '\x1b[2K'

function describeError(error: unknown): string {
  if (error instanceof DeviceFlowError) return error.description ?? (error.code === 'network_error' ? error.message : error.code)
  return error instanceof Error ? error.message : String(error)
}

/** The storage's file, with ~ for home; else a generic name. */
async function describeStorage(storage: TokenStorage): Promise<string> {
  const getPath = (storage as { getStoragePath?: () => Promise<string | null> }).getStoragePath
  const path = typeof getPath === 'function' ? await getPath.call(storage) : null
  if (!path) return 'token storage'
  const { homedir } = await import('node:os')
  const home = homedir()
  return home && (path === home || path.startsWith(home + '/')) ? '~' + path.slice(home.length) : path
}

/**
 * Sign in with the device flow, printing the 4a screen. Resolves the exit code.
 *
 * On a terminal the last three lines (keys, blank, spinner) are a live region:
 * the spinner line is redrawn every 80 ms and the keys line when a key changes
 * it, each cut to the terminal's width so nothing wraps. Elsewhere every line
 * is printed once.
 */
export async function runLogin(options: LoginOptions): Promise<number> {
  const { io, app } = options
  const out = io.stdout
  const mode = outputMode({ stdoutIsTTY: out.isTTY, stdinIsTTY: io.stdin?.isTTY, env: io.env })
  const write = (text: string) => {
    out.write(text)
  }

  write(paintLines(headerBlock(app), mode.colour))
  const fail = (message: string) => {
    write(paintLines([...outcomeLines({ kind: 'error', message }, app), []], mode.colour))
    return EXIT.failed
  }

  let reply: DeviceAuthorizationResponse
  try {
    reply = await authorizeDevice(options.clientId, options.headers, { deviceName: options.deviceName })
  } catch (error) {
    return fail(describeError(error))
  }
  if (options.signal?.aborted) return EXIT.interrupted

  // From here on only checked, cleaned values: a bad user code ends the run
  // without being echoed, and `link` (built by the CLI, not sent by the
  // server) is set only when the API's origin is safe to open.
  const parsed = parseDeviceAuthorization(reply, API_BASE)
  if (!parsed.ok) return fail(parsed.error)
  const { userCode: code, url, link, expiresIn } = parsed.grant
  const expiresAt = Date.now() + expiresIn * 1000
  const browser: BrowserState = link ? { opened: await io.openUrl(link).catch(() => false) } : { opened: false, refusedFor: originOf(API_BASE) }

  let frame = 0
  let remaining = () => expiresAt - Date.now()
  const waiting = () => waitingLine({ frame, remainingMs: remaining() }, mode)
  // Live lines are cut to the terminal's width: a wrapped line would break the redraw.
  const fitted = (line: Line) => paint(out.columns ? fit(line, out.columns - 1) : line, mode.colour)
  const redrawWaiting = () => write(`\r${ERASE_LINE}${fitted(waiting())}`)
  const redrawHint = () => write(`\x1b[2A\r${ERASE_LINE}${fitted(hintLine(browser, mode))}\x1b[2B\r${ERASE_LINE}${fitted(waiting())}`)

  write(paintLines(codeBlock(code, url), mode.colour))
  if (!mode.spinner) {
    write(paintLines([hintLine(browser, mode), [], waiting()], mode.colour))
  }

  const stop = new AbortController()
  const onAbort = () => stop.abort()
  options.signal?.addEventListener('abort', onAbort, { once: true })
  if (options.signal?.aborted) stop.abort()
  const keys = mode.keys ? io.stdin : undefined
  let listening = true
  let ticker: ReturnType<typeof setInterval> | undefined
  let cursorHidden = false
  let waitLineEnded = !mode.spinner

  // An unsafe link is never copied or opened; the keys do nothing for it.
  const copy = async () => {
    if (!link) return
    const ok = await io.copyText(link).catch(() => false)
    if (!listening) return
    browser.note = ok ? 'copied' : 'copy-failed'
    redrawHint()
  }
  const reopen = async () => {
    if (!link) return
    const ok = await io.openUrl(link).catch(() => false)
    if (!listening) return
    browser.opened = ok
    browser.note = undefined
    redrawHint()
  }
  const onKey = (chunk: string | Buffer) => {
    for (const key of String(chunk)) {
      if (key === '\x03') stop.abort()
      else if (key === 'c' || key === 'C') void copy()
      else if (key === 'o' || key === 'O') void reopen()
    }
  }

  let result: DevicePollResult
  try {
    if (mode.spinner) {
      cursorHidden = true
      write(`${HIDE_CURSOR}${fitted(hintLine(browser, mode))}\n\n${fitted(waiting())}`)
      ticker = setInterval(() => {
        frame += 1
        redrawWaiting()
      }, SPINNER_INTERVAL_MS)
    }
    if (keys) {
      try {
        keys.setRawMode?.(true)
      } catch {
        // not a real terminal after all; the keys just won't work
      }
      keys.setEncoding?.('utf8')
      keys.on('data', onKey)
      keys.resume()
    }

    result = await pollDeviceToken({
      clientId: options.clientId,
      deviceCode: parsed.grant.deviceCode,
      interval: parsed.grant.interval,
      expiresIn,
      headers: options.headers,
      signal: stop.signal,
    })

    if (mode.spinner) {
      // The spinner line stays as the record of the wait, on its first frame as in 4a.
      frame = 0
      if (result.status === 'expired') remaining = () => 0
      redrawWaiting()
      write('\n')
      waitLineEnded = true
    }
  } finally {
    listening = false
    if (ticker) clearInterval(ticker)
    if (keys) {
      keys.off('data', onKey)
      try {
        keys.setRawMode?.(false)
      } catch {
        // ignore
      }
      keys.pause()
    }
    if (!waitLineEnded) write('\n')
    if (cursorHidden) write(SHOW_CURSOR)
    options.signal?.removeEventListener('abort', onAbort)
  }

  if (result.status === 'aborted') return EXIT.interrupted

  const outcome = await settle(result, options)
  write(paintLines(outcomeBlock(outcome, app), mode.colour))
  return outcome.kind === 'success' ? EXIT.ok : EXIT.failed
}

/** Turn the poll's result into what to print, storing the tokens on approval. */
async function settle(result: Exclude<DevicePollResult, { status: 'aborted' }>, options: LoginOptions): Promise<LoginOutcome> {
  switch (result.status) {
    case 'denied':
      return { kind: 'denied' }
    case 'expired':
      return { kind: 'expired' }
    case 'error':
      return { kind: 'error', message: result.description ?? result.error }
    case 'approved': {
      // Only token characters are stored: `id.org.ai token` prints the access token as is.
      const tokens = storedTokenData(result.tokens)
      if (!tokens) return { kind: 'error', message: UNUSABLE_TOKEN }
      try {
        await options.storage.setTokenData(tokens)
      } catch (error) {
        return { kind: 'error', message: `couldn't store the credentials (${describeError(error)})` }
      }
      const { user } = await getUser(tokens.accessToken, options.headers)
      return {
        kind: 'success',
        name: user?.name || undefined,
        email: user?.email || undefined,
        workspace: user?.organizationName || undefined,
        storedIn: options.storageLabel ?? (await describeStorage(options.storage)),
      }
    }
  }
}
