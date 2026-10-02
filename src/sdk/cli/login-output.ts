/**
 * What `login` prints (mock 4a, docs/product-update/spec/cli-output.md).
 *
 * Pure: state in, text out. The I/O (spinner timer, keys, redraws) lives in
 * login.ts and draws with these functions, so the screen a test renders here
 * is the screen a person sees.
 *
 * Each line is a list of styled segments that follow the mock's spans. Styles
 * are terminal intensities only (bold, dim, normal), never hard-coded colours,
 * so the output reads on light and dark themes alike.
 */

export type Style = 'normal' | 'bold' | 'dim'

export interface Segment {
  text: string
  style: Style
}

export type Line = Segment[]

export interface OutputMode {
  /** Bold and dim. Off when stdout is not a terminal, or under NO_COLOR. */
  colour: boolean
  /** The animated spinner and in-place redraws. Needs stdout to be a terminal. */
  spinner: boolean
  /** The `c` and `o` keys. Needs stdin to be a terminal too. */
  keys: boolean
}

export interface LoginApp {
  /** Shown bold on the first line, e.g. `auto.dev`. */
  name: string
  /** The command people type, for "Run {cli} login again" and "Switch". */
  cli: string
}

export interface BrowserState {
  /** The last attempt to open the link worked. */
  opened: boolean
  /** The last key's result, shown in place of the browser sentence. */
  note?: 'copied' | 'copy-failed'
  /**
   * Set when the link isn't safe to open or copy (the API is neither https
   * nor http on loopback): the API's origin, for the warning shown instead of
   * the keys.
   */
  refusedFor?: string
}

export interface WaitingState {
  /** Spinner frame counter; any non-negative integer. */
  frame: number
  /** Time left on the code. */
  remainingMs: number
}

export type LoginOutcome =
  | {
      kind: 'success'
      name?: string
      email?: string
      /** The workspace the tokens are for, by name. */
      workspace?: string
      /** The credential store actually used. */
      storedIn: string
    }
  | { kind: 'denied' }
  | { kind: 'expired' }
  | { kind: 'error'; message: string }

/**
 * Every server value here (code, url, outcome text) arrives already checked and
 * cleaned (untrusted.ts, applied in device.ts and auth.ts): the renderer adds
 * only its own escapes.
 */
export interface LoginScreen {
  app: LoginApp
  /** The user code, already `XXXX-XXXX`. */
  code: string
  /** The confirm link the CLI built from the API origin and the code (device.ts). */
  url: string
  browser: BrowserState
  waiting: WaitingState
  outcome?: LoginOutcome
}

export const SPINNER_FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'] as const
export const SPINNER_INTERVAL_MS = 80

/** Labels sit in a 9-character column, success details in an 11-character one. */
const LABEL_WIDTH = 9
const DETAIL_WIDTH = 11
const INDENT = '  '
const DETAIL_INDENT = '    '

/**
 * How to print, from the streams and the environment.
 * NO_COLOR (when set and not empty, per no-color.org) drops styles only.
 * A non-terminal stdout, or TERM=dumb, drops styles, the spinner and the keys.
 */
export function outputMode(input: { stdoutIsTTY?: boolean; stdinIsTTY?: boolean; env: Record<string, string | undefined> }): OutputMode {
  const terminal = Boolean(input.stdoutIsTTY) && input.env.TERM !== 'dumb'
  const noColor = input.env.NO_COLOR !== undefined && input.env.NO_COLOR !== ''
  return {
    colour: terminal && !noColor,
    spinner: terminal,
    keys: terminal && Boolean(input.stdinIsTTY),
  }
}

/** mm:ss, rounded up, so it reads 00:00 only once the code has expired. */
export function formatCountdown(ms: number): string {
  const seconds = Math.max(0, Math.ceil(ms / 1000))
  const minutes = Math.floor(seconds / 60)
  return `${String(minutes).padStart(2, '0')}:${String(seconds % 60).padStart(2, '0')}`
}

const seg = (text: string, style: Style = 'normal'): Segment => ({ text, style })
const blank = (): Line => []

/** `  auto.dev  ·  sign in with id.org.ai`, or `  id.org.ai  ·  sign in` for this CLI itself. */
export function headerLine(app: LoginApp): Line {
  const tagline = app.name === 'id.org.ai' ? 'sign in' : 'sign in with id.org.ai'
  return [seg(INDENT + app.name, 'bold'), seg(`  ·  ${tagline}`, 'dim')]
}

/** The blank line, the app line and the blank line after it. */
export function headerBlock(app: LoginApp): Line[] {
  return [blank(), headerLine(app), blank()]
}

/** `Code` and `Confirm`. */
export function codeBlock(code: string, url: string): Line[] {
  return [
    [seg(INDENT + 'Code'.padEnd(LABEL_WIDTH), 'dim'), seg(code, 'bold')],
    [seg(INDENT + 'Confirm'.padEnd(LABEL_WIDTH), 'dim'), seg(url)],
  ]
}

function browserSentence(browser: BrowserState): string {
  if (browser.note === 'copied') return 'Link copied.'
  if (browser.note === 'copy-failed') return "Couldn't copy the link."
  return browser.opened ? 'Opened in your browser.' : 'Open this link in your browser.'
}

/**
 * Under the URL: what happened to the link, then the keys when they work.
 * A link that isn't safe gets a warning instead, undimmed, and no keys.
 */
export function hintLine(browser: BrowserState, mode: OutputMode): Line {
  if (browser.refusedFor !== undefined) {
    return [seg(`${INDENT}${' '.repeat(LABEL_WIDTH)}Not opened: ${browser.refusedFor} isn't https.`)]
  }
  const lead = INDENT + ' '.repeat(LABEL_WIDTH) + browserSentence(browser)
  if (!mode.keys) return [seg(lead, 'dim')]
  return [
    seg(lead + '  ', 'dim'),
    seg('c'),
    seg(' copy link   ', 'dim'),
    seg('o'),
    seg(browser.opened ? ' open again' : ' open', 'dim'),
  ]
}

/** `⠋ Waiting for you to confirm in the browser  ·  expires in 29:52`; no spinner when not a terminal. */
export function waitingLine(waiting: WaitingState, mode: OutputMode): Line {
  const frame = SPINNER_FRAMES[Math.abs(Math.trunc(waiting.frame)) % SPINNER_FRAMES.length]
  const lead = mode.spinner ? `${INDENT}${frame} ` : INDENT
  return [seg(lead), seg('Waiting for you to confirm in the browser'), seg(`  ·  expires in ${formatCountdown(waiting.remainingMs)}`, 'dim')]
}

function detail(label: string, value: string): Line {
  return [seg(DETAIL_INDENT + label.padEnd(DETAIL_WIDTH), 'dim'), seg(value)]
}

/** The result lines, without the blank lines around them. */
export function outcomeLines(outcome: LoginOutcome, app: LoginApp): Line[] {
  switch (outcome.kind) {
    case 'success': {
      const who: Line = [seg(`${INDENT}✓ `)]
      if (outcome.name && outcome.email) who.push(seg(`Signed in as ${outcome.name} `), seg(`<${outcome.email}>`, 'dim'))
      else if (outcome.name || outcome.email) who.push(seg(`Signed in as ${outcome.name || outcome.email}`))
      else who.push(seg('Signed in'))
      const lines = [who]
      if (outcome.workspace) lines.push(detail('Workspace', outcome.workspace))
      lines.push(detail('Stored in', outcome.storedIn))
      lines.push(detail('Switch', `${app.cli} login --account`))
      return lines
    }
    case 'denied':
      return [[seg(`${INDENT}✗ Sign-in cancelled in the browser.`)]]
    case 'expired':
      return [[seg(`${INDENT}✗ The code expired. Run ${app.cli} login again.`)]]
    case 'error':
      return [[seg(`${INDENT}✗ Sign-in failed: ${outcome.message}`)]]
  }
}

/** The blank line before the result, the result, and the blank line after. */
export function outcomeBlock(outcome: LoginOutcome, app: LoginApp): Line[] {
  return [blank(), ...outcomeLines(outcome, app), blank()]
}

const SGR: Record<Exclude<Style, 'normal'>, string> = { bold: '\x1b[1m', dim: '\x1b[2m' }
const SGR_NORMAL = '\x1b[22m'

/** One line as text, styled when `colour`. Adjacent segments of one style share codes. */
export function paint(line: Line, colour: boolean): string {
  if (!colour) return line.map((s) => s.text).join('')
  let out = ''
  let open: Style = 'normal'
  for (const { text, style } of line) {
    if (!text) continue
    if (style !== open) {
      if (open !== 'normal') out += SGR_NORMAL
      if (style !== 'normal') out += SGR[style]
      open = style
    }
    out += text
  }
  if (open !== 'normal') out += SGR_NORMAL
  return out
}

/** Lines as text, each ending in a newline. */
export function paintLines(lines: Line[], colour: boolean): string {
  return lines.map((line) => paint(line, colour) + '\n').join('')
}

/** Columns a line takes (every character the CLI prints is one column wide). */
export function visibleWidth(line: Line): number {
  return line.reduce((n, s) => n + Array.from(s.text).length, 0)
}

/**
 * Cut a line to `width` columns, ending in `…`, so a redrawn line never wraps:
 * a wrapped line would break the cursor arithmetic of the redraw.
 */
export function fit(line: Line, width: number): Line {
  if (!(width > 0) || visibleWidth(line) <= width) return line
  const out: Line = []
  let room = width - 1
  for (const s of line) {
    const chars = Array.from(s.text)
    if (chars.length <= room) {
      out.push(s)
      room -= chars.length
      continue
    }
    if (room > 0) out.push({ text: chars.slice(0, room).join(''), style: s.style })
    break
  }
  out.push(seg('…', 'dim'))
  return out
}

/**
 * The whole login screen as text: what a terminal shows once `screen` is
 * reached. With no outcome it stops after the waiting line.
 */
export function renderLogin(screen: LoginScreen, mode: OutputMode): string {
  const lines: Line[] = [
    ...headerBlock(screen.app),
    ...codeBlock(screen.code, screen.url),
    hintLine(screen.browser, mode),
    blank(),
    waitingLine(screen.waiting, mode),
  ]
  if (screen.outcome) lines.push(...outcomeBlock(screen.outcome, screen.app))
  return paintLines(lines, mode.colour)
}
