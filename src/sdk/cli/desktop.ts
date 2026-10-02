/**
 * Opening the confirm link and copying it: the desktop side of `login`.
 */

type Env = Record<string, string | undefined>

const overSsh = (env: Env) => Boolean(env.SSH_CONNECTION || env.SSH_CLIENT || env.SSH_TTY)

/**
 * Whether opening a browser here would put it in front of the person.
 * Not over SSH (it would open on the far machine), and not on a Linux box
 * with no display (WSL opens the Windows browser, so it counts as having one).
 */
export function canOpenBrowser(env: Env, platform: string): boolean {
  if (overSsh(env)) return false
  if (platform === 'linux') return Boolean(env.DISPLAY || env.WAYLAND_DISPLAY || env.WSL_DISTRO_NAME)
  return true
}

/** Open `url` in the default browser. Resolves whether it was handed to one. */
export async function openInBrowser(url: string, env: Env = process.env, platform: string = process.platform): Promise<boolean> {
  if (!canOpenBrowser(env, platform)) return false
  try {
    const { default: open } = await import('open')
    const child = await open(url)
    // A missing opener (ENOENT) arrives as an event, after this resolves.
    child.on('error', () => {})
    return true
  } catch {
    return false
  }
}

/** Run `command` with `input` on stdin; resolves whether it exited 0. */
export type RunCommand = (command: string, args: string[], input: string) => Promise<boolean>

const runCommand: RunCommand = async (command, args, input) => {
  const { spawn } = await import('node:child_process')
  return new Promise((resolve) => {
    try {
      const child = spawn(command, args, { stdio: ['pipe', 'ignore', 'ignore'] })
      const timer = setTimeout(() => {
        child.kill()
        resolve(false)
      }, 2_000)
      child.on('error', () => {
        clearTimeout(timer)
        resolve(false)
      })
      child.on('exit', (code) => {
        clearTimeout(timer)
        resolve(code === 0)
      })
      child.stdin?.on('error', () => {})
      child.stdin?.end(input)
    } catch {
      resolve(false)
    }
  })
}

function clipboardCommands(platform: string, env: Env): Array<[string, string[]]> {
  if (platform === 'darwin') return [['pbcopy', []]]
  if (platform === 'win32') return [['clip', []]]
  const commands: Array<[string, string[]]> = []
  if (env.WSL_DISTRO_NAME) commands.push(['clip.exe', []])
  if (env.WAYLAND_DISPLAY) commands.push(['wl-copy', []])
  if (env.DISPLAY) commands.push(['xclip', ['-selection', 'clipboard']], ['xsel', ['--clipboard', '--input']])
  return commands
}

export interface CopyOptions {
  platform?: string
  env?: Env
  /** Writes to the terminal, for the OSC 52 fallback. */
  write: (text: string) => unknown
  run?: RunCommand
}

/**
 * Copy `text` to the clipboard: the platform's tool when there is one, else
 * the terminal's own clipboard (OSC 52, which most modern terminals honour,
 * over SSH too). Over SSH it goes straight to OSC 52, since a tool there
 * would fill the far machine's clipboard.
 */
export async function copyToClipboard(text: string, options: CopyOptions): Promise<boolean> {
  const env = options.env ?? process.env
  const run = options.run ?? runCommand
  if (!overSsh(env)) {
    for (const [command, args] of clipboardCommands(options.platform ?? process.platform, env)) {
      if (await run(command, args, text)) return true
    }
  }
  options.write(`\x1b]52;c;${Buffer.from(text, 'utf8').toString('base64')}\x07`)
  return true
}
