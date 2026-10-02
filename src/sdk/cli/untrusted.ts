/**
 * Server data, made safe to print and to open.
 *
 * `login` prints what the server sends: the user code, the confirm link, error
 * descriptions, and the name, email and workspace from userinfo. None of it is
 * trusted. A workspace name is whatever its owner typed, and a hostile server
 * or a man in the middle can put anything in any field. Printed raw, an escape
 * sequence in that text drives the terminal: OSC 52 writes the clipboard,
 * OSC 8 disguises a link, CSI 2J clears the screen, and bidi controls make text
 * read as something it isn't.
 *
 * So server data is parsed into clean values where it enters the CLI
 * (device.ts and auth.ts call these), and the renderer only ever sees those.
 * The renderer's own escapes (bold, dim, cursor moves) are added after; they
 * are not data.
 */

/**
 * What cleanText removes: C0 controls and DEL (U+0000–U+001F, U+007F), C1
 * controls (U+0080–U+009F), bidi controls (U+061C, U+200E–U+200F,
 * U+202A–U+202E, U+2066–U+2069), zero-width and invisible characters
 * (U+200B–U+200D, U+2060–U+2064, U+FEFF), the line and paragraph separators
 * (U+2028–U+2029), and the deprecated format controls (U+206A–U+206F).
 */
const UNSAFE = /[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff]/g

/** The most characters of any one server value the CLI prints. */
export const MAX_TEXT_LENGTH = 200

/**
 * Server text as it may be printed: the unsafe characters above removed, ends
 * trimmed, and cut to `max` characters, ending in `…` when cut. Anything that
 * isn't a string is empty.
 */
export function cleanText(value: unknown, max: number = MAX_TEXT_LENGTH): string {
  if (typeof value !== 'string') return ''
  const chars = Array.from(value.replace(UNSAFE, '').trim())
  return chars.length <= max ? chars.join('') : chars.slice(0, max - 1).join('') + '…'
}

/** The user code alphabet: no I, O, 0 or 1 (src/sdk/oauth/provider.ts). */
const USER_CODE = /^([ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{4})-?([ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{4})$/

/**
 * The user code as people read it, `XXXX-XXXX`, when the server sent exactly
 * 8 characters of the code alphabet, with or without the hyphen. Anything
 * else is a protocol error: null.
 */
export function parseUserCode(value: unknown): string | null {
  if (typeof value !== 'string') return null
  const match = USER_CODE.exec(value)
  return match ? `${match[1]}-${match[2]}` : null
}

/** Printable ASCII, no spaces: all a link the server builds ever needs. */
const PRINTABLE_ASCII = /^[\x21-\x7e]+$/
/** RFC 3986's characters. A normalised link that keeps any other is refused. */
const URL_CHARACTERS = /^[A-Za-z0-9\-._~:/?#[\]@!$&'()*+,;=%]+$/

/** localhost, 127.0.0.0/8 or ::1, as URL.hostname spells them. */
function isLoopback(hostname: string): boolean {
  return hostname === 'localhost' || hostname === '[::1]' || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)
}

/**
 * The link, normalised, when it is safe to open in a browser and to copy;
 * else null. Safe means:
 * - https, or http on a loopback host (local development);
 * - the same origin as `apiBase`, the API the CLI talks to;
 * - no credentials, at most 200 characters, printable ASCII only, nothing
 *   outside RFC 3986 once normalised, and never starting with `-`, so no
 *   opener can take it for an option.
 */
export function openableUrl(value: unknown, apiBase: string): string | null {
  if (typeof value !== 'string' || value.length > MAX_TEXT_LENGTH) return null
  if (!PRINTABLE_ASCII.test(value) || value.startsWith('-')) return null
  let url: URL
  let base: URL
  try {
    url = new URL(value)
    base = new URL(apiBase)
  } catch {
    return null
  }
  if (!(url.protocol === 'https:' || (url.protocol === 'http:' && isLoopback(url.hostname)))) return null
  if (url.origin !== base.origin || url.username || url.password) return null
  return URL_CHARACTERS.test(url.href) ? url.href : null
}

/** The API's origin, for the "not on …" warning; the configured value, cleaned, if it doesn't parse. */
export function originOf(apiBase: string): string {
  try {
    return new URL(apiBase).origin
  } catch {
    return cleanText(apiBase)
  }
}
