/**
 * The guess and send budgets for emailed sign-in codes (security review S1,
 * round-2 B2, round-3 lockout fix).
 *
 * One path turns a 6-digit WorkOS Magic Auth code into a session on this
 * branch:
 *
 *   ml   POST /api/magic-link (listed clients) and AuthService.sendMagicLink
 *        (service bindings) -> POST /magic-link/:flow
 *        (worker/routes/magic-link.ts).
 *
 * Every budget below is PER PATH, keyed `<kind>:<path>:<normalised email>`,
 * so that a future public code-sending path (the unmerged upstream-federation
 * email fallback had one) cannot spend this path's budget and lock a person
 * out of magic-link sign-in. The keys are the ones the live worker uses, so
 * counters already in the `signin-code-guard` shard carry over unchanged.
 *
 *   sends      5 per address per hour (`code-send:ml:<email>`), reserved
 *              BEFORE WorkOS is asked to send.
 *   guesses    5 per address per 15 minutes (`code-guess:email:ml:<email>`),
 *              reserved BEFORE WorkOS is asked to check. Started afresh ONLY
 *              by a send reserved on the same path (or a sign-in on it), so
 *              its resets are bounded by the path's own send counter.
 *   per IP     50 guesses per hour across every address, keyed on
 *              CF-Connecting-IP (requests without one share a single bucket,
 *              so a missing header never escapes the cap).
 *
 * Every guess must also belong to one send: a /magic-link/:flow guess needs
 * the flow a reserved send opened, and each flow allows 5 guesses. So
 * guesses <= 5 x sends.
 *
 * The bound, per address: 5 sends per send window (1 hour from the window's
 * first send) x 5 guesses per send = 25 guesses per window. A 60-minute
 * interval can straddle two fixed send windows, so over any 60 minutes the
 * worst case is 50 guesses at one mailbox, against a 6-digit code.
 *
 * Reservation is one atomic Durable Object call per budget
 * (IdentityDO.consumeBudget), not a get/put pair (a read followed by a
 * separate write lets N parallel requests all pass), so parallel guesses or
 * sends cannot overrun any of them. Every budget lives in one dedicated shard.
 */
import type { Env } from '../types'
import { getStubForIdentity } from '../middleware/tenant'

/**
 * Which sign-in path a send or guess belongs to. Only magic-link exists here;
 * the type keeps the per-path key shape the live worker uses.
 */
export type CodeSendPath = 'ml'

const GUARD_SHARD = 'signin-code-guard'

export const CODE_GUESSES_PER_EMAIL = { max: 5, windowMs: 15 * 60 * 1000 }
export const CODE_GUESSES_PER_IP = { max: 50, windowMs: 60 * 60 * 1000 }
/** The send budget: 5 codes per address per hour, per path. */
export const CODE_SENDS_PER_EMAIL = { max: 5, windowMs: 60 * 60 * 1000 } as const

const normalizeEmail = (email: string) => email.trim().toLowerCase()

/** The per-address send counter of one path: `code-send:ml:<email>`. */
export const codeSendKey = (email: string, path: CodeSendPath) => `code-send:${path}:${normalizeEmail(email)}`
export const codeGuessKey = (email: string, path: CodeSendPath) => `code-guess:email:${path}:${normalizeEmail(email)}`
const ipKey = (ip: string) => `code-guess:ip:${ip}`

/** The client IP Cloudflare saw, or a shared bucket when there is none. */
export function clientIpOf(request: Request): string {
  return request.headers.get('cf-connecting-ip')?.trim() || 'none'
}

export type CodeGuessReservation = { ok: true } | { ok: false; scope: 'email' | 'ip'; retryAfterSec: number }

/**
 * Reserve one guess at `email`'s code from `ip` on `path`. The caller asks
 * WorkOS only when this answers `ok`. The IP budget is checked first, so a
 * capped IP does not also spend the address's budget.
 */
export async function reserveCodeGuess(env: Env, email: string, ip: string, path: CodeSendPath): Promise<CodeGuessReservation> {
  const stub = getStubForIdentity(env, GUARD_SHARD)
  const byIp = await stub.consumeBudget({ key: ipKey(ip), ...CODE_GUESSES_PER_IP })
  if (!byIp.allowed) return { ok: false, scope: 'ip', retryAfterSec: byIp.retryAfterSec }
  const byEmail = await stub.consumeBudget({ key: codeGuessKey(email, path), ...CODE_GUESSES_PER_EMAIL })
  if (!byEmail.allowed) return { ok: false, scope: 'email', retryAfterSec: byEmail.retryAfterSec }
  return { ok: true }
}

/**
 * Reserve one send of a sign-in code to `email` from `path`'s hourly send
 * budget for the address. The caller asks WorkOS to send only when this
 * answers `ok`; a reservation is spent even if the send then fails (fail
 * closed).
 */
export async function reserveCodeSend(env: Env, email: string, path: CodeSendPath): Promise<{ ok: true } | { ok: false; retryAfterSec: number }> {
  const stub = getStubForIdentity(env, GUARD_SHARD)
  const r = await stub.consumeBudget({ key: codeSendKey(email, path), ...CODE_SENDS_PER_EMAIL })
  return r.allowed ? { ok: true } : { ok: false, retryAfterSec: Math.max(1, r.retryAfterSec ?? 1) }
}

/**
 * A new code went to `email` on `path`, or it signed in there: that path's
 * guess budget starts afresh. Called only after a send reserved through
 * `reserveCodeSend` on the SAME path succeeded (or a sign-in), so its resets
 * are bounded by that path's send budget.
 */
export async function resetCodeGuesses(env: Env, email: string, path: CodeSendPath): Promise<void> {
  await getStubForIdentity(env, GUARD_SHARD).oauthStorageOp({ op: 'delete', key: codeGuessKey(email, path) })
}
