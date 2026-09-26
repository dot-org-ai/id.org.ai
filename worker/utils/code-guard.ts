/**
 * The guess and send budgets for emailed sign-in codes (security review S1,
 * round-2 B2, round-3 lockout fix).
 *
 * Two paths turn a 6-digit WorkOS Magic Auth code into a session:
 *
 *   fed  POST /federation/email/send  -> POST /federation/email/verify
 *        (worker/routes/federation.ts): public, anyone can ask.
 *   ml   POST /api/magic-link (listed clients) and AuthService.sendMagicLink
 *        (service bindings) -> POST /magic-link/:flow
 *        (worker/routes/magic-link.ts).
 *
 * Every budget below is PER PATH, keyed `<kind>:<path>:<normalised email>`.
 * They used to be one per-address counter shared by both paths, which let
 * anyone who can reach the public federation form spend the address's whole
 * send budget (5 an hour) and so lock that person out of magic-link sign-in.
 * Split, a flood on one path cannot touch the other path's counters.
 *
 *   sends      5 per address per hour, per path (`code-send:<path>:<email>`,
 *              src/sdk/federation/email-code.ts), reserved BEFORE WorkOS is
 *              asked to send.
 *   guesses    5 per address per 15 minutes, per path
 *              (`code-guess:email:<path>:<email>`), reserved BEFORE WorkOS is
 *              asked to check. Started afresh ONLY by a send reserved on the
 *              same path (or a sign-in on it), so its resets are bounded by
 *              that path's own send counter.
 *   per IP     50 guesses per hour across every address and both paths,
 *              keyed on CF-Connecting-IP (requests without one share a
 *              single bucket, so a missing header never escapes the cap).
 *
 * Every guess must also belong to one send: a /federation/email/verify must
 * present the transaction a successful send opened, a /magic-link/:flow guess
 * the flow a reserved send opened, and each transaction or flow allows 5
 * guesses. So on each path, guesses <= 5 x sends on that path.
 *
 * The bound, per address: 5 sends per path per send window (1 hour from the
 * window's first send) x 5 guesses per send = 25 guesses per path, 50 across
 * both paths per window. A 60-minute interval can straddle two fixed send
 * windows, so over any 60 minutes the worst case is 100 guesses at one
 * mailbox (10 sends x 5 guesses x 2 paths), against a 6-digit code.
 *
 * Reservation is one atomic Durable Object call per budget
 * (IdentityDO.consumeBudget), so parallel guesses or sends cannot overrun
 * any of them. Every budget lives in one dedicated shard.
 */
import type { Env } from '../types'
import { getStubForIdentity } from '../middleware/tenant'
import { reserveEmailCodeSend } from '../../src/sdk/federation/email-code'
import type { CodeSendPath } from '../../src/sdk/federation/email-code'

export type { CodeSendPath }

const GUARD_SHARD = 'signin-code-guard'

export const CODE_GUESSES_PER_EMAIL = { max: 5, windowMs: 15 * 60 * 1000 }
export const CODE_GUESSES_PER_IP = { max: 50, windowMs: 60 * 60 * 1000 }

export const codeGuessKey = (email: string, path: CodeSendPath) => `code-guess:email:${path}:${email.trim().toLowerCase()}`
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
  const r = await reserveEmailCodeSend({ consume: (input) => stub.consumeBudget(input) }, email, { path })
  return r.allowed ? { ok: true } : { ok: false, retryAfterSec: r.retryAfterSec }
}

/**
 * A new code went to `email` on `path`, or it signed in there: that path's
 * guess budget starts afresh. Called only after a send reserved through
 * `reserveCodeSend` on the SAME path succeeded (or a sign-in), so its resets
 * are bounded by that path's send budget. The other path's budget is untouched.
 */
export async function resetCodeGuesses(env: Env, email: string, path: CodeSendPath): Promise<void> {
  await getStubForIdentity(env, GUARD_SHARD).oauthStorageOp({ op: 'delete', key: codeGuessKey(email, path) })
}
