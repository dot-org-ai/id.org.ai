/**
 * The guess budget for emailed sign-in codes (security review S1).
 *
 * Two routes turn a 6-digit WorkOS Magic Auth code into a session:
 *
 *   POST /federation/email/verify   (worker/routes/federation.ts)
 *   POST /magic-link/:flow          (worker/routes/magic-link.ts)
 *
 * Each route bounds its own transaction (a send transaction, a flow) to 5
 * guesses. That alone is not enough: every new transaction would buy 5 more
 * guesses at the same mailbox's code. So both routes also reserve every guess
 * here, BEFORE WorkOS is asked, against two shared fixed-window budgets:
 *
 *   per email  5 guesses per 15 minutes, keyed on the normalised address,
 *              shared by both routes. A new code sent to the address (either
 *              route) and a successful sign-in start it afresh: after 5
 *              wrong guesses the address is refused until a new send.
 *   per IP     50 guesses per hour across every address and both routes,
 *              keyed on CF-Connecting-IP (requests without one share a
 *              single bucket, so a missing header never escapes the cap).
 *
 * Because a send starts the address's guess budget afresh, the sends
 * themselves are the other half of the bound. Both routes that have a code
 * emailed (POST /federation/email/send, POST /api/magic-link and its RPC twin
 * AuthService.sendMagicLink) reserve every send, BEFORE WorkOS is asked,
 * against ONE shared per-address counter:
 *
 *   sends      5 per address per hour (`code-send:<normalised email>`,
 *              src/sdk/federation/email-code.ts), whichever route sends.
 *
 * So sends can restart an address's guess budget at most 5 times an hour,
 * however they race: within a 15-minute guess window an address sees at most
 * 5 guesses per successful send.
 *
 * Reservation is one atomic Durable Object call per budget
 * (IdentityDO.consumeBudget), so parallel guesses or sends cannot overrun
 * any of them. Every budget lives in one dedicated shard so the routes count
 * together.
 */
import type { Env } from '../types'
import { getStubForIdentity } from '../middleware/tenant'

const GUARD_SHARD = 'signin-code-guard'

export const CODE_GUESSES_PER_EMAIL = { max: 5, windowMs: 15 * 60 * 1000 }
export const CODE_GUESSES_PER_IP = { max: 50, windowMs: 60 * 60 * 1000 }

/** The send budget: 5 codes per address per hour. */
export const CODE_SENDS_PER_EMAIL = { max: 5, windowMs: 60 * 60 * 1000 } as const

/**
 * The one per-address send counter, keyed on the normalised address so casing
 * games do not buy extra sends. It is one atomic consume, not a get/put pair:
 * a read followed by a separate write lets N parallel sends all pass.
 */
export const codeSendKey = (email: string) => `code-send:${email.trim().toLowerCase()}`

const emailKey = (email: string) => `code-guess:email:${email.trim().toLowerCase()}`
const ipKey = (ip: string) => `code-guess:ip:${ip}`

/** The client IP Cloudflare saw, or a shared bucket when there is none. */
export function clientIpOf(request: Request): string {
  return request.headers.get('cf-connecting-ip')?.trim() || 'none'
}

export type CodeGuessReservation = { ok: true } | { ok: false; scope: 'email' | 'ip'; retryAfterSec: number }

/**
 * Reserve one guess at `email`'s code from `ip`. The caller asks WorkOS only
 * when this answers `ok`. The IP budget is checked first, so a capped IP does
 * not also spend the address's budget.
 */
export async function reserveCodeGuess(env: Env, email: string, ip: string): Promise<CodeGuessReservation> {
  const stub = getStubForIdentity(env, GUARD_SHARD)
  const byIp = await stub.consumeBudget({ key: ipKey(ip), ...CODE_GUESSES_PER_IP })
  if (!byIp.allowed) return { ok: false, scope: 'ip', retryAfterSec: byIp.retryAfterSec }
  const byEmail = await stub.consumeBudget({ key: emailKey(email), ...CODE_GUESSES_PER_EMAIL })
  if (!byEmail.allowed) return { ok: false, scope: 'email', retryAfterSec: byEmail.retryAfterSec }
  return { ok: true }
}

/**
 * Reserve one send of a sign-in code to `email` from the address's shared
 * hourly send budget. The caller asks WorkOS to send only when this answers
 * `ok`; a reservation is spent even if the send then fails (fail closed).
 */
export async function reserveCodeSend(env: Env, email: string): Promise<{ ok: true } | { ok: false; retryAfterSec: number }> {
  const stub = getStubForIdentity(env, GUARD_SHARD)
  const r = await stub.consumeBudget({ key: codeSendKey(email), ...CODE_SENDS_PER_EMAIL })
  return r.allowed ? { ok: true } : { ok: false, retryAfterSec: Math.max(1, r.retryAfterSec ?? 1) }
}

/**
 * A new code went to `email`, or it signed in: its guess budget starts afresh.
 * Called only after a send reserved through `reserveCodeSend` succeeded (or a
 * sign-in), so resets are bounded by the send budget.
 */
export async function resetCodeGuesses(env: Env, email: string): Promise<void> {
  await getStubForIdentity(env, GUARD_SHARD).oauthStorageOp({ op: 'delete', key: emailKey(email) })
}
