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
 * Reservation is one atomic Durable Object call per budget
 * (IdentityDO.consumeBudget), so parallel guesses cannot overrun either.
 * Both budgets live in one dedicated shard so the two routes count together.
 */
import type { Env } from '../types'
import { getStubForIdentity } from '../middleware/tenant'

const GUARD_SHARD = 'signin-code-guard'

export const CODE_GUESSES_PER_EMAIL = { max: 5, windowMs: 15 * 60 * 1000 }
export const CODE_GUESSES_PER_IP = { max: 50, windowMs: 60 * 60 * 1000 }

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

/** A new code went to `email`, or it signed in: its guess budget starts afresh. */
export async function resetCodeGuesses(env: Env, email: string): Promise<void> {
  await getStubForIdentity(env, GUARD_SHARD).oauthStorageOp({ op: 'delete', key: emailKey(email) })
}
