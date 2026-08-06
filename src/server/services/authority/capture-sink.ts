/**
 * The one write door, as an `ActionSink`.
 *
 * Every authority Action — mint, attenuation, claim, use, revocation, refusal —
 * emits THROUGH the public capture door rather than into a store of this
 * service's own. Two ingest paths mean two canonicalizations, and then the
 * binding invariant between an authority record and its witnessed event is
 * untestable.
 *
 * ⚠ **This sink never fabricates a hash and never throws into a verb path.**
 * When the door is unset, unreachable, slow or answers anything but a 2xx with
 * a hash, the emit returns `confirmed: false` and the caller's receipt carries
 * an **`unconfirmed`** artifact. That is a presence state the contract already
 * has, it renders distinguishably in every face, and it is the truth: the
 * decision was recorded here and its witness is not yet confirmed.
 *
 * The alternative — failing the whole verb when capture is down — would make
 * `revoke` unavailable exactly when a customer most needs it, and REQ-7 says
 * you never pay, wait or log in to stop an agent.
 */

import type { ActionReceipt, ActionSink, AuthorityAction } from './types'

export interface CaptureActionSinkConfig {
  /** Absolute URL of the public capture door. Unset → every emit is unconfirmed. */
  captureUrl?: string
  /** Bearer credential for the door, when it requires one. */
  token?: string
  /** Milliseconds before an emit is abandoned as unconfirmed. */
  timeoutMs?: number
  /** Injected for tests. Defaults to global fetch. */
  fetchImpl?: typeof fetch
}

export class CaptureActionSink implements ActionSink {
  constructor(private readonly config: CaptureActionSinkConfig) {}

  async emit(action: AuthorityAction): Promise<ActionReceipt> {
    const url = this.config.captureUrl
    if (!url) return { confirmed: false }

    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), this.config.timeoutMs ?? 3000)
    try {
      const doFetch = this.config.fetchImpl ?? fetch
      const res = await doFetch(url, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          ...(this.config.token ? { authorization: `Bearer ${this.config.token}` } : {}),
        },
        body: JSON.stringify(action),
        signal: controller.signal,
      })
      if (!res.ok) return { confirmed: false }
      const body = (await res.json().catch(() => null)) as { eventHash?: unknown } | null
      const hash = body?.eventHash
      // A 2xx with no hash is not a confirmation. The door answered; it did not
      // hand back an artifact, and an artifact is what a settlement returns.
      if (typeof hash !== 'string' || hash.length === 0) return { confirmed: false }
      return { eventHash: hash, confirmed: true }
    } catch {
      return { confirmed: false }
    } finally {
      clearTimeout(timer)
    }
  }
}
