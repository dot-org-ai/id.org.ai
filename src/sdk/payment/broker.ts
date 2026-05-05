/**
 * PaymentBroker — pay-per-call settlement for tools and APIs.
 *
 * The broker mediates between an Identity (with bound payment instruments)
 * and a server demanding payment. It speaks both x402 (Coinbase, custom
 * `PAYMENT-*` headers) and MPP (Stripe + Tempo, `WWW-Authenticate: Payment`)
 * — MPP is backwards-compatible with x402 so the same instrument can settle
 * either way.
 *
 * The interface is two methods (one-shot and session). All wire-protocol
 * detail, rail selection, facilitator round-tripping, and 402 synthesis
 * lives behind this seam.
 */
import type { Identity } from '../types'
import type {
  PaymentOutcome,
  PaymentRequired,
  PaymentSession,
  PaymentInstrument,
  PaymentRejection,
  SessionRequired,
} from './types'

export interface PaymentBroker {
  /**
   * One-shot charge. Maps to x402 `exact` scheme or MPP `charge` intent.
   * Returns a receipt on success; a `PaymentRejection` (with a pre-baked
   * 402 Response) on failure that the caller can return directly.
   */
  settle(identity: Identity, required: PaymentRequired): Promise<PaymentOutcome>

  /**
   * Open an MPP session — escrow + cumulative EIP-712 vouchers. Returns a
   * `PaymentSession` handle whose `.spend()` is sub-100ms (no RPC per
   * call); `.close()` batch-settles to chain.
   */
  session(
    identity: Identity,
    required: SessionRequired,
  ): Promise<PaymentSession | PaymentRejection>

  /** What the Identity has bound. Useful for UIs and rail negotiation. */
  instrumentsFor(identity: Identity): Promise<PaymentInstrument[]>
}
