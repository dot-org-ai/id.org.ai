/**
 * Payment domain types — shared across the PaymentBroker, the wire-format
 * adapters (x402, MPP), and consumers in primitives.org.ai.
 *
 * Naming follows the IETF `draft-httpauth-payment-00` (MPP) and the x402
 * v2 spec: a *rail* is the `(protocol, method)` pair that determines the
 * wire format and settlement chain. MPP is backwards-compatible with x402
 * — a `charge`-intent MPP request maps cleanly onto x402's `exact` scheme.
 */

/** Wire-level protocol family. */
export type PaymentProtocol = 'x402' | 'mpp'

/**
 * Settlement method. Open string union — the IETF MPP draft makes methods
 * pluggable, so consumers can extend without a library version bump.
 */
export type PaymentMethod =
  | 'exact' // x402 'exact' scheme (USDC via EIP-3009)
  | 'tempo' // MPP method: Tempo stablecoin L1
  | 'stripe-spt' // MPP method: Stripe Shared Payment Token
  | 'solana' // MPP method: Solana USDC
  | 'lightning' // MPP method: Bitcoin Lightning
  | 'card' // MPP method: Visa/Mastercard network token
  | (string & {})

/** A specific wire-protocol + settlement-chain pair. */
export interface PaymentRail {
  protocol: PaymentProtocol
  method: PaymentMethod
  /** CAIP-2 chain identifier (e.g. 'eip155:8453' for Base). */
  network?: string
  /** CAIP-19 asset identifier or short symbol (e.g. 'USDC'). */
  asset?: string
}

/**
 * A payment instrument the Identity has bound (wallet, SPT, card via SPT,
 * Lightning channel, …). One instrument may satisfy multiple rails — a
 * single USDC wallet can pay via x402-exact and MPP-charge-tempo.
 */
export interface PaymentInstrument {
  /** Stable id, e.g. `pi_…`. */
  id: string
  /** Rails this instrument can settle on. */
  rails: PaymentRail[]
  /** Caller-facing reference (`••••4242`, `0xabc…`, `lnbc…`). */
  display?: string
  /** Per-period spend cap, enforced by the broker. */
  spendCap?: {
    amount: string
    currency: string
    period: 'session' | 'day'
  }
  /** Adapter-private detail (token, customer id, escrow handle). */
  meta?: Record<string, unknown>
}

/**
 * What a server demands. Three shapes — the bare `{ amount }` form is the
 * 95% case (one currency, default rails); the explicit `intent: 'charge'`
 * form lets callers list multiple accepted rails; the `intent: 'session'`
 * form opens an MPP escrow for sub-100-ms repeated spends.
 */
export type PaymentRequired =
  | {
      /** Decimal string in asset-major units (e.g. '0.01' for one USDC cent). */
      amount: string
      /** Default 'USDC'. */
      asset?: string
      /** Recipient — CAIP-10 / merchant id. Defaults to broker config. */
      payTo?: string
      /** Free-form description of what the payment buys. */
      description?: string
    }
  | {
      intent: 'charge'
      /** Accepted rail+price tuples. Server lists all rails it can settle. */
      accepts: RailQuote[]
      description?: string
    }
  | SessionRequired

export interface SessionRequired {
  intent: 'session'
  /** Total escrow budget in asset-major units. */
  budget: string
  /** Session expires after N seconds. */
  ttlSeconds: number
  accepts: RailQuote[]
  description?: string
}

export interface RailQuote {
  rail: PaymentRail
  amount: string
  asset: string
  payTo: string
  maxTimeoutSeconds?: number
  /** Scheme-specific extras (EIP-3009 nonce, MPP-method extension fields). */
  extra?: Record<string, unknown>
}

/** Successful settlement. */
export interface PaymentReceipt {
  ok: true
  rail: PaymentRail
  /** Asset-major amount actually settled. */
  amount: string
  asset: string
  /** Transaction hash, voucher id, or Stripe charge id. */
  txRef: string
  settledAt: number
  /**
   * Header to echo back on the response.
   * x402: `['PAYMENT-RESPONSE', '<base64 SettlementResponse>']`
   * MPP:  `['Payment-Receipt', '<receipt token>']`
   */
  responseHeader: [name: string, value: string]
}

/** Settlement failed; the broker also synthesises the 402 the route can return. */
export interface PaymentRejection {
  ok: false
  reason:
    | 'no-payment'
    | 'no-instrument'
    | 'rail-unsupported'
    | 'insufficient-funds'
    | 'declined'
    | 'expired'
    | 'frozen'
    | 'verify-failed'
  /**
   * Pre-baked 402 with `WWW-Authenticate: Payment` (MPP) and
   * `PAYMENT-REQUIRED` (x402) headers set so x402-only and MPP-aware
   * clients both know what to send back.
   */
  response: Response
}

export type PaymentOutcome = PaymentReceipt | PaymentRejection

/**
 * Active MPP session — escrow opened, callers spend cumulatively against
 * `remaining`, then `close()` batch-settles on chain. State lives behind
 * this handle; callers never touch the underlying voucher chain.
 */
export interface PaymentSession {
  id: string
  /** Asset-major remaining budget. */
  remaining: string
  /** Sign and record one cumulative voucher; sub-100ms (no RPC). */
  spend(amount: string, memo?: string): Promise<PaymentReceipt | PaymentRejection>
  /** Batch-settle the cumulative voucher to chain; refund unspent escrow. */
  close(): Promise<PaymentReceipt>
}

/**
 * A contact channel for the Identity — how it can be reached. Used by
 * digital-tasks for human-in-the-loop dispatch (preferred channel for
 * Tasks) and by id.org.ai for OOB notifications.
 */
export interface ContactChannel {
  kind: 'email' | 'phone' | 'slack' | 'webhook' | (string & {})
  value: string
  /** Caller-facing label (e.g. "Work email"). */
  label?: string
  verified?: boolean
}
