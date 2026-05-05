/**
 * PaymentBrokerImpl — phase 1 implementation.
 *
 * Scope:
 *   - x402 `exact` scheme (USDC via EIP-3009)
 *   - MPP `charge` intent over Tempo
 *   - Bare `{amount}` shape expanded to default rails (USDC on Base via
 *     both protocols)
 *   - Verification + settlement delegated to a FacilitatorClient
 *     (Coinbase, Cloudflare, Stripe all run public facilitators); on-chain
 *     verification without a facilitator is deferred to a later pass
 *
 * Out of scope (this pass):
 *   - MPP `session` intent (escrow + cumulative vouchers) — `session()`
 *     throws "not yet implemented"
 *   - On-chain RPC (no viem / ethers in the Worker bundle)
 *   - Stub rails: stripe-spt, solana, lightning, card
 *
 * The broker stays portable — no `cloudflare:workers` import; no DO state.
 */
import type { Identity } from '../types'
import type { PaymentBroker } from './broker'
import type { FacilitatorClient } from './facilitator'
import {
  MppChargeCardAdapter,
  MppChargeLightningAdapter,
  MppChargeSolanaAdapter,
  MppChargeStripeSptAdapter,
  MppChargeTempoAdapter,
  X402ExactAdapter,
  renderMppChallenge,
  renderX402Required,
  type RailAdapter,
  type RailProof,
} from './rails'
import type {
  PaymentInstrument,
  PaymentOutcome,
  PaymentRail,
  PaymentRejection,
  PaymentRequired,
  PaymentSession,
  RailQuote,
  SessionRequired,
} from './types'

export interface PaymentBrokerConfig {
  /** Facilitator client used for /verify and /settle. */
  facilitator: FacilitatorClient
  /** Default `payTo` for the bare `{amount}` shape. CAIP-10 / merchant id. */
  defaultPayTo?: string
  /** Default asset for the bare `{amount}` shape. Default: 'USDC'. */
  defaultAsset?: string
  /** Default network (CAIP-2). Default: 'eip155:8453' (Base). */
  defaultNetwork?: string
  /** Realm for the MPP `WWW-Authenticate: Payment` challenge. */
  realm?: string
  /** Resource URL stamped into the x402 `PAYMENT-REQUIRED` body. */
  resourceUrl?: string
  /** Adapter overrides — useful for tests or pinning a custom rail. */
  adapters?: RailAdapter[]
}

const DEFAULT_NETWORK = 'eip155:8453'
const DEFAULT_ASSET = 'USDC'
const DEFAULT_TIMEOUT_SECONDS = 60

export class PaymentBrokerImpl implements PaymentBroker {
  private readonly adapters: RailAdapter[]

  constructor(private readonly config: PaymentBrokerConfig) {
    this.adapters = config.adapters ?? [
      new X402ExactAdapter(),
      new MppChargeTempoAdapter(),
      new MppChargeStripeSptAdapter(),
      new MppChargeSolanaAdapter(),
      new MppChargeLightningAdapter(),
      new MppChargeCardAdapter(),
    ]
  }

  async settle(
    req: Request,
    identity: Identity,
    required: PaymentRequired,
  ): Promise<PaymentOutcome> {
    // Reject `session` intent here — covered by `session()`.
    if ('intent' in required && required.intent === 'session') {
      return this.reject('rail-unsupported', [], req, 'session intent must be opened via session()')
    }

    // 1. Expand the requirement into a list of accepted rail quotes.
    const quotes = this.expandQuotes(required)

    // 2. Intersect with what the identity can actually pay.
    const supportable = this.intersectWithIdentity(quotes, identity)
    if (supportable.length === 0) {
      return this.reject('no-instrument', quotes, req)
    }

    // 3. Probe adapters for a proof on the request.
    let proof: RailProof | null = null
    let adapter: RailAdapter | null = null
    for (const a of this.adaptersFor(supportable)) {
      const p = a.parseProof(req, supportable)
      if (p) {
        proof = p
        adapter = a
        break
      }
    }

    if (!proof || !adapter) {
      return this.reject('no-payment', supportable, req)
    }

    // 4. Verify via facilitator.
    let payer: string | undefined
    try {
      const verified = await adapter.verify(proof, this.config.facilitator)
      payer = verified.payer
    } catch (err) {
      return this.reject('verify-failed', supportable, req, errMsg(err))
    }

    // 5. Settle via facilitator.
    let settled: { txRef: string; payer?: string }
    try {
      settled = await adapter.settle(proof, this.config.facilitator)
    } catch (err) {
      return this.reject('declined', supportable, req, errMsg(err))
    }

    const finalPayer = settled.payer ?? payer
    return {
      ok: true,
      rail: proof.accepted.rail,
      amount: proof.accepted.amount,
      asset: proof.accepted.asset,
      txRef: settled.txRef,
      settledAt: Date.now(),
      responseHeader: adapter.responseHeader({
        txRef: settled.txRef,
        quote: proof.accepted,
        payer: finalPayer,
      }),
    }
  }

  async session(
    _identity: Identity,
    _required: SessionRequired,
  ): Promise<PaymentSession | PaymentRejection> {
    throw new Error(
      'MPP session intent not yet implemented — use settle() with charge intent for now',
    )
  }

  async instrumentsFor(identity: Identity): Promise<PaymentInstrument[]> {
    return identity.paymentInstruments ?? []
  }

  // ─── internals ────────────────────────────────────────────────────────

  /** Default rails for the bare `{amount}` shape. */
  private defaultRails(): PaymentRail[] {
    const network = this.config.defaultNetwork ?? DEFAULT_NETWORK
    const asset = this.config.defaultAsset ?? DEFAULT_ASSET
    return [
      { protocol: 'x402', method: 'exact', network, asset },
      { protocol: 'mpp', method: 'tempo', network, asset },
    ]
  }

  /** Convert any `PaymentRequired` shape into a flat list of `RailQuote`s. */
  private expandQuotes(required: PaymentRequired): RailQuote[] {
    if ('intent' in required) {
      // 'charge' or 'session' (session rejected upstream).
      return required.accepts
    }
    const asset = required.asset ?? this.config.defaultAsset ?? DEFAULT_ASSET
    const payTo = required.payTo ?? this.config.defaultPayTo ?? ''
    return this.defaultRails().map((rail) => ({
      rail,
      amount: required.amount,
      asset,
      payTo,
      maxTimeoutSeconds: DEFAULT_TIMEOUT_SECONDS,
    }))
  }

  /** Keep only quotes whose rail an instrument can settle. */
  private intersectWithIdentity(quotes: RailQuote[], identity: Identity): RailQuote[] {
    const instruments = identity.paymentInstruments ?? []
    if (instruments.length === 0) return []
    return quotes.filter((q) =>
      instruments.some((inst) => inst.rails.some((r) => railEquivalent(r, q.rail))),
    )
  }

  /** Adapters relevant to a given quote set, in iteration order. */
  private adaptersFor(quotes: RailQuote[]): RailAdapter[] {
    return this.adapters.filter((a) =>
      quotes.some((q) => q.rail.protocol === a.protocol && q.rail.method === a.method),
    )
  }

  /** Build a 402 with both x402 and MPP challenge headers. */
  private reject(
    reason: PaymentRejection['reason'],
    quotes: RailQuote[],
    req: Request,
    errorMessage?: string,
  ): PaymentRejection {
    const headers = new Headers()
    const realm = this.config.realm ?? 'id.org.ai'
    const resource = this.config.resourceUrl ?? new URL(req.url).toString()

    if (quotes.length > 0) {
      // x402 `PAYMENT-REQUIRED` — base64 JSON, all accepted rails.
      const x402Accepts = quotes
        .filter((q) => q.rail.protocol === 'x402')
        .map((q) => this.x402AcceptsEntry(q))
      // x402 spec is happy to list any quote in PAYMENT-REQUIRED so callers
      // see all acceptable rails; we also include MPP-tempo flattened so
      // x402-only clients can fall back to a USDC payment if the wire
      // semantics overlap.
      const allAccepts =
        x402Accepts.length > 0
          ? x402Accepts
          : quotes.map((q) => this.x402AcceptsEntry(q))
      headers.set(
        'PAYMENT-REQUIRED',
        renderX402Required({ resource, accepts: allAccepts, error: errorMessage }),
      )

      // MPP `WWW-Authenticate: Payment` — one challenge per accepted rail.
      const mppQuotes = quotes.filter((q) => q.rail.protocol === 'mpp')
      const challengeQuotes = mppQuotes.length > 0 ? mppQuotes : quotes
      for (const q of challengeQuotes) {
        headers.append(
          'WWW-Authenticate',
          renderMppChallenge({
            id: `chg_${shortId()}`,
            realm,
            quote: q,
            intent: 'charge',
            request: {
              method: q.rail.method,
              network: q.rail.network,
              amount: q.amount,
              asset: q.asset,
              payTo: q.payTo,
              maxTimeoutSeconds: q.maxTimeoutSeconds,
              extra: q.extra,
            },
          }),
        )
      }
    } else {
      headers.set(
        'PAYMENT-REQUIRED',
        renderX402Required({
          resource,
          accepts: [],
          error: errorMessage ?? reason,
        }),
      )
    }

    return {
      ok: false,
      reason,
      response: new Response(JSON.stringify({ error: 'payment_required', reason }), {
        status: 402,
        headers: mergeHeaders(headers, { 'Content-Type': 'application/json' }),
      }),
    }
  }

  private x402AcceptsEntry(q: RailQuote): Record<string, unknown> {
    return {
      scheme: q.rail.method === 'exact' ? 'exact' : q.rail.method,
      network: q.rail.network,
      amount: q.amount,
      asset: q.asset,
      payTo: q.payTo,
      maxTimeoutSeconds: q.maxTimeoutSeconds,
      extra: q.extra,
    }
  }
}

/** Two rails are equivalent when protocol+method match; network/asset only narrow. */
function railEquivalent(a: PaymentRail, b: PaymentRail): boolean {
  if (a.protocol !== b.protocol) return false
  if (a.method !== b.method) return false
  if (a.network && b.network && a.network !== b.network) return false
  if (a.asset && b.asset && a.asset !== b.asset) return false
  return true
}

function mergeHeaders(headers: Headers, extras: Record<string, string>): Headers {
  for (const [k, v] of Object.entries(extras)) headers.set(k, v)
  return headers
}

function errMsg(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

function shortId(): string {
  // 8 hex chars — enough entropy for a challenge id, no crypto import needed.
  return Math.floor(Math.random() * 0xffffffff).toString(16).padStart(8, '0')
}
