/**
 * RailAdapter — internal port that hides wire-format detail per
 * `(protocol, method)` pair.
 *
 * NOT exported from `src/sdk/payment/index.ts`. This is a private seam used
 * by the broker for rail negotiation, challenge synthesis, proof parsing,
 * and receipt formatting. One adapter per first-class rail; stub adapters
 * exist for the rails we name in `PaymentMethod` but haven't fully wired
 * (so rail-selection code compiles and we can add support incrementally).
 *
 * First-class rails in this pass:
 *   - `X402ExactAdapter`      — x402 + USDC + EIP-3009
 *   - `MppChargeTempoAdapter` — MPP `charge` intent over Tempo (USDC L1)
 *
 * Stubs (throw "not implemented" on use):
 *   - mpp-charge-stripe-spt, mpp-charge-solana, mpp-charge-lightning,
 *     mpp-charge-card
 */
import type { FacilitatorClient } from './facilitator'
import type { PaymentMethod, PaymentProtocol, PaymentRail, RailQuote } from './types'

/** Result of a successful proof verification — the broker turns this into a receipt. */
export interface RailVerified {
  /** Echoed from the proof so the caller can audit. */
  payer?: string
  /** Carried into FacilitatorClient.settle() unchanged. */
  payload: Record<string, unknown>
  /** Echoed from the proof. */
  accepted: RailQuote
}

/** Extracted proof shape — what the request carried in headers. */
export interface RailProof {
  protocol: PaymentProtocol
  method: PaymentMethod
  /** Wire payload — adapter-private. */
  payload: Record<string, unknown>
  /** The `accepts` entry the client picked. */
  accepted: RailQuote
}

export interface RailAdapter {
  /** Wire-protocol family this adapter speaks. */
  readonly protocol: PaymentProtocol
  /** Settlement method — keys the adapter map. */
  readonly method: PaymentMethod

  /**
   * Render the challenge body for this rail. x402 returns the
   * `PaymentRequirements` entry; MPP returns the `WWW-Authenticate`
   * `request=<base64url>` payload.
   */
  challenge(quote: RailQuote): Record<string, unknown>

  /**
   * Read proof from request headers. Returns null if no proof for this
   * rail is present — the broker probes adapters in order until one
   * matches or all decline.
   */
  parseProof(req: Request, accepts: RailQuote[]): RailProof | null

  /**
   * Verify proof via the configured facilitator (chain RPC is deferred).
   * Throws if the facilitator rejects; broker maps to `verify-failed`.
   */
  verify(proof: RailProof, facilitator: FacilitatorClient): Promise<RailVerified>

  /**
   * Settle proof via the configured facilitator. Returns the tx ref the
   * broker stamps onto the receipt.
   */
  settle(
    proof: RailProof,
    facilitator: FacilitatorClient,
  ): Promise<{ txRef: string; payer?: string }>

  /**
   * Build the rail-specific success header for the response. x402 emits
   * `PAYMENT-RESPONSE: <base64 JSON>`; MPP emits `Payment-Receipt: <token>`.
   */
  responseHeader(args: {
    txRef: string
    quote: RailQuote
    payer?: string
  }): [name: string, value: string]
}

// ───────────────────────────────────────────────────────────────────────
// Helpers — base64url codec (Web-Crypto-only; no Buffer in Workers)
// ───────────────────────────────────────────────────────────────────────

function base64Encode(input: string): string {
  // btoa handles ASCII; we encode UTF-8 first.
  const bytes = new TextEncoder().encode(input)
  let bin = ''
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!)
  return btoa(bin)
}

function base64UrlEncode(input: string): string {
  return base64Encode(input).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function base64Decode(input: string): string {
  const bin = atob(input)
  const bytes = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
  return new TextDecoder().decode(bytes)
}

function base64UrlDecode(input: string): string {
  let s = input.replace(/-/g, '+').replace(/_/g, '/')
  while (s.length % 4) s += '='
  return base64Decode(s)
}

/** Pick the first quote matching this adapter's (protocol, method). */
function matchQuote(adapter: RailAdapter, accepts: RailQuote[]): RailQuote | null {
  for (const q of accepts) {
    if (q.rail.protocol === adapter.protocol && q.rail.method === adapter.method) {
      return q
    }
  }
  return null
}

// ───────────────────────────────────────────────────────────────────────
// X402 + exact (USDC via EIP-3009)
// ───────────────────────────────────────────────────────────────────────

export class X402ExactAdapter implements RailAdapter {
  readonly protocol = 'x402' as const
  readonly method = 'exact' as const

  challenge(quote: RailQuote): Record<string, unknown> {
    return {
      scheme: 'exact',
      network: quote.rail.network,
      amount: quote.amount,
      asset: quote.asset,
      payTo: quote.payTo,
      maxTimeoutSeconds: quote.maxTimeoutSeconds,
      extra: quote.extra,
    }
  }

  parseProof(req: Request, accepts: RailQuote[]): RailProof | null {
    const header = req.headers.get('PAYMENT-SIGNATURE') ?? req.headers.get('payment-signature')
    if (!header) return null

    let parsed: { accepted?: Record<string, unknown>; payload?: Record<string, unknown> }
    try {
      parsed = JSON.parse(base64Decode(header)) as typeof parsed
    } catch {
      return null
    }

    const quote = matchQuote(this, accepts)
    if (!quote) return null

    return {
      protocol: this.protocol,
      method: this.method,
      payload: parsed.payload ?? {},
      accepted: quote,
    }
  }

  async verify(proof: RailProof, facilitator: FacilitatorClient): Promise<RailVerified> {
    const res = await facilitator.verify({
      protocol: this.protocol,
      method: this.method,
      network: proof.accepted.rail.network,
      accepted: this.toFacilitatorAccepted(proof.accepted),
      payload: proof.payload,
    })
    if (!res.valid) {
      throw new Error(`x402 verify failed: ${res.reason ?? 'verify-failed'}`)
    }
    return { payer: res.payer, payload: proof.payload, accepted: proof.accepted }
  }

  async settle(
    proof: RailProof,
    facilitator: FacilitatorClient,
  ): Promise<{ txRef: string; payer?: string }> {
    const res = await facilitator.settle({
      protocol: this.protocol,
      method: this.method,
      network: proof.accepted.rail.network,
      accepted: this.toFacilitatorAccepted(proof.accepted),
      payload: proof.payload,
    })
    if (!res.success || !res.transaction) {
      throw new Error(`x402 settle failed: ${res.errorReason ?? 'settle-failed'}`)
    }
    return { txRef: res.transaction, payer: res.payer }
  }

  responseHeader(args: { txRef: string; quote: RailQuote; payer?: string }): [string, string] {
    const body = {
      success: true,
      transaction: args.txRef,
      network: args.quote.rail.network,
      payer: args.payer,
    }
    return ['PAYMENT-RESPONSE', base64Encode(JSON.stringify(body))]
  }

  private toFacilitatorAccepted(quote: RailQuote) {
    return {
      scheme: 'exact',
      network: quote.rail.network,
      amount: quote.amount,
      asset: quote.asset,
      payTo: quote.payTo,
      maxTimeoutSeconds: quote.maxTimeoutSeconds,
      extra: quote.extra,
    }
  }
}

// ───────────────────────────────────────────────────────────────────────
// MPP + charge intent over Tempo
// ───────────────────────────────────────────────────────────────────────

export class MppChargeTempoAdapter implements RailAdapter {
  readonly protocol = 'mpp' as const
  readonly method = 'tempo' as const

  challenge(quote: RailQuote): Record<string, unknown> {
    // The MPP `request=…` body carries enough for the client to sign a
    // Tempo voucher: amount, payTo, network, asset, optional `extra`.
    return {
      method: 'tempo',
      network: quote.rail.network,
      amount: quote.amount,
      asset: quote.asset,
      payTo: quote.payTo,
      maxTimeoutSeconds: quote.maxTimeoutSeconds,
      extra: quote.extra,
    }
  }

  parseProof(req: Request, accepts: RailQuote[]): RailProof | null {
    const auth = req.headers.get('Authorization') ?? req.headers.get('authorization')
    if (!auth) return null
    if (!/^Payment\s+/i.test(auth)) return null

    // RFC 7235 auth params: `Payment k1=v1, k2="v2", …`
    const params = parseAuthParams(auth.replace(/^Payment\s+/i, ''))
    const intent = stripQuotes(params.intent)
    const method = stripQuotes(params.method)
    if (intent !== 'charge' || method !== this.method) return null

    const proofBody = stripQuotes(params.proof) ?? stripQuotes(params.response)
    if (!proofBody) return null

    let payload: Record<string, unknown>
    try {
      payload = JSON.parse(base64UrlDecode(proofBody)) as Record<string, unknown>
    } catch {
      return null
    }

    const quote = matchQuote(this, accepts)
    if (!quote) return null

    return {
      protocol: this.protocol,
      method: this.method,
      payload,
      accepted: quote,
    }
  }

  async verify(proof: RailProof, facilitator: FacilitatorClient): Promise<RailVerified> {
    const res = await facilitator.verify({
      protocol: this.protocol,
      method: this.method,
      network: proof.accepted.rail.network,
      accepted: this.toFacilitatorAccepted(proof.accepted),
      payload: proof.payload,
    })
    if (!res.valid) {
      throw new Error(`mpp verify failed: ${res.reason ?? 'verify-failed'}`)
    }
    return { payer: res.payer, payload: proof.payload, accepted: proof.accepted }
  }

  async settle(
    proof: RailProof,
    facilitator: FacilitatorClient,
  ): Promise<{ txRef: string; payer?: string }> {
    const res = await facilitator.settle({
      protocol: this.protocol,
      method: this.method,
      network: proof.accepted.rail.network,
      accepted: this.toFacilitatorAccepted(proof.accepted),
      payload: proof.payload,
    })
    if (!res.success || !res.transaction) {
      throw new Error(`mpp settle failed: ${res.errorReason ?? 'settle-failed'}`)
    }
    return { txRef: res.transaction, payer: res.payer }
  }

  responseHeader(args: { txRef: string; quote: RailQuote; payer?: string }): [string, string] {
    const body = {
      method: this.method,
      transaction: args.txRef,
      network: args.quote.rail.network,
      payer: args.payer,
    }
    return ['Payment-Receipt', base64UrlEncode(JSON.stringify(body))]
  }

  private toFacilitatorAccepted(quote: RailQuote) {
    return {
      method: this.method,
      network: quote.rail.network,
      amount: quote.amount,
      asset: quote.asset,
      payTo: quote.payTo,
      maxTimeoutSeconds: quote.maxTimeoutSeconds,
      extra: quote.extra,
    }
  }
}

// ───────────────────────────────────────────────────────────────────────
// Stubs — present so rail-selection code compiles
// ───────────────────────────────────────────────────────────────────────

function unimplemented(rail: PaymentRail): never {
  throw new Error(
    `rail not yet implemented: ${rail.protocol}/${rail.method}; pin to x402+exact or mpp+tempo for now`,
  )
}

class StubAdapter implements RailAdapter {
  constructor(
    readonly protocol: PaymentProtocol,
    readonly method: PaymentMethod,
  ) {}
  challenge(quote: RailQuote) {
    return unimplemented(quote.rail)
  }
  parseProof() {
    return null
  }
  async verify(): Promise<RailVerified> {
    throw new Error(`rail not yet implemented: ${this.protocol}/${this.method}`)
  }
  async settle(): Promise<{ txRef: string; payer?: string }> {
    throw new Error(`rail not yet implemented: ${this.protocol}/${this.method}`)
  }
  responseHeader(): [string, string] {
    throw new Error(`rail not yet implemented: ${this.protocol}/${this.method}`)
  }
}

export class MppChargeStripeSptAdapter extends StubAdapter {
  constructor() {
    super('mpp', 'stripe-spt')
  }
}
export class MppChargeSolanaAdapter extends StubAdapter {
  constructor() {
    super('mpp', 'solana')
  }
}
export class MppChargeLightningAdapter extends StubAdapter {
  constructor() {
    super('mpp', 'lightning')
  }
}
export class MppChargeCardAdapter extends StubAdapter {
  constructor() {
    super('mpp', 'card')
  }
}

// ───────────────────────────────────────────────────────────────────────
// Auth-param parser — RFC 7235 challenge / credentials params
// ───────────────────────────────────────────────────────────────────────

function parseAuthParams(input: string): Record<string, string> {
  const out: Record<string, string> = {}
  // Split on commas not inside quotes.
  const parts: string[] = []
  let buf = ''
  let inQuote = false
  for (let i = 0; i < input.length; i++) {
    const ch = input[i]!
    if (ch === '"' && input[i - 1] !== '\\') inQuote = !inQuote
    if (ch === ',' && !inQuote) {
      parts.push(buf)
      buf = ''
    } else {
      buf += ch
    }
  }
  if (buf.trim()) parts.push(buf)

  for (const part of parts) {
    const eq = part.indexOf('=')
    if (eq < 0) continue
    const k = part.slice(0, eq).trim()
    const v = part.slice(eq + 1).trim()
    if (k) out[k] = v
  }
  return out
}

function stripQuotes(v: string | undefined): string | undefined {
  if (v == null) return v
  if (v.length >= 2 && v.startsWith('"') && v.endsWith('"')) {
    return v.slice(1, -1).replace(/\\(.)/g, '$1')
  }
  return v
}

// ───────────────────────────────────────────────────────────────────────
// Public-to-broker helpers
// ───────────────────────────────────────────────────────────────────────

/** Render `WWW-Authenticate: Payment …` value for one quote. */
export function renderMppChallenge(args: {
  realm: string
  id: string
  quote: RailQuote
  intent: 'charge' | 'session'
  request: Record<string, unknown>
}): string {
  const params: string[] = []
  params.push(`id="${escapeQ(args.id)}"`)
  params.push(`realm="${escapeQ(args.realm)}"`)
  params.push(`method=${args.quote.rail.method}`)
  params.push(`intent=${args.intent}`)
  params.push(`request="${escapeQ(base64UrlEncode(JSON.stringify(args.request)))}"`)
  return `Payment ${params.join(', ')}`
}

/** Render `PAYMENT-REQUIRED` body for x402 v2. */
export function renderX402Required(args: {
  resource: string
  accepts: Array<Record<string, unknown>>
  error?: string
}): string {
  const body = {
    x402Version: 2,
    error: args.error ?? '',
    resource: args.resource,
    accepts: args.accepts,
  }
  return base64Encode(JSON.stringify(body))
}

function escapeQ(v: string): string {
  return v.replace(/\\/g, '\\\\').replace(/"/g, '\\"')
}

// Re-export base64 helpers for tests.
export const __test = { base64Encode, base64UrlEncode, base64Decode, base64UrlDecode }
