/**
 * dlvp/settlement.ts — the MONEY-SAFE settlement PORT (Phase-6, SYNTHESIS §3).
 *
 * A single seam between the DLVP settle path and the value rail, copying the
 * honest-default pattern of `registry/port.ts` (emptyRegistryPort → typed
 * not-provisioned) and `src/sdk/payment` (verify/settle vocabulary). Two-phase:
 *   prepare  → escrow HOLD / authorize (fallible)
 *   commit   → CAPTURE (the point of no return on the rail)
 *   void     → compensating release (never throws)
 * This ordering lets the caller sign the receipt (fallible, local) BETWEEN
 * prepare and commit, and void the hold if anything fails — so disclosure and
 * value clear together or NEITHER (atomic-or-nothing).
 *
 * ┌─ MONEY-SAFETY (hard) — do NOT relax ──────────────────────────────────────┐
 * │ NO live payments, NO real money movement, NO payments.do credentials, NO   │
 * │ new provisioned binding, NO live keys. The PRODUCTION default is           │
 * │ noopSettlementPort — FAIL-CLOSED (mirrors emptyRegistryPort): every prepare │
 * │ returns not-provisioned, so no money ever moves without an explicitly-wired │
 * │ adapter. mockSettlementPort is TEST-ONLY. LiveValueRailSettlement is the    │
 * │ real adapter SHAPE wired to NOTHING — it throws not-provisioned until the   │
 * │ deferred value-rail work lands. bd model-gap id.org.ai-67g (+ siblings).    │
 * └────────────────────────────────────────────────────────────────────────────┘
 */

import type { PossessionTier } from './offer'
import type { AllowedValueType } from './value-types'

/** One leg of a settlement intent — a value transfer from one party to the other. */
export interface SettlementLeg {
  valueType: AllowedValueType
  from: 'brand' | 'consumer'
  to: 'brand' | 'consumer'
  /** micro-payment: integer USD micros. */
  amountMicros?: number
  asset?: string
  /** credential-grant: the target VC type. */
  vct?: string
  /** verified-attribute: a digest of the P5-disclosed predicate (NEVER raw PII). */
  attributeDigest?: string
}

/** The dual-leg settlement intent. `nonce` (r) is the idempotency key (r ⊆ e). */
export interface SettlementIntent {
  nonce: string
  epcisEventId: string
  offerId: string
  /** brand→consumer leg (default net direction: value flows TO the discloser). */
  brandLeg: SettlementLeg
  /** consumer→brand leg. */
  consumerLeg: SettlementLeg
  reachedRung: PossessionTier
  /** Opaque rail authorization from the settle-offer body (never the OFFER terms). */
  valueProof?: Record<string, unknown>
}

/** A successful HOLD — the handle the caller passes to commit/void. */
export interface SettlementPrepared {
  handle: string
  intent: SettlementIntent
  expiresAt: number
}

/** A committed settlement — BOTH legs cleared. */
export interface SettlementReceipt {
  ok: true
  txRef: string
  settledAt: number
  legs: SettlementLeg[]
}

/** A typed rejection at any phase. NO money moved. */
export interface SettlementRejected {
  ok: false
  reason: 'not-provisioned' | 'no-instrument' | 'insufficient-funds' | 'declined' | 'expired' | 'rail-unsupported'
  detail: string
}

/**
 * The settlement PORT — the single seam. `prepare` and `commit` may reject;
 * `void` must never throw (a compensating release runs on the failure path).
 * The both-legs-or-neither invariant lives INSIDE the port implementation.
 */
export interface SettlementPort {
  prepare(intent: SettlementIntent): Promise<SettlementPrepared | SettlementRejected>
  commit(prepared: SettlementPrepared): Promise<SettlementReceipt | SettlementRejected>
  void(prepared: SettlementPrepared): Promise<void>
}

/**
 * The PRODUCTION default — FAIL-CLOSED (mirrors emptyRegistryPort). No rail is
 * wired, so prepare always answers `not-provisioned` and no money ever moves.
 * This is what `dlvpRoutes` mounts in production: the money path is inert until
 * an adapter is explicitly injected.
 */
export function noopSettlementPort(detail = 'settlement rail not provisioned'): SettlementPort {
  return {
    async prepare(): Promise<SettlementRejected> {
      return { ok: false, reason: 'not-provisioned', detail }
    },
    async commit(): Promise<SettlementRejected> {
      return { ok: false, reason: 'not-provisioned', detail }
    },
    async void() {
      /* nothing was held */
    },
  }
}

/** Options for the deterministic TEST port. */
export interface MockSettlementOptions {
  /** Force a rejection/throw at a phase, to drive the atomic failure matrix. */
  failAt?: 'prepare' | 'commit'
  /** The reason a forced rejection reports. */
  failReason?: SettlementRejected['reason']
}

/**
 * TEST-ONLY deterministic port. prepare/commit succeed unless `failAt` forces a
 * typed rejection at that phase. Records a call log + a mock txRef; moves NO real
 * money. The verified-attribute leg is inherently a no-op (the attribute is
 * already in the presentation) — recorded only. Both-legs-or-neither: commit
 * returns BOTH leg records or a single rejection, never a partial.
 */
export interface MockSettlementPort extends SettlementPort {
  /** The live call log (same reference — mutated in place as phases run). */
  readonly calls: ReadonlyArray<{ phase: 'prepare' | 'commit' | 'void'; handle?: string }>
  /** How many commits SUCCEEDED (money-moved count). */
  readonly committedCount: number
}

export function mockSettlementPort(opts: MockSettlementOptions = {}): MockSettlementPort {
  const calls: Array<{ phase: 'prepare' | 'commit' | 'void'; handle?: string }> = []
  const counters = { committed: 0 }
  const port: MockSettlementPort = {
    // `calls` is the live array reference; `committedCount` is a live getter.
    calls,
    get committedCount() {
      return counters.committed
    },
    async prepare(intent) {
      calls.push({ phase: 'prepare' })
      if (opts.failAt === 'prepare') {
        return { ok: false, reason: opts.failReason ?? 'declined', detail: 'mock: forced prepare failure' }
      }
      return {
        handle: `hold_${intent.nonce.slice(0, 8)}_${crypto.randomUUID()}`,
        intent,
        expiresAt: Date.now() + 30_000,
      }
    },
    async commit(prepared) {
      calls.push({ phase: 'commit', handle: prepared.handle })
      if (opts.failAt === 'commit') {
        return { ok: false, reason: opts.failReason ?? 'declined', detail: 'mock: forced commit failure' }
      }
      counters.committed++
      return {
        ok: true,
        txRef: `mocktx_${prepared.handle}`,
        settledAt: Date.now(),
        legs: [prepared.intent.brandLeg, prepared.intent.consumerLeg],
      }
    },
    async void(prepared) {
      calls.push({ phase: 'void', handle: prepared.handle })
    },
  }
  return port
}

/**
 * The REAL adapter SHAPE — declared, wired to NOTHING. The constructor takes NO
 * secrets and NO binding; every phase returns/short-circuits `not-provisioned`
 * until the deferred payments.do value-rail wiring lands. This exists so the
 * interface the live adapter must satisfy is committed now, money-safely.
 *
 * DEFERRED + TICKETED: live value-rail wiring (payments.do / x402·MPP), 2-phase
 * escrow over a real rail, durable cross-isolate idempotency on `nonce`.
 * bd model-gap id.org.ai-67g.
 */
export class LiveValueRailSettlement implements SettlementPort {
  private readonly detail = 'live value rail not provisioned (id.org.ai-67g) — no keys, no binding wired'
  // Intentionally NO constructor params: no secrets, no keys, no binding.

  async prepare(): Promise<SettlementRejected> {
    return { ok: false, reason: 'not-provisioned', detail: this.detail }
  }
  async commit(): Promise<SettlementRejected> {
    return { ok: false, reason: 'not-provisioned', detail: this.detail }
  }
  async void(): Promise<void> {
    /* nothing was held — no rail wired */
  }
}
