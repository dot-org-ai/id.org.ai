/**
 * dlvp/store.ts — the v1 in-memory receipt + Token-Status-List store.
 *
 * A minted consent receipt occupies one bit in a Token Status List; revocation
 * flips the bit. v1 serves this IN-MEMORY (per-isolate), injectable so tests get
 * a fresh instance and production shares one module singleton.
 *
 * DEFERRED + TICKETED (bd model-gap id.org.ai-56v): the PERSISTENT Token-Status-
 * List store + durable revocation + the receipt GRAI registry write — need a provisioned
 * binding (RAILS forbids one this increment). v1 revocation is session-scoped:
 * it flips an in-memory bit and stamps a BizStep-revoking event; a restart clears
 * it. The GDPR "erasure = revoke transition" semantics are honored in-shape.
 */

import type { MutualDisclosureReceipt, StatusListRef } from './protocol'

export const STATUS_LIST_URI = 'https://id.org.ai/dlvp/status/1'

interface StatusEntry {
  idx: number
  revoked: boolean
  revokedAt?: string
}

/** The DLVP store: receipts by GRAI + their status-list bits. */
export class DlvpStore {
  private receipts = new Map<string, MutualDisclosureReceipt>()
  private status = new Map<string, StatusEntry>()
  private nextIdx = 0
  // Single-use resolution nonces (replay guard) + per-receipt revocation capability.
  // v1 in-memory/per-isolate; the durable cross-isolate store is deferred (id.org.ai-56v):
  // production replay-defense + revocation authority need the same provisioned binding.
  private spentNonces = new Set<string>()
  private revTokens = new Map<string, string>()

  /** True once a resolution nonce has been settled — a co-presentation is single-use. */
  isNonceSpent(nonce: string): boolean {
    return this.spentNonces.has(nonce)
  }

  /** Burn a resolution nonce so a captured co-presentation cannot be replayed. */
  spendNonce(nonce: string): void {
    this.spentNonces.add(nonce)
  }

  /** Bind a revocation capability token to a receipt (returned to the parties at settle). */
  setRevocationToken(grai: string, token: string): void {
    this.revTokens.set(grai, token)
  }

  /**
   * Constant-time-ish check that the caller holds the receipt's revocation capability.
   * A receipt with no bound token (legacy/none) is NOT revocable by anyone.
   */
  checkRevocationToken(grai: string, token: string | undefined | null): boolean {
    const expected = this.revTokens.get(grai)
    if (!expected || !token || token.length !== expected.length) return false
    let diff = 0
    for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ token.charCodeAt(i)
    return diff === 0
  }

  /** Reserve the next status-list bit index for a new receipt. */
  reserveStatus(grai: string): StatusListRef {
    const idx = this.nextIdx++
    this.status.set(grai, { idx, revoked: false })
    return { uri: STATUS_LIST_URI, idx, status: 'valid' }
  }

  /** Persist (in-memory) a minted receipt. */
  put(receipt: MutualDisclosureReceipt): void {
    this.receipts.set(receipt.grai, receipt)
  }

  /** Fetch a receipt by GRAI. */
  get(grai: string): MutualDisclosureReceipt | undefined {
    const receipt = this.receipts.get(grai)
    if (!receipt) return undefined
    // Reflect current status onto the returned view.
    const st = this.status.get(grai)
    if (st) receipt.status = { ...receipt.status, status: st.revoked ? 'revoked' : 'valid' }
    return receipt
  }

  /** Number of receipts persisted (test-facing; atomic-or-nothing assertions). */
  size(): number {
    return this.receipts.size
  }

  /** Current status of a receipt's grant. */
  statusOf(grai: string): 'valid' | 'revoked' | 'unknown' {
    const st = this.status.get(grai)
    if (!st) return 'unknown'
    return st.revoked ? 'revoked' : 'valid'
  }

  /**
   * Flip the status-list bit → revoked. Returns false if the GRAI is unknown.
   * Idempotent: re-revoking a revoked grant returns true (already revoked).
   */
  revoke(grai: string, at = new Date().toISOString()): boolean {
    const st = this.status.get(grai)
    if (!st) return false
    st.revoked = true
    st.revokedAt = at
    const receipt = this.receipts.get(grai)
    if (receipt) receipt.status = { ...receipt.status, status: 'revoked' }
    return true
  }
}

/** The production module singleton (per-isolate, in-memory — deferred: persistence). */
export const dlvpStore = new DlvpStore()
