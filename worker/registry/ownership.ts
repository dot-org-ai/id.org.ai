/**
 * registry/ownership.ts — the four-methods-to-one ownership reducer (lens-A §2).
 * PURE: no I/O.
 *
 * The registry accepts a claim when it carries ANY ONE of four proofs, ranked by
 * strength, all reduced to one `OwnershipClaim` with a proof digest:
 *   1. GCP-VC   — a GS1 Company Prefix verifiable credential ASSERTS the licensed
 *                 prefix; matching it grants write-scope over the ENTIRE GTIN range
 *                 under that prefix in one act (range-scoped ownership).
 *   2. DNS      — control of `brand.example` via a TXT record binds a hostname.
 *   3. VC       — any issuer the ID-JAG trust list vouches for (long tail: VIN, ISBN…).
 *   4. anchor   — an on-chain anchor for adversarially-durable provenance.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * CRITICAL HONEST-GRADE FINDING (corrects lens-A §2 claim 2):
 *
 * lens-A asserts barcoding.dev "already pins the GS1 Company Prefix split table
 * (P0-15)" so GTIN `09506000134352` decomposes to GCP `0950600`. THIS IS FALSE.
 * In barcoding.dev, "P0-15" is the ruled OUTPUT-CONTRACT gate, not a GCP prefix
 * table. `engine/src/core/epc.js` REFUSES to derive GCP length ("company-prefix
 * length required… a licensed allocation fact; pass gcpLength") and the scheme
 * JSON carries only PROSE notes ("split from the pinned prefix table (P0-15)")
 * with NO table data anywhere.
 *
 * THEREFORE the range proof MUST NOT derive GCP from a bare GTIN. Instead: the
 * GCP-VC ASSERTS the licensed prefix, and we verify by PREFIX-CONTAINMENT on the
 * GTIN-14 digits (strip the leading indicator/pad) — no table needed. The
 * nonexistent derive-side prefix-length table is a declared, ticketed gap
 * (bd model-gap): a real table is required ONLY if we ever derive GCP from a
 * bare GTIN with no VC. Do not claim it exists.
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * DEFERRED + TICKETED (bd model-gap): FULL 4-METHOD CRYPTOGRAPHIC VERIFICATION.
 * v1 reduces the four methods to one shape and matches SCOPE (range
 * prefix-containment / instance key match). The cryptographic checks — GCP-VC
 * signature verify against the GS1/bridge issuer JWKS, DNS TXT fetch, non-GS1 VC
 * verify against the ID-JAG trust list, on-chain anchor read — are deferred;
 * `proofDigest` is trusted as-supplied in v1.
 */

import type { OwnershipClaim, ClaimScope, ProofMethod } from './port'

export type { OwnershipClaim, ClaimScope, ProofMethod }

/** The verdict-tier strength each proof method mints, weakest → strongest. */
const STRENGTH_BY_METHOD: Record<ProofMethod, OwnershipClaim['strength']> = {
  dns: 'hostname',
  'gcp-vc': 'range',
  vc: 'attested',
  anchor: 'anchored',
}

/**
 * Reduce a raw proof (whichever of the four methods produced it) to the one
 * unified `OwnershipClaim` shape. This is the "four methods → one claim" move:
 * callers hand the method + subject + scope + a pre-computed proof digest, and
 * the reducer stamps the strength tier and the proved-at time.
 *
 * v1 does NOT verify the proof cryptographically (deferred + ticketed) — it
 * normalises the SHAPE so downstream scope-matching (`verifyRangeClaim` /
 * `verifyInstanceClaim`) can gate on it.
 */
export function reduceToClaim(input: {
  method: ProofMethod
  subject: string
  scope: ClaimScope
  proofDigest: string
  provedAt?: string
}): OwnershipClaim {
  return {
    method: input.method,
    subject: input.subject,
    scope: input.scope,
    proofDigest: input.proofDigest,
    provedAt: input.provedAt ?? new Date().toISOString(),
    strength: STRENGTH_BY_METHOD[input.method],
  }
}

/**
 * Normalise a GTIN to its 14-digit form by left-padding with zeros. GTIN-8/12/13
 * are the same value as a GTIN-14 with leading zeros; prefix-containment is only
 * meaningful against a canonical width.
 */
export function gtin14(gtin: string): string {
  return gtin.padStart(14, '0')
}

/**
 * RANGE proof — NO table lookup (see the header finding). The GCP-VC ASSERTS the
 * licensed prefix in `claim.scope.gcpPrefix`; we verify the GTIN falls under it
 * by prefix-containment on the GTIN-14 digits AFTER the leading indicator digit.
 *
 * GTIN-14 layout: [indicator][GCP + item ref (12)][check]. The GCP sits after
 * the indicator digit, so we test the prefix against the GTIN-14 with its first
 * (indicator) digit stripped. For a padded GTIN-13/12 the indicator region is a
 * leading zero, which strips cleanly.
 *
 * Returns true iff the claim is a range claim whose asserted prefix contains the
 * GTIN. Never derives the prefix from the GTIN.
 */
export function verifyRangeClaim(gtin: string, claim: OwnershipClaim): boolean {
  if (claim.scope.kind !== 'range') return false
  const prefix = claim.scope.gcpPrefix
  if (!/^[0-9]+$/.test(prefix) || prefix.length === 0) return false
  if (!/^[0-9]+$/.test(gtin)) return false
  // Strip the leading indicator digit from the canonical GTIN-14 before matching
  // the asserted GCP (which is indexed from the start of the company-prefix field).
  const afterIndicator = gtin14(gtin).slice(1)
  return afterIndicator.startsWith(prefix)
}

/**
 * INSTANCE proof — the claim-by-commit ceremony (src/sdk/claim) mints a transfer
 * credential binding `owns(subject, key)`. v1 matches the SCOPE: the claim must
 * be an instance claim whose `scope.key` equals the resolved key. The
 * cryptographic verify of the transfer credential is deferred (reuses the
 * existing claim-token verify path when wired).
 */
export function verifyInstanceClaim(key: string, claim: OwnershipClaim): boolean {
  return claim.scope.kind === 'instance' && claim.scope.key === key
}
