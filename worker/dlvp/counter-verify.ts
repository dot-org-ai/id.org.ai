/**
 * dlvp/counter-verify.ts — the C3 DUAL-VERIFIER counter-join (SYNTHESIS C3,
 * lens-B bold-claim 5).
 *
 * id.org.ai is simultaneously the VC verifier (sd-jwt.ts already checked the
 * issuer signature + KB binding) AND the registry of record. This module runs
 * the SECOND leg IN THE SAME ROUND: it counter-checks the consumer VC's asserted
 * ownership against the identifier RegistryPort. When the presented owner matches
 * the registry's owner for the resolved key, it mints the strictly-stronger
 *   `holder-presented-vc-counterverified`
 * verdict — a claim no wallet, issuer, OR registry can produce alone.
 *
 * This does NOT call src/sdk/credential/verify() — that function is the
 * registry-of-record verifier for LICENSES over the SourcePort, which has no
 * identifier RegistryPort. The counter-join is a pure DATA join (no crypto
 * material) reusing the Phase-4 scope matchers verifyInstanceClaim /
 * verifyRangeClaim from worker/registry/ownership.ts.
 *
 * ┌─ C5 possession-confidence ladder (SYNTHESIS C5) ──────────────────────────┐
 * │ v1 records the presented predicate TIER (registry/purchase binding, rung 3)│
 * │ — it does NOT compute the compounding longitudinal posterior, and it does  │
 * │ NOT reach rung 4 (cryptographic-presence) or rung 5 (signed ownership      │
 * │ chain): those need the deferred secure-element / transfer-credential verify.│
 * │ Declared scope narrowing — bd model-gap id.org.ai-67g (+ registry graded    │
 * │ confidence id.org.ai-x3u).                                                   │
 * └────────────────────────────────────────────────────────────────────────────┘
 */

import type { RegistryPort, Grain, ClaimScope } from '../registry/port'
import { verifyInstanceClaim, verifyRangeClaim, gtin14 } from '../registry/ownership'
import type { SdJwtVerified } from './sd-jwt'
import type { DlvpVerdict } from './protocol'

/** The v1 possession-confidence rung reached (SYNTHESIS C5; v1 caps at 3). */
export type PossessionRung = 1 | 2 | 3

export interface DlvpCounterVerifyResult {
  verdict: DlvpVerdict
  /** The registry owner id when a counter-match was found. */
  owner?: string
  /** The registry claim's strength tier when matched. */
  registryStrength?: string
  /** The possession-confidence rung reached (v1: ≤ 3). */
  rung: PossessionRung
  /** Human-readable account of the join outcome (honest, never fabricated). */
  note: string
}

/** The ownership assertion pulled out of the consumer VC's disclosed claims. */
export interface OwnershipAssertion {
  /** The owner id the VC asserts (org_/human_/agent_). */
  subject?: string
  /** The scope the VC asserts it owns. */
  scope?: ClaimScope
}

/**
 * Extract the ownership assertion from disclosed claims. Convention (v1):
 *   - `owner_subject`: the asserted owner id.
 *   - `owns`: the instance key string (→ instance scope), OR
 *   - `gcp` / `gcpPrefix`: the asserted GCP prefix (→ range scope).
 * Absent/other shapes yield an empty assertion (→ holder-attested).
 */
export function extractOwnershipAssertion(claims: Record<string, unknown>): OwnershipAssertion {
  const subject = typeof claims.owner_subject === 'string' ? claims.owner_subject : undefined
  let scope: ClaimScope | undefined
  if (typeof claims.owns === 'string') {
    scope = { kind: 'instance', key: claims.owns }
  } else if (typeof claims.gcp === 'string' || typeof claims.gcpPrefix === 'string') {
    scope = { kind: 'range', gcpPrefix: (claims.gcp ?? claims.gcpPrefix) as string }
  }
  return { subject, scope }
}

/** Parse the GTIN out of a DL key like `01/{gtin}` or `01/{gtin}/21/{serial}`. */
function gtinOf(key: string): string | null {
  const segs = key.split('/')
  if (segs[0] === '01' && segs[1]) return segs[1]
  return null
}

/**
 * Run the counter-join for a verified consumer presentation against the registry.
 * Fail-open to `holder-attested` (never fabricates a counter-match): a valid VC
 * with no corroborating registry record is honestly self-attested.
 */
export async function counterVerify(params: {
  presentation: SdJwtVerified
  identifier: string
  grain: Grain
  registry: RegistryPort
}): Promise<DlvpCounterVerifyResult> {
  const assertion = extractOwnershipAssertion(params.presentation.claims)
  const lookup = await params.registry.lookup(params.identifier, params.grain)

  if (!lookup.found) {
    return {
      verdict: 'holder-attested',
      rung: assertion.scope ? 3 : 1,
      note:
        lookup.reason === 'not-provisioned'
          ? 'registry not provisioned — VC verified but not registry-counter-checked (holder-attested)'
          : 'no registry record for this key — VC is self-attested (holder-attested)',
    }
  }

  const manifest = lookup.manifest
  const registryOwner = manifest.owner.ownerId
  const registryClaim = manifest.owner.claim

  // The registry claim must actually cover THIS key (integrity of the record).
  let registryCoversKey = false
  if (registryClaim.scope.kind === 'instance') {
    registryCoversKey = verifyInstanceClaim(params.identifier, registryClaim)
  } else if (registryClaim.scope.kind === 'range') {
    const gtin = gtinOf(params.identifier)
    registryCoversKey = gtin ? verifyRangeClaim(gtin, registryClaim) : false
  } else if (registryClaim.scope.kind === 'hostname') {
    registryCoversKey = true // hostname-scoped brand owner
  }

  // The presented owner must equal the registry owner for a counter-match.
  const subjectMatches =
    assertion.subject !== undefined && assertion.subject === registryOwner

  // When the VC also asserts a scope, it must be consistent with the registry's.
  const scopeConsistent = assertionScopeConsistent(assertion.scope, registryClaim.scope, params.identifier)

  if (registryCoversKey && subjectMatches && scopeConsistent) {
    return {
      verdict: 'holder-presented-vc-counterverified',
      owner: registryOwner,
      registryStrength: registryClaim.strength,
      rung: 3,
      note: `VC subject ${assertion.subject} counter-verified against registry owner of ${params.identifier} (registry strength: ${registryClaim.strength})`,
    }
  }

  return {
    verdict: 'holder-attested',
    owner: registryOwner,
    registryStrength: registryClaim.strength,
    rung: assertion.scope ? 3 : 1,
    note: subjectMatches
      ? 'VC subject matches but the asserted scope is not consistent with the registry claim (holder-attested)'
      : `VC subject ${assertion.subject ?? '(none)'} does not match registry owner ${registryOwner} (holder-attested)`,
  }
}

/**
 * The VC's asserted scope must be consistent with the registry claim's scope for
 * the resolved key: an instance VC key must equal the resolved key; a range VC
 * prefix must contain the resolved GTIN. An absent VC scope is permissive (the
 * subject-match alone still counter-verifies who, not what-scope).
 */
function assertionScopeConsistent(
  vcScope: ClaimScope | undefined,
  registryScope: ClaimScope,
  identifier: string,
): boolean {
  if (!vcScope) return true
  if (vcScope.kind === 'instance') return vcScope.key === identifier
  if (vcScope.kind === 'range') {
    const gtin = gtinOf(identifier)
    if (!gtin) return false
    return gtin14(gtin).slice(1).startsWith(vcScope.gcpPrefix)
  }
  if (vcScope.kind === 'hostname') return registryScope.kind === 'hostname'
  return false
}
