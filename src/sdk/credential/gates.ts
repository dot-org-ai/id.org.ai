/**
 * Ordered credential-gate enforcement — the pinned spec's group C behavior
 * (ADR 0012 M8 → ADR 0016 C3): humanSigner FIRST, then the requiresSigner
 * supply gate, then the requiresAccess demand gate. Every denial names its
 * gate and echoes the required gate as an OBJECT carrying a jurisdiction —
 * a gate is a reference, never a bool.
 *
 * This module is the pure decision core the /credentials/enforce route
 * drives. The full AuthBroker integration (beads id-bbi + id-p89) extends
 * `AuthRequirement` separately; this core is deliberately broker-free so the
 * ordering discipline is testable without I/O.
 */

import type { RegistryCure, VerificationResult, VerifyPrincipal } from './types'
import { deepFreeze } from './types'

// ── The gates table (versioned, frozen) ────────────────────────────────────

export interface SupplyGate {
  readonly act: string
  readonly requiresSigner: {
    readonly jurisdiction: string
    readonly credentialType: string
    readonly registry: string
  }
}

export interface DemandGate {
  readonly upstream: string
  readonly requiresAccess: {
    readonly jurisdiction: string
    readonly entitlementType: string
  }
}

export interface CredentialGatesTable {
  readonly version: 1
  readonly acts: Readonly<Record<string, SupplyGate>>
  readonly upstreams: Readonly<Record<string, DemandGate>>
}

export const CREDENTIAL_GATES_V1: CredentialGatesTable = deepFreeze({
  version: 1 as const,
  acts: {
    'file.patent': {
      act: 'file.patent',
      requiresSigner: { jurisdiction: 'US', credentialType: 'uspto-registered', registry: 'uspto-oed' },
    },
  },
  upstreams: {
    'cm-ecf': {
      upstream: 'cm-ecf',
      requiresAccess: { jurisdiction: 'US', entitlementType: 'cm-ecf-access' },
    },
  },
})

export function supplyGateFor(act: string): SupplyGate | null {
  return CREDENTIAL_GATES_V1.acts[act] ?? null
}

export function demandGateFor(upstream: string): DemandGate | null {
  return CREDENTIAL_GATES_V1.upstreams[upstream] ?? null
}

// ── Ordered enforcement ────────────────────────────────────────────────────

export interface EnforceInput {
  readonly act?: string
  readonly upstream?: string
  readonly signer?: VerifyPrincipal
  readonly principal?: VerifyPrincipal
  /**
   * The caller-resolved verification evidence for the signer's credential
   * under the act's supply gate (null/absent = no evidence). The evidence
   * must be `satisfiesActClass` to pass — a `holder-attested` result NEVER
   * clears the supply gate (ADR 0018 R4).
   */
  readonly signerVerification?: VerificationResult | null
  /** Does the principal hold the upstream's entitlement? (caller-resolved) */
  readonly principalEntitled?: boolean
}

export type EnforceDecision =
  | { readonly denied: false; readonly gates: readonly string[] }
  | {
      readonly denied: true
      readonly gate: 'humanSigner' | 'requiresSigner' | 'requiresAccess'
      readonly required?: Readonly<Record<string, unknown>> & { readonly jurisdiction: string }
      readonly reason: string
      readonly cure?: RegistryCure
    }

/**
 * Walk the gates in ratified order. FIRST denial wins:
 *   1. humanSigner  — an agent signer is stopped before any credential math.
 *   2. requiresSigner — the supply gate: fresh registry-verified evidence.
 *   3. requiresAccess — the demand gate: the principal's entitlement.
 */
export function enforceOrdered(input: EnforceInput): EnforceDecision {
  const passed: string[] = []

  if (input.act) {
    const gate = supplyGateFor(input.act)
    if (!gate) {
      // An unratified act cannot be lawfully signed by anyone — typed denial
      // at the supply gate with no jurisdiction to echo.
      return { denied: true, gate: 'requiresSigner', reason: `no ratified supply gate for act '${input.act}'` }
    }

    // 1 — humanSigner (ADR 0012 M8): runs FIRST, before any credential check.
    if (!input.signer || input.signer.workerType !== 'human') {
      return {
        denied: true,
        gate: 'humanSigner',
        reason: 'a reserved act demands a human signer — an agent may prepare, never sign',
      }
    }
    passed.push('humanSigner')

    // 2 — requiresSigner (ADR 0016 C3 supply gate).
    const evidence = input.signerVerification
    const clears =
      !!evidence && evidence.satisfiesActClass && evidence.live && evidence.goodStanding
    if (!clears) {
      return {
        denied: true,
        gate: 'requiresSigner',
        required: gate.requiresSigner,
        reason: evidence
          ? evidence.verdict === 'holder-attested'
            ? 'holder-attested evidence never satisfies an act-class predicate'
            : evidence.freshnessFailure
              ? `signer credential evidence failed freshness: ${evidence.freshnessFailure}`
              : 'signer credential is not live and in good standing at the registry'
          : 'signer holds no verifiable credential for this act',
        ...(evidence?.cure ? { cure: evidence.cure } : {}),
      }
    }
    passed.push('requiresSigner')
  }

  if (input.upstream) {
    const gate = demandGateFor(input.upstream)
    if (!gate) {
      return { denied: true, gate: 'requiresAccess', reason: `no ratified demand gate for upstream '${input.upstream}'` }
    }

    // 3 — requiresAccess (ADR 0016 C3 demand gate).
    if (!input.principal || !input.principalEntitled) {
      return {
        denied: true,
        gate: 'requiresAccess',
        required: gate.requiresAccess,
        reason: 'principal holds no entitlement for this upstream',
      }
    }
    passed.push('requiresAccess')
  }

  return { denied: false, gates: passed }
}
