/**
 * verify(credential, principal) — the ADR 0016 C5 verification entrypoint
 * (beads id-hww), extended with the ADR 0018 verdict tier.
 *
 * Invariants:
 *   - `live` and `goodStanding` are NEVER collapsed into one boolean.
 *   - This layer never mints: issuers home credentials; the registry (or the
 *     holder's own export) is the only thing that can answer.
 *   - `reps` are the registry's own worker-ID enumeration — derived, never a
 *     stored field.
 *   - Failure is typed: an unverifiable answer is fail-closed
 *     (live=false, goodStanding=false) AND carries the verdict + cure the
 *     caller must surface. A cached or cadence-stale answer on an act-class
 *     check is a typed `freshnessFailure`, never a silent pass.
 *   - `holder-attested` NEVER satisfies an act-class predicate
 *     (`satisfiesActClass` is false for that tier, always).
 */

import { Ok, Err } from '../foundation'
import type { Result } from '../foundation'
import { ValidationError } from '../foundation'
import type {
  EffectClass,
  HolderPortalExport,
  PresentedCredential,
  VerificationResult,
  VerifyPrincipal,
} from './types'
import { isEffectClass } from './types'
import { freshnessPolicyFor, staleBeyondCadence } from './freshness'
import type { RegistryAdapter, SourcePort } from './sources'
import { REGISTRY_ADAPTERS, registryForCredentialType } from './sources'

export interface VerifyOptions {
  readonly effectClass: EffectClass
  readonly port: SourcePort
  readonly now?: Date
  /** Adapter override, for tests. Defaults to REGISTRY_ADAPTERS. */
  readonly adapters?: Readonly<Record<string, RegistryAdapter>>
  /** Holder-supplied portal export for the holder-attested interim tier. */
  readonly holderAttested?: HolderPortalExport
}

export async function verify(
  credential: PresentedCredential,
  principal: VerifyPrincipal,
  options: VerifyOptions,
): Promise<Result<VerificationResult, ValidationError>> {
  // ── Request validation (typed 400s at the route) ────────────────────────
  if (!credential || typeof credential.type !== 'string' || !credential.type.trim()) {
    return Err(new ValidationError('credential.type', 'credential.type is required'))
  }
  if (!principal || typeof principal.id !== 'string' || !principal.id.trim()) {
    return Err(new ValidationError('principal.id', 'principal.id is required'))
  }
  if (!isEffectClass(options.effectClass)) {
    return Err(new ValidationError('effectClass', `effectClass must be one of act|record|read, got '${String(options.effectClass)}'`))
  }

  const registryId = registryForCredentialType(credential.type)
  if (!registryId) {
    return Err(new ValidationError('credential.type', `unknown credential type '${credential.type}' — no registry of record is ratified for it`))
  }
  const adapters = options.adapters ?? REGISTRY_ADAPTERS
  const adapter = adapters[registryId]
  if (!adapter) {
    return Err(new ValidationError('credential.type', `no adapter registered for registry '${registryId}'`))
  }

  const now = options.now ?? new Date()
  const effectClass = options.effectClass
  const policy = freshnessPolicyFor(effectClass)
  const checkedAt = now.toISOString()

  const answer = await adapter.lookup(
    { credential, principal, ...(options.holderAttested ? { holderAttested: options.holderAttested } : {}) },
    { port: options.port, now, effectClass },
  )

  const source = {
    mode: adapter.mode,
    registry: adapter.id,
    sourceClass: adapter.sourceClass,
    status: adapter.status,
  } as const

  // ── Typed unverifiability: fail closed, surface the cure ────────────────
  if (answer.verdict === 'unverifiable-by-registry') {
    return Ok({
      live: false,
      goodStanding: false,
      holder: null,
      reps: [],
      source,
      freshness: {
        cached: false,
        ...(policy.mustBeUncached ? {} : { maxAgeSeconds: policy.maxAgeSeconds }),
        cadence: adapter.cadence,
        staleBeyondCadence: false,
      },
      checkedAt,
      verdict: answer.verdict,
      registryStatus: answer.reason,
      satisfiesActClass: false,
      cure: answer.cure,
    })
  }

  // ── A finding (registry-verified or holder-attested) ────────────────────
  const stale = staleBeyondCadence(answer.asOf, adapter.cadence, now)
  const freshnessFailure =
    effectClass === 'act' && answer.fromCache ? ('cached-for-act' as const) : stale ? ('stale-beyond-cadence' as const) : undefined

  const satisfiesActClass = answer.verdict === 'registry-verified' && !answer.fromCache && !stale

  return Ok({
    live: answer.live,
    goodStanding: answer.goodStanding,
    holder: answer.holder,
    reps: answer.reps,
    source,
    freshness: {
      cached: answer.fromCache,
      ...(policy.mustBeUncached ? {} : { maxAgeSeconds: policy.maxAgeSeconds }),
      asOf: answer.asOf,
      cadence: adapter.cadence,
      staleBeyondCadence: stale,
    },
    checkedAt,
    verdict: answer.verdict,
    registryStatus: answer.registryStatus,
    satisfiesActClass,
    ...(freshnessFailure ? { freshnessFailure } : {}),
  })
}
