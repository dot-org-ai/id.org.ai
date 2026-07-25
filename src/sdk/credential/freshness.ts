/**
 * Freshness by effect-class — org.ai ADR 0016 C5, instantiated by ADR 0018 R5.
 *
 * A reserved ACT demands a fresh registry check at the act — no cached
 * attestation (the lapsed dealer is stopped at the lane exactly as the
 * suspended attorney at file.patent). READ and RECORD may cache with a
 * per-class TTL, disclosed on the wire as `freshness.maxAgeSeconds`.
 *
 * "Fresh" is bounded by what the registry itself publishes: per-query
 * sources support a genuine at-the-act check; file-published sources (AZ's
 * twice-weekly Excel) support only fresh-against-latest-file — staleness
 * beyond the registry's own cadence is a TYPED failure, never a silent pass.
 *
 * The TTL values are the ADR 0016 C5 policy knob — held in this one ratified
 * table, versioned, deep-frozen, never edited (a change is a new version).
 */

import type { EffectClass, RegistryCadence } from './types'
import { deepFreeze } from './types'

export interface EffectClassFreshnessRow {
  readonly effectClass: EffectClass
  /** Act rows demand an uncached answer; a cached answer is a typed failure. */
  readonly mustBeUncached: boolean
  /** TTL disclosed on the wire. 0 for act (no cache is acceptable at all). */
  readonly maxAgeSeconds: number
}

export interface EffectClassFreshnessTable {
  readonly version: 1
  readonly owner: 'platform-counsel'
  readonly rows: Readonly<Record<EffectClass, EffectClassFreshnessRow>>
}

export const EFFECT_CLASS_FRESHNESS_V1: EffectClassFreshnessTable = deepFreeze({
  version: 1 as const,
  owner: 'platform-counsel' as const,
  rows: {
    act: { effectClass: 'act' as const, mustBeUncached: true, maxAgeSeconds: 0 },
    record: { effectClass: 'record' as const, mustBeUncached: false, maxAgeSeconds: 86_400 },
    read: { effectClass: 'read' as const, mustBeUncached: false, maxAgeSeconds: 604_800 },
  },
})

/** The ratified freshness row for an effect class. */
export function freshnessPolicyFor(effectClass: EffectClass): EffectClassFreshnessRow {
  return EFFECT_CLASS_FRESHNESS_V1.rows[effectClass]
}

/**
 * The widest age (seconds) at which an answer can still be
 * fresh-against-latest-publication for a given registry cadence. `null`
 * means the cadence imposes no checkable bound:
 *   - per-query: the answer IS the act-time check — its asOf is the check time.
 *   - unknown: no cadence is published, so no cadence bound can be typed;
 *     the verdict tier (not this bound) carries the evidentiary weakness.
 */
export function cadenceMaxAgeSeconds(cadence: RegistryCadence): number | null {
  switch (cadence.kind) {
    case 'per-query':
      // A per-query answer older than an hour was necessarily cached upstream.
      return 3_600
    case 'daily':
      // One missed publication day of slack on top of the daily file.
      return 2 * 86_400
    case 'twice-weekly':
      // Tue/Thu publication: the longest lawful gap (Thu → next Tue) + slack.
      return 5 * 86_400
    case 'unknown':
      return null
  }
}

/**
 * Is `asOf` stale beyond the registry's own publication cadence at `now`?
 * An unparseable `asOf` is stale (fail closed) — an answer whose age cannot
 * be established cannot certify freshness.
 */
export function staleBeyondCadence(asOf: string, cadence: RegistryCadence, now: Date): boolean {
  const bound = cadenceMaxAgeSeconds(cadence)
  if (bound === null) return false
  const asOfMs = Date.parse(asOf)
  if (Number.isNaN(asOfMs)) return true
  const ageSeconds = (now.getTime() - asOfMs) / 1000
  return ageSeconds > bound
}
