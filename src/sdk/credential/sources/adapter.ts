/**
 * Registry adapter contract — the shape every source in this directory
 * implements (design §4 of law docs/design/2026-07-25-three-part-process-check.md).
 *
 * Discipline (ADR 0018 R4):
 *   - A REAL adapter maps the source's documented answer into a
 *     `RegistryFinding`, preserving the registry's status VERBATIM.
 *   - An HONEST STUB returns `unverifiable-by-registry` with the cure being
 *     the access application itself. It never calls the port for a finding
 *     and never fake-passes — even if handed a live-looking payload.
 *   - Staleness and unreachability are typed failures, never silent passes.
 */

import type {
  AdapterStatus,
  EffectClass,
  HolderPortalExport,
  PresentedCredential,
  RegistryAnswer,
  RegistryCadence,
  RegistryCure,
  SourceClass,
  SourceMode,
  VerifyPrincipal,
} from '../types'
import type { SourcePort, SourceResult } from './port'

export interface RegistryQuery {
  readonly credential: PresentedCredential
  readonly principal?: VerifyPrincipal
  /** Holder-supplied portal export — only the holder-pull adapter reads this. */
  readonly holderAttested?: HolderPortalExport
}

export interface AdapterContext {
  readonly port: SourcePort
  readonly now: Date
  readonly effectClass: EffectClass
}

export interface RegistryDescriptor {
  readonly id: string
  readonly mode: SourceMode
  readonly issuer: string
  readonly sourceClass: SourceClass
  readonly status: AdapterStatus
  readonly cadence: RegistryCadence
  readonly ingested?: boolean
  readonly practitionerCount?: number
  readonly refreshedAt?: string
  readonly note?: string
}

export interface RegistryAdapter {
  readonly id: string
  readonly issuer: string
  readonly mode: SourceMode
  readonly sourceClass: SourceClass
  readonly cadence: RegistryCadence
  readonly status: AdapterStatus
  lookup(query: RegistryQuery, ctx: AdapterContext): Promise<RegistryAnswer>
  /** Optional registry descriptor (roster stats, ingest state) for /credentials/registries/:id. */
  describe?(ctx: AdapterContext): Promise<RegistryDescriptor>
}

// ── Shared helpers ─────────────────────────────────────────────────────────

/** The cache-discipline the effect class demands of the port (ADR 0018 R5). */
export function portFreshness(effectClass: EffectClass): 'bypass-cache' | 'allow-cache' {
  return effectClass === 'act' ? 'bypass-cache' : 'allow-cache'
}

/** Typed unavailability → typed verdict with a connect-source cure. */
export function unavailableAnswer(adapterId: string, result: Extract<SourceResult, { ok: false }>): RegistryAnswer {
  return {
    verdict: 'unverifiable-by-registry',
    reason: `source ${result.unavailable}: ${result.detail}`,
    cure: {
      action: 'connect-source',
      channel: adapterId,
      note: `Bind the src.do source '${adapterId}' — verification cannot proceed without it`,
    },
  }
}

/** A hard-typed stub answer: no sanctioned channel, cure = the application itself. */
export function stubAnswer(reason: string, cure: RegistryCure): RegistryAnswer {
  return { verdict: 'unverifiable-by-registry', reason, cure }
}

/**
 * Map a verbatim registry status into the two never-collapsed booleans using
 * per-registry semantics. Unknown statuses fail closed (false/false) while
 * still carrying the verbatim string.
 */
export function mapStatus(
  status: string,
  semantics: Readonly<Record<string, { live: boolean; goodStanding: boolean }>>,
): { live: boolean; goodStanding: boolean; registryStatus: string } {
  const mapped = semantics[status]
  if (mapped) return { ...mapped, registryStatus: status }
  return { live: false, goodStanding: false, registryStatus: status }
}
