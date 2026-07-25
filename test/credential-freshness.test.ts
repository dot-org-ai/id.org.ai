/**
 * Effect-class freshness table (id-nqq) + registry-cadence staleness math
 * (ADR 0016 C5 / ADR 0018 R5).
 */

import { describe, it, expect } from 'vitest'
import {
  EFFECT_CLASS_FRESHNESS_V1,
  freshnessPolicyFor,
  cadenceMaxAgeSeconds,
  staleBeyondCadence,
} from '../src/sdk/credential'

const NOW = new Date('2026-07-25T12:00:00Z')

function agoIso(seconds: number): string {
  return new Date(NOW.getTime() - seconds * 1000).toISOString()
}

describe('EFFECT_CLASS_FRESHNESS_V1 — the ratified policy table', () => {
  it('is version 1 and owned by platform-counsel', () => {
    expect(EFFECT_CLASS_FRESHNESS_V1.version).toBe(1)
    expect(EFFECT_CLASS_FRESHNESS_V1.owner).toBe('platform-counsel')
  })

  it('demands an uncached answer for act, with no TTL at all', () => {
    expect(freshnessPolicyFor('act')).toEqual({ effectClass: 'act', mustBeUncached: true, maxAgeSeconds: 0 })
  })

  it('permits cached answers with disclosed TTLs for record and read', () => {
    expect(freshnessPolicyFor('record')).toEqual({ effectClass: 'record', mustBeUncached: false, maxAgeSeconds: 86_400 })
    expect(freshnessPolicyFor('read')).toEqual({ effectClass: 'read', mustBeUncached: false, maxAgeSeconds: 604_800 })
  })

  it('is deep-frozen — mutation attempts throw', () => {
    expect(() => {
      ;(EFFECT_CLASS_FRESHNESS_V1.rows.act as { maxAgeSeconds: number }).maxAgeSeconds = 999
    }).toThrow()
    expect(() => {
      ;(EFFECT_CLASS_FRESHNESS_V1 as { version: number }).version = 2
    }).toThrow()
  })
})

describe('cadenceMaxAgeSeconds — bounded by what the registry publishes', () => {
  it('bounds each cadence class', () => {
    expect(cadenceMaxAgeSeconds({ kind: 'per-query' })).toBe(3_600)
    expect(cadenceMaxAgeSeconds({ kind: 'daily' })).toBe(2 * 86_400)
    expect(cadenceMaxAgeSeconds({ kind: 'twice-weekly', publishDays: ['Tue', 'Thu'] })).toBe(5 * 86_400)
  })

  it('declares an unknown cadence unbounded (the verdict tier carries the weakness instead)', () => {
    expect(cadenceMaxAgeSeconds({ kind: 'unknown' })).toBeNull()
  })
})

describe('staleBeyondCadence', () => {
  it('accepts a per-query answer minutes old and rejects one hours old', () => {
    expect(staleBeyondCadence(agoIso(600), { kind: 'per-query' }, NOW)).toBe(false)
    expect(staleBeyondCadence(agoIso(2 * 3_600), { kind: 'per-query' }, NOW)).toBe(true)
  })

  it('accepts a twice-weekly file within the publication window and rejects a missed one', () => {
    const cadence = { kind: 'twice-weekly', publishDays: ['Tue', 'Thu'] } as const
    expect(staleBeyondCadence(agoIso(4 * 86_400), cadence, NOW)).toBe(false)
    expect(staleBeyondCadence(agoIso(6 * 86_400), cadence, NOW)).toBe(true)
  })

  it('rejects a daily file older than the slack window', () => {
    expect(staleBeyondCadence(agoIso(86_400), { kind: 'daily' }, NOW)).toBe(false)
    expect(staleBeyondCadence(agoIso(3 * 86_400), { kind: 'daily' }, NOW)).toBe(true)
  })

  it('never types staleness for an unknown cadence', () => {
    expect(staleBeyondCadence(agoIso(30 * 86_400), { kind: 'unknown' }, NOW)).toBe(false)
  })

  it('fails closed on an unparseable asOf', () => {
    expect(staleBeyondCadence('not-a-date', { kind: 'per-query' }, NOW)).toBe(true)
  })
})
