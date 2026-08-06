/**
 * The RFC 8693 `act` claim, and the ledger check the specification does not
 * require.
 *
 * The first test pins the RFC's own §4.1 worked example, because the direction
 * of the nesting is the one thing here that is easy to get backwards and
 * impossible to notice: a reversed builder produces an envelope that verifies
 * against itself and inverts who is accountable.
 */

import { describe, it, expect } from 'vitest'
import {
  ACT_CHAIN_POISON,
  MAX_CHAIN_DEPTH,
  POISON_HONEST_ENVELOPE,
  POISON_LEDGER_CHAIN,
  chainFromEnvelope,
  envelopeFromChain,
  flattenEnvelope,
  verifyActChain,
} from '../src/server/services/authority/act-chain'
import type { ActHop } from '../src/server/services/authority/types'

describe('RFC 8693 S4.1 - the worked example is the contract', () => {
  // From RFC 8693 §4.1 verbatim, with the RFC's own reading of it:
  // "service16 is the current actor and service77 was a prior actor",
  // for the flow user → service77 → service16.
  const RFC_ENVELOPE = {
    sub: 'user@example.net',
    act: {
      sub: 'https://service16.example.com',
      act: { sub: 'https://service77.example.com' },
    },
  }

  // Our ledger runs the other way: current actor first, root last.
  const LEDGER: ActHop[] = [
    { sub: 'https://service16.example.com', grantId: 'grant_b' },
    { sub: 'https://service77.example.com', grantId: 'grant_a' },
    { sub: 'user@example.net', grantId: null },
  ]

  it('builds the RFC example exactly from our ledger chain', () => {
    expect(envelopeFromChain(LEDGER)).toEqual(RFC_ENVELOPE)
  })

  it('reads the RFC example back into our ledger order', () => {
    expect(chainFromEnvelope(RFC_ENVELOPE)).toEqual([
      'https://service16.example.com',
      'https://service77.example.com',
      'user@example.net',
    ])
  })

  it('verifies the RFC example against the ledger it describes', () => {
    expect(verifyActChain(RFC_ENVELOPE, LEDGER)).toEqual({ ok: true })
  })

  it('round-trips any chain up to the depth cap', () => {
    for (let n = 1; n <= MAX_CHAIN_DEPTH; n++) {
      const chain: ActHop[] = Array.from({ length: n }, (_, i) => ({ sub: `p${i}`, grantId: `g${i}` }))
      const envelope = envelopeFromChain(chain)
      expect(chainFromEnvelope(envelope)).toEqual(chain.map((h) => h.sub))
      expect(verifyActChain(envelope, chain)).toEqual({ ok: true })
    }
  })

  it('a single-hop chain names no actor distinct from its subject', () => {
    expect(envelopeFromChain([{ sub: 'human:seat_kim', grantId: null }])).toEqual({ sub: 'human:seat_kim' })
  })

  it('refuses to build past the depth cap rather than silently truncating', () => {
    const tooDeep: ActHop[] = Array.from({ length: MAX_CHAIN_DEPTH + 1 }, (_, i) => ({ sub: `p${i}`, grantId: null }))
    expect(() => envelopeFromChain(tooDeep)).toThrow(RangeError)
  })

  it('an empty chain has no envelope - not an empty one', () => {
    expect(envelopeFromChain([])).toBeNull()
  })
})

describe('the honest envelope for the poison ledger verifies', () => {
  it('accepts the matching envelope', () => {
    expect(verifyActChain(POISON_HONEST_ENVELOPE, POISON_LEDGER_CHAIN)).toEqual({ ok: true })
  })

  it('is the envelope the builder produces', () => {
    expect(envelopeFromChain(POISON_LEDGER_CHAIN)).toEqual(POISON_HONEST_ENVELOPE)
  })
})

describe('poison fixtures - every one of them is a real forgery shape', () => {
  it('ships fixtures, and they are not all the same failure', () => {
    const reasons = new Set(ACT_CHAIN_POISON.map((p) => p.expect))
    expect(ACT_CHAIN_POISON.length).toBeGreaterThanOrEqual(10)
    expect(reasons.size).toBeGreaterThanOrEqual(4)
  })

  for (const poison of ACT_CHAIN_POISON) {
    it(`refuses ${poison.name} - ${poison.why}`, () => {
      const verdict = verifyActChain(poison.presented, poison.ledger)
      expect(verdict.ok, `${poison.name} was ACCEPTED`).toBe(false)
      if (!verdict.ok) expect(verdict.reason).toBe(poison.expect)
    })
  }
})

describe('the checks that a set-based or length-based verifier would pass', () => {
  it('refuses a reordering even though the SET of principals is identical', () => {
    const reordered = {
      sub: 'human:seat_kim',
      act: { sub: 'agent_supervisor_02', act: { sub: 'agent_7f3a' } },
    }
    const honestSet = new Set(chainFromEnvelope(POISON_HONEST_ENVELOPE))
    const forgedSet = new Set(chainFromEnvelope(reordered))
    expect(forgedSet).toEqual(honestSet) // a set check would pass this
    expect(verifyActChain(reordered, POISON_LEDGER_CHAIN).ok).toBe(false)
  })

  it('refuses a substitution even though the LENGTH is identical', () => {
    const substituted = {
      sub: 'human:seat_kim',
      act: { sub: 'agent_7f3a', act: { sub: 'agent_impostor' } },
    }
    expect(chainFromEnvelope(substituted)!.length).toBe(POISON_LEDGER_CHAIN.length)
    expect(verifyActChain(substituted, POISON_LEDGER_CHAIN).ok).toBe(false)
  })

  it('refuses an empty ledger - there is nothing to verify against', () => {
    expect(verifyActChain(POISON_HONEST_ENVELOPE, [])).toEqual({ ok: false, reason: 'empty', at: 0 })
  })
})

describe('flattenEnvelope never truncates', () => {
  it('reports depth-exceeded rather than returning the first N hops', () => {
    let envelope: unknown = { sub: 'p0' }
    for (let i = 1; i <= MAX_CHAIN_DEPTH + 3; i++) envelope = { sub: `p${i}`, act: envelope }
    const flat = flattenEnvelope(envelope)
    expect(flat.ok).toBe(false)
    if (!flat.ok) expect(flat.reason).toBe('depth-exceeded')
    expect(chainFromEnvelope(envelope)).toBeNull()
  })

  it('reports malformed at the hop that broke, not at hop zero', () => {
    const flat = flattenEnvelope({ sub: 'a', act: { sub: 'b', act: { sub: 42 } } })
    expect(flat.ok).toBe(false)
    if (!flat.ok) {
      expect(flat.reason).toBe('malformed')
      expect(flat.at).toBe(2)
    }
  })
})
