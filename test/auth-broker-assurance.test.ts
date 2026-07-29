/**
 * AuthBroker × federation assurance.
 *
 * Two properties, both security-relevant:
 *
 *   1. **The clamp.** A federated principal is evaluated at the level its
 *      assurance supports, NOT the level written on the row. IdentityService
 *      enforces level monotonicity (a level can only go up), so without the
 *      clamp a viewer who first arrived through Entra at L2 and later returned
 *      through the weaker email-code path would keep L2 forever.
 *
 *   2. **No collateral damage.** Every non-federated principal — API keys,
 *      agents, WorkOS humans, anonymous — must be completely unaffected.
 */
import { describe, it, expect } from 'vitest'
import { AuthBrokerImpl } from '../src/sdk/auth/broker-impl'
import type { Identity } from '../src/sdk/types'
import type { FederationProvenance } from '../src/sdk/federation/types'
import { assuranceSatisfies, levelCeilingForAssurance } from '../src/sdk/federation/types'

const broker = new AuthBrokerImpl()

function provenance(assurance: FederationProvenance['assurance']): FederationProvenance {
  return {
    provider: assurance === 'federated-idp' ? 'microsoft' : 'email-code',
    issuer: 'https://login.microsoftonline.com/tid/v2.0',
    tenantId: assurance === 'federated-idp' ? 'tid' : undefined,
    subject: 'subject',
    assurance,
    verifiedAt: Date.now(),
    emailDomain: 'zebra.com',
  }
}

function federatedIdentity(assurance: FederationProvenance['assurance'], level: Identity['level']): Identity {
  return {
    id: 'human:ms:tid:oid',
    type: 'human',
    name: 'Alice Anders',
    email: 'alice@zebra.com',
    verified: true,
    level,
    claimStatus: 'claimed',
    federation: provenance(assurance),
  }
}

// ── Ordering primitives ───────────────────────────────────────────────────

describe('assurance ordering', () => {
  it('ranks federated-idp above email-code above unverified', () => {
    expect(assuranceSatisfies('federated-idp', 'email-code')).toBe(true)
    expect(assuranceSatisfies('email-code', 'federated-idp')).toBe(false)
    expect(assuranceSatisfies('email-code', 'email-code')).toBe(true)
    expect(assuranceSatisfies('unverified', 'email-code')).toBe(false)
    expect(assuranceSatisfies(undefined, 'email-code')).toBe(false)
  })

  it('maps assurance to a capability ceiling', () => {
    expect(levelCeilingForAssurance('federated-idp')).toBe(2)
    expect(levelCeilingForAssurance('email-code')).toBe(1)
    expect(levelCeilingForAssurance('unverified')).toBe(0)
    expect(levelCeilingForAssurance(undefined)).toBe(0)
  })
})

// ── 1. The clamp ──────────────────────────────────────────────────────────

describe('check() clamps a federated identity to its assurance ceiling', () => {
  it('lets a Microsoft-federated viewer through an L2 gate', () => {
    const decision = broker.check(federatedIdentity('federated-idp', 2), 2)
    expect(decision.ok).toBe(true)
  })

  it('denies an L2 gate to an email-code viewer even when the row says level 2', () => {
    const stale = federatedIdentity('email-code', 2)
    const decision = broker.check(stale, 2)
    expect(decision.ok).toBe(false)
    if (!decision.ok) expect(decision.reason).toBe('insufficient-level')
  })

  it('still lets that email-code viewer through an L1 gate', () => {
    expect(broker.check(federatedIdentity('email-code', 2), 1).ok).toBe(true)
  })

  it('reports the clamped level on the returned identity, not the stored one', () => {
    const decision = broker.check(federatedIdentity('email-code', 2), 1)
    expect(decision.ok).toBe(true)
    if (decision.ok) expect(decision.identity.level).toBe(1)
  })

  it('never raises a level — a federated-idp principal stored at L1 stays L1', () => {
    const decision = broker.check(federatedIdentity('federated-idp', 1), 1)
    expect(decision.ok).toBe(true)
    if (decision.ok) expect(decision.identity.level).toBe(1)
  })

  it('clamps through the typed requirement shape too', () => {
    const decision = broker.check(federatedIdentity('email-code', 2), { minLevel: 2 })
    expect(decision.ok).toBe(false)
    if (!decision.ok) expect(decision.reason).toBe('insufficient-level')
  })
})

// ── 2. minAssurance ───────────────────────────────────────────────────────

describe('check() honours minAssurance', () => {
  it('admits a Microsoft-federated viewer to a federated-idp-only surface', () => {
    expect(broker.check(federatedIdentity('federated-idp', 2), { minAssurance: 'federated-idp' }).ok).toBe(true)
  })

  it('denies an email-code viewer with insufficient-assurance, not insufficient-level', () => {
    const decision = broker.check(federatedIdentity('email-code', 1), { minAssurance: 'federated-idp' })
    expect(decision.ok).toBe(false)
    // The distinction matters: the cure is re-authentication through the
    // stronger path, not a level grant.
    if (!decision.ok) expect(decision.reason).toBe('insufficient-assurance')
  })

  it('admits an email-code viewer to an email-code-or-better surface', () => {
    expect(broker.check(federatedIdentity('email-code', 1), { minAssurance: 'email-code' }).ok).toBe(true)
  })

  it('denies a non-federated principal any minAssurance requirement', () => {
    const apiKeyIdentity: Identity = {
      id: 'agent_1',
      type: 'agent',
      name: 'api-key',
      verified: true,
      level: 2,
      claimStatus: 'claimed',
      scopes: ['read', 'write'],
    }
    const decision = broker.check(apiKeyIdentity, { minAssurance: 'email-code' })
    expect(decision.ok).toBe(false)
    if (!decision.ok) expect(decision.reason).toBe('insufficient-assurance')
  })

  it('composes with a level requirement — both must pass', () => {
    const viewer = federatedIdentity('federated-idp', 2)
    expect(broker.check(viewer, { minLevel: 2, minAssurance: 'federated-idp' }).ok).toBe(true)
    expect(broker.check(viewer, { minLevel: 3, minAssurance: 'federated-idp' }).ok).toBe(false)
  })
})

// ── 3. No collateral damage ───────────────────────────────────────────────

describe('non-federated principals are untouched', () => {
  const cases: Array<[string, Identity]> = [
    [
      'API-key agent at L2',
      { id: 'agent_1', type: 'agent', name: 'agent', verified: true, level: 2, claimStatus: 'claimed' },
    ],
    [
      'WorkOS human at L2',
      { id: 'human:user_1', type: 'human', name: 'Nathan', verified: true, level: 2, claimStatus: 'claimed' },
    ],
    [
      'WorkOS service key at L2',
      { id: 'apik_1', type: 'service', name: 'svc', verified: true, level: 2, claimStatus: 'claimed' },
    ],
    ['anonymous at L0', { id: 'anon', type: 'agent', name: 'anonymous', verified: false, level: 0, claimStatus: 'unclaimed' }],
  ]

  for (const [label, identity] of cases) {
    it(`${label} keeps its level`, () => {
      const decision = broker.check(identity, identity.level)
      expect(decision.ok).toBe(true)
      if (decision.ok) expect(decision.identity.level).toBe(identity.level)
    })
  }

  it('returns the SAME object reference when no clamp applies (no hot-path allocation)', () => {
    const identity = cases[0]![1]
    const decision = broker.check(identity, 0)
    expect(decision.ok).toBe(true)
    if (decision.ok) expect(decision.identity).toBe(identity)
  })

  it('a frozen federated identity is still refused before any assurance logic runs', () => {
    const frozen = { ...federatedIdentity('federated-idp', 2), frozen: true }
    const decision = broker.check(frozen, 0)
    expect(decision.ok).toBe(false)
    if (!decision.ok) expect(decision.reason).toBe('frozen')
  })
})
