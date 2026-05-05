/**
 * AuthBroker.check() — pure synchronous gate against an Identity. The hot
 * path used by MCP dispatch and digital-tools' wrap() helper.
 */
import { describe, it, expect } from 'vitest'
import { AuthBrokerImpl } from '../src/sdk/auth/broker-impl'
import type { Identity } from '../src/sdk/types'

const broker = new AuthBrokerImpl()

function identity(overrides: Partial<Identity> = {}): Identity {
  return {
    id: 'id-1',
    type: 'agent',
    name: 'test',
    verified: false,
    level: 1,
    claimStatus: 'unclaimed',
    ...overrides,
  } as Identity
}

describe('AuthBroker.check — bare-number requirement (95% case)', () => {
  it('passes when level meets the requirement', () => {
    const result = broker.check(identity({ level: 2 }), 1)
    expect(result.ok).toBe(true)
  })

  it('passes when level exactly equals the requirement', () => {
    const result = broker.check(identity({ level: 1 }), 1)
    expect(result.ok).toBe(true)
  })

  it('fails when level is below', () => {
    const result = broker.check(identity({ level: 0 }), 1)
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toBe('insufficient-level')
      expect(result.identity?.level).toBe(0)
    }
  })

  it('always populates identity on the decision (success or failure)', () => {
    const id = identity({ level: 0 })
    const success = broker.check(identity({ level: 3 }), 1)
    const failure = broker.check(id, 2)
    expect(success.ok && success.identity.id).toBe('id-1')
    expect(!failure.ok && failure.identity?.id).toBe('id-1')
  })
})

describe('AuthBroker.check — typed requirement', () => {
  it('checks minLevel', () => {
    expect(broker.check(identity({ level: 1 }), { minLevel: 2 }).ok).toBe(false)
    expect(broker.check(identity({ level: 2 }), { minLevel: 2 }).ok).toBe(true)
  })

  it('passes when all required scopes are present', () => {
    const id = identity({ scopes: ['read', 'write'] })
    expect(broker.check(id, { scopes: ['read'] }).ok).toBe(true)
    expect(broker.check(id, { scopes: ['read', 'write'] }).ok).toBe(true)
  })

  it('fails when a required scope is missing', () => {
    const id = identity({ scopes: ['read'] })
    const result = broker.check(id, { scopes: ['write'] })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toBe('missing-scope')
  })

  it('treats missing identity.scopes as empty', () => {
    const result = broker.check(identity({ scopes: undefined }), { scopes: ['read'] })
    expect(result.ok).toBe(false)
  })

  it('anyScopes passes when at least one scope matches', () => {
    const id = identity({ scopes: ['read'] })
    expect(broker.check(id, { anyScopes: ['read', 'write'] }).ok).toBe(true)
    expect(broker.check(id, { anyScopes: ['admin'] }).ok).toBe(false)
  })

  it('combines minLevel + scopes — both must pass', () => {
    const id = identity({ level: 1, scopes: ['read'] })
    expect(broker.check(id, { minLevel: 2, scopes: ['read'] }).ok).toBe(false)
    expect(broker.check(id, { minLevel: 1, scopes: ['write'] }).ok).toBe(false)
    expect(broker.check(id, { minLevel: 1, scopes: ['read'] }).ok).toBe(true)
  })

  it('empty scopes array is a no-op (does not block)', () => {
    expect(broker.check(identity({ level: 2 }), { minLevel: 2, scopes: [] }).ok).toBe(true)
  })
})

describe('AuthBroker.check — frozen identities', () => {
  it('blocks frozen identities regardless of level', () => {
    const id = identity({ level: 3, frozen: true })
    const result = broker.check(id, 1)
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toBe('frozen')
  })

  it('frozen check runs before level/scope evaluation', () => {
    const id = identity({ level: 3, frozen: true, scopes: ['admin'] })
    const result = broker.check(id, { minLevel: 1, scopes: ['admin'] })
    if (!result.ok) expect(result.reason).toBe('frozen')
  })
})

describe('AuthBroker.check — FGA requirements', () => {
  it('rejects synchronous calls that pass a resource — FGA must use gate()', () => {
    const id = identity({ level: 2 })
    const result = broker.check(id, {
      minLevel: 1,
      resource: { $id: 'https://x/123', $type: 'Tenant' },
    })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toBe('forbidden')
  })
})
