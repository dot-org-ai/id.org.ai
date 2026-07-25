/**
 * CredentialFactService (id-j0k) — held-credential facts per principal,
 * verification journal insert-only.
 */

import { describe, it, expect, beforeEach } from 'vitest'
import { MemoryStorageAdapter } from '../src/sdk/storage'
import { CredentialFactServiceImpl } from '../src/server/services/credential'
import type { CredentialVerificationEvent } from '../src/server/services/credential'

function makeService() {
  return new CredentialFactServiceImpl({ storage: new MemoryStorageAdapter() })
}

function makeEvent(overrides: Partial<CredentialVerificationEvent> = {}): CredentialVerificationEvent {
  return {
    principalId: 'user_pat',
    credentialType: 'uspto-registered',
    ref: '99999',
    registry: 'uspto-oed',
    verdict: 'registry-verified',
    sourceClass: 'public-lookup',
    effectClass: 'act',
    live: true,
    goodStanding: true,
    satisfiesActClass: true,
    checkedAt: '2026-07-25T12:00:00.000Z',
    ...overrides,
  }
}

describe('held-credential facts', () => {
  let service: CredentialFactServiceImpl

  beforeEach(() => {
    service = makeService()
  })

  it('stores and retrieves a fact per principal', async () => {
    const put = await service.putFact({
      principalId: 'user_pat',
      credentialType: 'uspto-registered',
      ref: '99999',
      presented: { type: 'uspto-registered', registrationNumber: '99999' },
    })
    expect(put.success).toBe(true)
    if (!put.success) return
    expect(put.data.recordedAt).toBeTruthy()

    const got = await service.getFact('user_pat', 'uspto-registered', '99999')
    expect(got.success).toBe(true)
    if (!got.success) return
    expect(got.data.presented.registrationNumber).toBe('99999')
  })

  it('answers NotFound for an absent fact', async () => {
    const got = await service.getFact('user_pat', 'uspto-registered', 'nope')
    expect(got.success).toBe(false)
  })

  it('validates required fields', async () => {
    const missingPrincipal = await service.putFact({
      principalId: '',
      credentialType: 't',
      ref: 'r',
      presented: { type: 't' },
    })
    expect(missingPrincipal.success).toBe(false)

    const missingPresented = await service.putFact({
      principalId: 'p',
      credentialType: 't',
      ref: 'r',
      presented: undefined as never,
    })
    expect(missingPresented.success).toBe(false)
  })

  it('lists facts filtered by credential type, isolated per principal', async () => {
    await service.putFact({ principalId: 'a', credentialType: 'mn-dealer-license', ref: '1', presented: { type: 'mn-dealer-license' } })
    await service.putFact({ principalId: 'a', credentialType: 'tx-dealer-license', ref: '2', presented: { type: 'tx-dealer-license' } })
    await service.putFact({ principalId: 'b', credentialType: 'mn-dealer-license', ref: '3', presented: { type: 'mn-dealer-license' } })

    expect(await service.listFacts('a')).toHaveLength(2)
    expect(await service.listFacts('a', { credentialType: 'mn-dealer-license' })).toHaveLength(1)
    expect(await service.listFacts('b')).toHaveLength(1)
    expect(await service.listFacts('c')).toHaveLength(0)
  })

  it('deletes a fact and reports whether one existed', async () => {
    await service.putFact({ principalId: 'a', credentialType: 't', ref: '1', presented: { type: 't' } })
    expect(await service.deleteFact('a', 't', '1')).toEqual({ success: true, data: { deleted: true } })
    expect(await service.deleteFact('a', 't', '1')).toEqual({ success: true, data: { deleted: false } })
  })
})

describe('verification journal — insert-only', () => {
  let service: CredentialFactServiceImpl

  beforeEach(() => {
    service = makeService()
  })

  it('records events and lists them newest first', async () => {
    await service.recordVerification(makeEvent({ checkedAt: '2026-07-25T10:00:00.000Z', verdict: 'unverifiable-by-registry' }))
    await service.recordVerification(makeEvent({ checkedAt: '2026-07-25T12:00:00.000Z' }))
    await service.recordVerification(makeEvent({ checkedAt: '2026-07-25T11:00:00.000Z', verdict: 'holder-attested' }))

    const events = await service.listVerifications('user_pat')
    expect(events.map((e) => e.checkedAt)).toEqual([
      '2026-07-25T12:00:00.000Z',
      '2026-07-25T11:00:00.000Z',
      '2026-07-25T10:00:00.000Z',
    ])
  })

  it('never merges events at the same instant (insert-only, no overwrite)', async () => {
    await service.recordVerification(makeEvent({ verdict: 'registry-verified' }))
    await service.recordVerification(makeEvent({ verdict: 'holder-attested' }))
    const events = await service.listVerifications('user_pat')
    expect(events).toHaveLength(2)
  })

  it('respects the list limit', async () => {
    for (let i = 0; i < 5; i++) {
      await service.recordVerification(makeEvent({ checkedAt: `2026-07-25T0${i}:00:00.000Z` }))
    }
    expect(await service.listVerifications('user_pat', { limit: 3 })).toHaveLength(3)
  })

  it('validates the event', async () => {
    const bad = await service.recordVerification(makeEvent({ registry: '' }))
    expect(bad.success).toBe(false)
  })

  it('exposes no update or delete surface for the journal', () => {
    const surface = service as unknown as Record<string, unknown>
    expect(surface.updateVerification).toBeUndefined()
    expect(surface.deleteVerification).toBeUndefined()
  })
})
