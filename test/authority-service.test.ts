/**
 * The four authority verbs, and the poison that proves each rule is enforced
 * rather than described.
 *
 * Every `describe` below names a rule from the requirements it enforces. Where
 * a test asserts an absence -- no Action written, no row returned, no field
 * present -- the absence is the point and the comment says why.
 */

import { describe, it, expect, beforeEach } from 'vitest'
import { MemoryStorageAdapter } from '../src/sdk/storage'
import {
  AuthorityServiceImpl,
  MemoryActionSink,
  NON_RETROACTIVE_DISCLOSURE,
} from '../src/server/services/authority/service'
import { AUTHORITY_SLUGS } from '../src/server/services/authority/types'
import type {
  ActClaimShape,
  AuthorityError,
  GrantRecord,
  GrantReceipt,
  Scope,
  SettledAskRef,
} from '../src/server/services/authority/types'
import type { Result } from '../src/sdk/foundation'

// ── Fixtures ────────────────────────────────────────────────────────────────

const TENANT = 'tenant_acme'
const OTHER_TENANT = 'tenant_globex'
const KIM = 'human:seat_kim'
const DANA = 'human:seat_dana'
const AGENT = 'agent_7f3a'
const SUPERVISOR = 'agent_supervisor_02'

const NOW = new Date('2026-08-05T12:00:00.000Z')
const IN_AN_HOUR = '2026-08-05T13:00:00.000Z'
const IN_A_DAY = '2026-08-06T12:00:00.000Z'
const IN_A_WEEK = '2026-08-12T12:00:00.000Z'
const YESTERDAY = '2026-08-04T12:00:00.000Z'

const CAPTURE_GTIN: Scope = {
  grants: [{ verb: 'epcis.capture', resource: 'gtin/09506000134376', ceiling: { value: 500, unit: 'events' } }],
}
const CAPTURE_ANY_GTIN: Scope = { grants: [{ verb: 'epcis.capture', resource: 'gtin/*' }] }
const EVERYTHING: Scope = { grants: [{ verb: '*', resource: '*' }] }

let storage: MemoryStorageAdapter
let sink: MemoryActionSink
let svc: AuthorityServiceImpl

beforeEach(() => {
  storage = new MemoryStorageAdapter()
  sink = new MemoryActionSink()
  svc = new AuthorityServiceImpl({ storage, actions: sink, now: () => NOW, origin: 'https://id.org.ai' })
})

function unwrap<T>(r: Result<T, AuthorityError>): T {
  if (!r.success) throw new Error(`expected Ok, got ${r.error.slug}: ${r.error.message}`)
  return r.data
}

function slugOf<T>(r: Result<T, AuthorityError>): string {
  if (r.success) throw new Error('expected an error, got Ok')
  return r.error.slug
}

async function dispatchAsk(askId = 'ask_1', scope: Scope = CAPTURE_GTIN, tenantId = TENANT) {
  return unwrap(
    await svc.recordAsk({
      askId,
      tenantId,
      requestedBy: AGENT,
      onBehalfOf: KIM,
      scope,
      expiresAt: IN_AN_HOUR,
      createdAt: NOW.toISOString(),
    }),
  )
}

function askRef(askId = 'ask_1', askedScope: Scope = CAPTURE_GTIN, settledBy = KIM): SettledAskRef {
  return { askId, settledBy, askedScope }
}

/** The happy path every other test builds on: a human settled a concrete ask. */
async function mintFromAsk(overrides: Partial<Parameters<AuthorityServiceImpl['grant']>[0]> = {}): Promise<GrantReceipt> {
  await dispatchAsk()
  return unwrap(
    await svc.grant({
      tenantId: TENANT,
      subject: { kind: 'agent', id: AGENT },
      scope: CAPTURE_GTIN,
      expiresAt: IN_A_DAY,
      fromAsk: askRef(),
      actor: KIM,
      ...overrides,
    }),
  )
}

// ============================================================================

describe('grant: a grant is never authored from parameters', () => {
  it('refuses a grant that cites neither a settled ask nor a parent', async () => {
    const r = await svc.grant({
      tenantId: TENANT,
      subject: { kind: 'agent', id: AGENT },
      scope: CAPTURE_GTIN,
      expiresAt: IN_A_DAY,
      actor: KIM,
    })
    expect(slugOf(r)).toBe('authority-authoring-refused')
  })

  it('refuses a grant that cites BOTH an ask and a parent', async () => {
    const parent = await mintFromAsk()
    await dispatchAsk('ask_2')
    const r = await svc.grant({
      tenantId: TENANT,
      subject: { kind: 'agent', id: SUPERVISOR },
      scope: CAPTURE_GTIN,
      expiresAt: IN_A_DAY,
      fromAsk: askRef('ask_2'),
      parentGrantId: parent.grant.id,
      actor: KIM,
    })
    expect(slugOf(r)).toBe('authority-authoring-refused')
  })

  it('refuses an ask settled by an agent -- an agent that approves its own ask has abolished the tier', async () => {
    await dispatchAsk()
    const r = await svc.grant({
      tenantId: TENANT,
      subject: { kind: 'agent', id: AGENT },
      scope: CAPTURE_GTIN,
      expiresAt: IN_A_DAY,
      fromAsk: askRef('ask_1', CAPTURE_GTIN, AGENT),
      actor: AGENT,
    })
    expect(slugOf(r)).toBe('not-the-warrantor')
  })

  it('refuses a minted Scope wider than the ask the human read', async () => {
    await dispatchAsk('ask_1', CAPTURE_GTIN)
    const r = await svc.grant({
      tenantId: TENANT,
      subject: { kind: 'agent', id: AGENT },
      scope: EVERYTHING,
      expiresAt: IN_A_DAY,
      fromAsk: askRef('ask_1', CAPTURE_GTIN),
      actor: KIM,
    })
    expect(slugOf(r)).toBe('grant-widens-ask')
  })

  it('mints a Scope that narrows the ask, and one identical to it', async () => {
    await dispatchAsk('ask_wide', CAPTURE_ANY_GTIN)
    const narrower = await svc.grant({
      tenantId: TENANT,
      subject: { kind: 'agent', id: AGENT },
      scope: { grants: [{ verb: 'epcis.capture', resource: 'gtin/09506000134376' }] },
      expiresAt: IN_A_DAY,
      fromAsk: askRef('ask_wide', CAPTURE_ANY_GTIN),
      actor: KIM,
    })
    expect(narrower.success).toBe(true)

    await dispatchAsk('ask_same', CAPTURE_GTIN)
    const identical = await svc.grant({
      tenantId: TENANT,
      subject: { kind: 'agent', id: AGENT },
      scope: CAPTURE_GTIN,
      expiresAt: IN_A_DAY,
      fromAsk: askRef('ask_same', CAPTURE_GTIN),
      actor: KIM,
    })
    expect(identical.success).toBe(true)
  })

  it('refuses a warrantor other than the human who settled it', async () => {
    await dispatchAsk()
    const r = await svc.grant({
      tenantId: TENANT,
      subject: { kind: 'agent', id: AGENT },
      scope: CAPTURE_GTIN,
      expiresAt: IN_A_DAY,
      fromAsk: askRef(),
      warrantor: DANA,
      actor: KIM,
    })
    expect(slugOf(r)).toBe('warrantor-mismatch')
  })

  it('refuses an expiry in the past and a malformed one', async () => {
    await dispatchAsk()
    expect(
      slugOf(
        await svc.grant({
          tenantId: TENANT,
          subject: { kind: 'agent', id: AGENT },
          scope: CAPTURE_GTIN,
          expiresAt: YESTERDAY,
          fromAsk: askRef(),
          actor: KIM,
        }),
      ),
    ).toBe('invalid-expiry')
    expect(
      slugOf(
        await svc.grant({
          tenantId: TENANT,
          subject: { kind: 'agent', id: AGENT },
          scope: CAPTURE_GTIN,
          expiresAt: 'next tuesday',
          fromAsk: askRef(),
          actor: KIM,
        }),
      ),
    ).toBe('invalid-expiry')
  })

  it('refuses a Scope that is not a Scope', async () => {
    await dispatchAsk()
    const r = await svc.grant({
      tenantId: TENANT,
      subject: { kind: 'agent', id: AGENT },
      scope: { grants: [{ verb: 'epcis.capture' }] } as unknown as Scope,
      expiresAt: IN_A_DAY,
      fromAsk: askRef(),
      actor: KIM,
    })
    expect(slugOf(r)).toBe('malformed-scope')
  })

  it('refuses to settle an ask that already expired', async () => {
    await svc.recordAsk({
      askId: 'ask_old',
      tenantId: TENANT,
      requestedBy: AGENT,
      onBehalfOf: KIM,
      scope: CAPTURE_GTIN,
      expiresAt: YESTERDAY,
      createdAt: YESTERDAY,
    })
    const r = await svc.grant({
      tenantId: TENANT,
      subject: { kind: 'agent', id: AGENT },
      scope: CAPTURE_GTIN,
      expiresAt: IN_A_DAY,
      fromAsk: askRef('ask_old'),
      actor: KIM,
    })
    expect(slugOf(r)).toBe('ask-expired')
  })

  it('returns the seatless revoke secret exactly once, at mint', async () => {
    const receipt = await mintFromAsk()
    expect(receipt.revokeToken).toMatch(/^rvk_[0-9a-f]{48}$/)
    // The secret is never readable back off the record.
    const stored = await storage.get<GrantRecord>(`authority:grant:${receipt.grant.id}`)
    expect(stored!.revokeTokenHash).toBeTruthy()
    expect(JSON.stringify(stored)).not.toContain(receipt.revokeToken)
    // Nor off any read projection.
    const introspected = unwrap(await svc.introspect({ tenantId: TENANT, grantId: receipt.grant.id }))
    expect(JSON.stringify(introspected)).not.toContain(receipt.revokeToken)
  })

  it('records exactly one mint Action and no others', async () => {
    await mintFromAsk()
    expect(sink.emitted.map((a) => a.action)).toEqual(['authority.mint'])
  })

  it('marks the ask granted, so a second channel cannot settle it again', async () => {
    const receipt = await mintFromAsk()
    const settlement = unwrap(await svc.settlement({ tenantId: TENANT, askId: 'ask_1' }))
    expect(settlement.state).toBe('granted')
    expect(settlement.grantId).toBe(receipt.grant.id)

    const second = await svc.grant({
      tenantId: TENANT,
      subject: { kind: 'agent', id: SUPERVISOR },
      scope: CAPTURE_GTIN,
      expiresAt: IN_A_DAY,
      fromAsk: askRef(),
      actor: KIM,
    })
    expect(slugOf(second)).toBe('ask-already-settled')
  })
})

describe('grant: an attenuation may only ever shrink', () => {
  it('mints a narrower child of an active parent', async () => {
    const parent = await mintFromAsk({ scope: CAPTURE_ANY_GTIN, fromAsk: askRef('ask_1', CAPTURE_ANY_GTIN) })
    const child = unwrap(
      await svc.grant({
        tenantId: TENANT,
        subject: { kind: 'agent', id: SUPERVISOR },
        scope: { grants: [{ verb: 'epcis.capture', resource: 'gtin/09506000134376' }] },
        expiresAt: IN_AN_HOUR,
        parentGrantId: parent.grant.id,
        actor: AGENT,
      }),
    )
    expect(child.grant.parentGrantId).toBe(parent.grant.id)
    expect(child.grant.warrantor).toBe(KIM)
    expect(sink.byName('authority.attenuate')).toHaveLength(1)
  })

  it('refuses a child that widens the parent Scope', async () => {
    const parent = await mintFromAsk()
    const r = await svc.grant({
      tenantId: TENANT,
      subject: { kind: 'agent', id: SUPERVISOR },
      scope: EVERYTHING,
      expiresAt: IN_AN_HOUR,
      parentGrantId: parent.grant.id,
      actor: AGENT,
    })
    expect(slugOf(r)).toBe('scope-widens-parent')
  })

  it('refuses a child that outlives the parent', async () => {
    const parent = await mintFromAsk()
    const r = await svc.grant({
      tenantId: TENANT,
      subject: { kind: 'agent', id: SUPERVISOR },
      scope: CAPTURE_GTIN,
      expiresAt: IN_A_WEEK,
      parentGrantId: parent.grant.id,
      actor: AGENT,
    })
    expect(slugOf(r)).toBe('expiry-widens-parent')
  })

  it('refuses attenuation by anyone but the holder or the warrantor', async () => {
    const parent = await mintFromAsk()
    const r = await svc.grant({
      tenantId: TENANT,
      subject: { kind: 'agent', id: 'agent_stranger' },
      scope: CAPTURE_GTIN,
      expiresAt: IN_AN_HOUR,
      parentGrantId: parent.grant.id,
      actor: 'agent_stranger',
    })
    expect(slugOf(r)).toBe('not-the-warrantor')
  })

  it('refuses attenuation of a revoked parent', async () => {
    const parent = await mintFromAsk()
    await svc.revoke({ tenantId: TENANT, grantId: parent.grant.id, actor: KIM })
    const r = await svc.grant({
      tenantId: TENANT,
      subject: { kind: 'agent', id: SUPERVISOR },
      scope: CAPTURE_GTIN,
      expiresAt: IN_AN_HOUR,
      parentGrantId: parent.grant.id,
      actor: AGENT,
    })
    expect(slugOf(r)).toBe('grant-not-active')
  })

  it('refuses a child that re-declares a different warrantor', async () => {
    const parent = await mintFromAsk()
    const r = await svc.grant({
      tenantId: TENANT,
      subject: { kind: 'agent', id: SUPERVISOR },
      scope: CAPTURE_GTIN,
      expiresAt: IN_AN_HOUR,
      parentGrantId: parent.grant.id,
      warrantor: DANA,
      actor: AGENT,
    })
    expect(slugOf(r)).toBe('warrantor-mismatch')
  })

  it('refuses a standing envelope minted by attenuation -- no human read it', async () => {
    const parent = await mintFromAsk()
    const r = await svc.grant({
      tenantId: TENANT,
      subject: { kind: 'agent', id: SUPERVISOR },
      scope: CAPTURE_GTIN,
      expiresAt: IN_AN_HOUR,
      parentGrantId: parent.grant.id,
      standing: true,
      bindsToTier: 'agentic',
      actor: AGENT,
    })
    expect(slugOf(r)).toBe('authority-authoring-refused')
  })

  it('refuses a parent in another tenant as MISSING, not as forbidden', async () => {
    const parent = await mintFromAsk()
    const r = await svc.grant({
      tenantId: OTHER_TENANT,
      subject: { kind: 'agent', id: SUPERVISOR },
      scope: CAPTURE_GTIN,
      expiresAt: IN_AN_HOUR,
      parentGrantId: parent.grant.id,
      actor: AGENT,
    })
    expect(slugOf(r)).toBe('grant-not-found')
  })

  it('builds an act envelope in RFC 8693 order across the whole chain', async () => {
    const parent = await mintFromAsk({ scope: CAPTURE_ANY_GTIN, fromAsk: askRef('ask_1', CAPTURE_ANY_GTIN) })
    const child = unwrap(
      await svc.grant({
        tenantId: TENANT,
        subject: { kind: 'agent', id: SUPERVISOR },
        scope: CAPTURE_ANY_GTIN,
        expiresAt: IN_AN_HOUR,
        parentGrantId: parent.grant.id,
        actor: AGENT,
      }),
    )
    // sub = the human root; outermost act = the most recent actor.
    expect(child.actClaim).toEqual({
      sub: KIM,
      act: { sub: SUPERVISOR, act: { sub: AGENT } },
    } satisfies ActClaimShape)
  })
})

describe('grant: a standing envelope is a preview of consequence, not an editor', () => {
  it('refuses a standing envelope that names no cascade rung', async () => {
    await dispatchAsk()
    const r = await svc.grant({
      tenantId: TENANT,
      subject: { kind: 'agent', id: AGENT },
      scope: CAPTURE_GTIN,
      expiresAt: IN_A_DAY,
      fromAsk: askRef(),
      standing: true,
      actor: KIM,
    })
    expect(slugOf(r)).toBe('authority-authoring-refused')
  })

  it('mints one that is exactly the ScopeGrant of the ask the human read', async () => {
    const receipt = await mintFromAsk({ standing: true, bindsToTier: 'agentic', narrowingAsksIncluded: true })
    expect(receipt.grant.standing).toBe(true)
    expect(receipt.grant.bindsToTier).toBe('agentic')
    expect(receipt.grant.narrowingAsksIncluded).toBe(true)
    expect(receipt.grant.scope).toEqual(CAPTURE_GTIN)
  })

  it('refuses a standing envelope wider than the ask, even by one wildcard', async () => {
    await dispatchAsk('ask_1', CAPTURE_GTIN)
    const r = await svc.grant({
      tenantId: TENANT,
      subject: { kind: 'agent', id: AGENT },
      scope: CAPTURE_ANY_GTIN,
      expiresAt: IN_A_DAY,
      fromAsk: askRef('ask_1', CAPTURE_GTIN),
      standing: true,
      bindsToTier: 'agentic',
      actor: KIM,
    })
    expect(slugOf(r)).toBe('grant-widens-ask')
  })
})

describe('grant: a subject that has never resolved (REQ-9)', () => {
  async function mintPending() {
    await dispatchAsk()
    return unwrap(
      await svc.grant({
        tenantId: TENANT,
        subject: { kind: 'pending', hint: 'kim@acme.example' },
        scope: CAPTURE_GTIN,
        expiresAt: IN_A_DAY,
        fromAsk: askRef(),
        actor: KIM,
      }),
    )
  }

  it('mints a pending Scope with a claim URL', async () => {
    const receipt = await mintPending()
    expect(receipt.grant.status).toBe('pending')
    expect(receipt.claimToken).toMatch(/^clm_[0-9a-f]{48}$/)
    expect(receipt.grant.claimUrl).toContain(receipt.claimToken!)
  })

  it('authorises NOTHING before it is claimed', async () => {
    const receipt = await mintPending()
    const decision = unwrap(
      await svc.authorize({
        tenantId: TENANT,
        grantId: receipt.grant.id,
        verb: 'epcis.capture',
        resource: 'gtin/09506000134376',
        amount: { value: 1, unit: 'events' },
        actor: AGENT,
      }),
    )
    expect(decision.allowed).toBe(false)
    expect(decision.slug).toBe('subject-unclaimed')
  })

  it('is revocable before claim, and stays dead afterwards', async () => {
    const receipt = await mintPending()
    const revoked = unwrap(await svc.revoke({ tenantId: TENANT, grantId: receipt.grant.id, actor: KIM }))
    expect(revoked.alreadyRevoked).toBe(false)
    const claimed = await svc.claim({
      tenantId: TENANT,
      grantId: receipt.grant.id,
      claimToken: receipt.claimToken!,
      subject: { kind: 'human', id: 'human:seat_new' },
      actor: 'human:seat_new',
    })
    expect(slugOf(claimed)).toBe('grant-not-active')
  })

  it('refuses a wrong claim token and a token for another grant', async () => {
    const a = await mintPending()
    await dispatchAsk('ask_2')
    const b = unwrap(
      await svc.grant({
        tenantId: TENANT,
        subject: { kind: 'pending' },
        scope: CAPTURE_GTIN,
        expiresAt: IN_A_DAY,
        fromAsk: askRef('ask_2'),
        actor: KIM,
      }),
    )
    expect(
      slugOf(
        await svc.claim({
          tenantId: TENANT,
          grantId: a.grant.id,
          claimToken: 'clm_' + '0'.repeat(48),
          subject: { kind: 'human', id: 'human:seat_new' },
          actor: 'human:seat_new',
        }),
      ),
    ).toBe('claim-token-invalid')
    expect(
      slugOf(
        await svc.claim({
          tenantId: TENANT,
          grantId: a.grant.id,
          claimToken: b.claimToken!,
          subject: { kind: 'human', id: 'human:seat_new' },
          actor: 'human:seat_new',
        }),
      ),
    ).toBe('claim-token-invalid')
  })

  it('is single-use -- two people cannot claim the same grant', async () => {
    const receipt = await mintPending()
    const first = await svc.claim({
      tenantId: TENANT,
      grantId: receipt.grant.id,
      claimToken: receipt.claimToken!,
      subject: { kind: 'human', id: 'human:seat_first' },
      actor: 'human:seat_first',
    })
    expect(first.success).toBe(true)
    const second = await svc.claim({
      tenantId: TENANT,
      grantId: receipt.grant.id,
      claimToken: receipt.claimToken!,
      subject: { kind: 'human', id: 'human:seat_second' },
      actor: 'human:seat_second',
    })
    expect(slugOf(second)).toBe('claim-token-invalid')
  })

  it('activates on claim, extends the chain, and stops advertising a claim URL', async () => {
    const receipt = await mintPending()
    const claimed = unwrap(
      await svc.claim({
        tenantId: TENANT,
        grantId: receipt.grant.id,
        claimToken: receipt.claimToken!,
        subject: { kind: 'human', id: 'human:seat_new' },
        actor: 'human:seat_new',
      }),
    )
    expect(claimed.grant.status).toBe('active')
    expect(claimed.grant.claimUrl).toBeNull()
    expect(claimed.actClaim).toEqual({ sub: KIM, act: { sub: 'human:seat_new' } })
    expect(sink.byName('authority.claim')).toHaveLength(1)
  })

  it('introspects as a REAL gap, never as a resolved hop naming nobody', async () => {
    const receipt = await mintPending()
    const result = unwrap(await svc.introspect({ tenantId: TENANT, grantId: receipt.grant.id }))
    expect(result.chain[0].resolution).toBe('unresolved')
    expect(result.chain[0].gap).toBe('subject-unclaimed')
    expect(result.chain[0].principal).toBeNull()
    expect(result.chainComplete).toBe(false)
    expect(result.rootsAtHuman).toBe(false)
  })
})

describe('introspect: the full chain to its human root, gaps included (REQ-6)', () => {
  it('walks a two-hop delegation to the human who settled the ask', async () => {
    const parent = await mintFromAsk({ scope: CAPTURE_ANY_GTIN, fromAsk: askRef('ask_1', CAPTURE_ANY_GTIN) })
    const child = unwrap(
      await svc.grant({
        tenantId: TENANT,
        subject: { kind: 'agent', id: SUPERVISOR },
        scope: CAPTURE_ANY_GTIN,
        expiresAt: IN_AN_HOUR,
        parentGrantId: parent.grant.id,
        actor: AGENT,
      }),
    )
    const result = unwrap(await svc.introspect({ tenantId: TENANT, grantId: child.grant.id }))
    expect(result.chain.map((h) => h.principal)).toEqual([SUPERVISOR, AGENT, KIM])
    expect(result.chainComplete).toBe(true)
    expect(result.rootsAtHuman).toBe(true)
    expect(result.warrantor).toBe(KIM)
  })

  it('reports a missing parent as an unresolved hop and NEVER shortens the chain silently', async () => {
    const parent = await mintFromAsk({ scope: CAPTURE_ANY_GTIN, fromAsk: askRef('ask_1', CAPTURE_ANY_GTIN) })
    const child = unwrap(
      await svc.grant({
        tenantId: TENANT,
        subject: { kind: 'agent', id: SUPERVISOR },
        scope: CAPTURE_ANY_GTIN,
        expiresAt: IN_AN_HOUR,
        parentGrantId: parent.grant.id,
        actor: AGENT,
      }),
    )
    // The parent record is lost. A chain that stopped here and reported itself
    // whole would name SUPERVISOR as its own root.
    await storage.delete(`authority:grant:${parent.grant.id}`)

    const result = unwrap(await svc.introspect({ tenantId: TENANT, grantId: child.grant.id }))
    expect(result.chainComplete).toBe(false)
    expect(result.rootsAtHuman).toBe(false)
    const gapHop = result.chain[result.chain.length - 1]
    expect(gapHop.resolution).toBe('unresolved')
    expect(gapHop.gap).toBe('grant-missing')
    expect(gapHop.grantId).toBe(parent.grant.id)
  })

  it('reports a parent in another tenant as a gap, not as a hop it walked into', async () => {
    const parent = await mintFromAsk({ scope: CAPTURE_ANY_GTIN, fromAsk: askRef('ask_1', CAPTURE_ANY_GTIN) })
    const child = unwrap(
      await svc.grant({
        tenantId: TENANT,
        subject: { kind: 'agent', id: SUPERVISOR },
        scope: CAPTURE_ANY_GTIN,
        expiresAt: IN_AN_HOUR,
        parentGrantId: parent.grant.id,
        actor: AGENT,
      }),
    )
    const moved = await storage.get<GrantRecord>(`authority:grant:${parent.grant.id}`)
    await storage.put(`authority:grant:${parent.grant.id}`, { ...moved!, tenantId: OTHER_TENANT })

    const result = unwrap(await svc.introspect({ tenantId: TENANT, grantId: child.grant.id }))
    expect(result.chainComplete).toBe(false)
    expect(result.chain[result.chain.length - 1].gap).toBe('tenant-mismatch')
  })

  it('reports a cycle rather than looping forever', async () => {
    const a = await mintFromAsk({ scope: CAPTURE_ANY_GTIN, fromAsk: askRef('ask_1', CAPTURE_ANY_GTIN) })
    const b = unwrap(
      await svc.grant({
        tenantId: TENANT,
        subject: { kind: 'agent', id: SUPERVISOR },
        scope: CAPTURE_ANY_GTIN,
        expiresAt: IN_AN_HOUR,
        parentGrantId: a.grant.id,
        actor: AGENT,
      }),
    )
    // Only a corrupt write can produce this, which is exactly why it is tested.
    const recA = await storage.get<GrantRecord>(`authority:grant:${a.grant.id}`)
    await storage.put(`authority:grant:${a.grant.id}`, { ...recA!, parentGrantId: b.grant.id })

    const result = unwrap(await svc.introspect({ tenantId: TENANT, grantId: b.grant.id }))
    expect(result.chainComplete).toBe(false)
    expect(result.chain.some((h) => h.gap === 'cycle-detected')).toBe(true)
  })

  it('refuses a cross-tenant read as MISSING, so it confirms nothing', async () => {
    const receipt = await mintFromAsk()
    const r = await svc.introspect({ tenantId: OTHER_TENANT, grantId: receipt.grant.id })
    expect(slugOf(r)).toBe('grant-not-found')
    if (!r.success) expect(JSON.stringify(r.error.detail)).not.toContain(TENANT)
  })

  it('carries the non-retroactive disclosure verbatim on every introspection', async () => {
    const receipt = await mintFromAsk()
    const result = unwrap(await svc.introspect({ tenantId: TENANT, grantId: receipt.grant.id }))
    expect(result.revoke.disclosure).toBe(NON_RETROACTIVE_DISCLOSURE)
    expect(result.revoke.free).toBe(true)
    expect(result.revoke.seatRequired).toBe(false)
    expect(result.revoke.address).toContain(receipt.grant.id)
  })

  it('is a read: it writes no Action, so listing authority is not a ledger event', async () => {
    const receipt = await mintFromAsk()
    sink.clear()
    await svc.introspect({ tenantId: TENANT, grantId: receipt.grant.id })
    expect(sink.emitted).toHaveLength(0)
  })
})

describe('revoke: free, seatless, non-retroactive, cascading (REQ-7)', () => {
  it('is reachable by the warrantor with no seat and no session', async () => {
    const receipt = await mintFromAsk()
    const r = unwrap(await svc.revoke({ tenantId: TENANT, grantId: receipt.grant.id, actor: KIM }))
    expect(r.revokedBy).toBe(KIM)
    expect(r.cause).toBe('warrantor-revoked')
  })

  it('is reachable by the revoke address ALONE -- no actor, no key, no seat', async () => {
    const receipt = await mintFromAsk()
    const r = unwrap(
      await svc.revoke({ tenantId: TENANT, grantId: receipt.grant.id, revokeToken: receipt.revokeToken }),
    )
    expect(r.alreadyRevoked).toBe(false)
    expect(sink.byName('authority.revoke')[0].metadata!.seatless).toBe(true)
  })

  it('is reachable by the holder revoking its own authority', async () => {
    const receipt = await mintFromAsk()
    const r = unwrap(await svc.revoke({ tenantId: TENANT, grantId: receipt.grant.id, actor: AGENT }))
    expect(r.cause).toBe('holder-revoked')
  })

  it('refuses a stranger, and a stranger holding a wrong token', async () => {
    const receipt = await mintFromAsk()
    expect(slugOf(await svc.revoke({ tenantId: TENANT, grantId: receipt.grant.id, actor: DANA }))).toBe(
      'not-the-warrantor',
    )
    expect(
      slugOf(
        await svc.revoke({
          tenantId: TENANT,
          grantId: receipt.grant.id,
          actor: DANA,
          revokeToken: 'rvk_' + '0'.repeat(48),
        }),
      ),
    ).toBe('not-the-warrantor')
  })

  it('cascades to every descendant', async () => {
    const root = await mintFromAsk({ scope: EVERYTHING, fromAsk: askRef('ask_1', EVERYTHING) })
    const mid = unwrap(
      await svc.grant({
        tenantId: TENANT,
        subject: { kind: 'agent', id: SUPERVISOR },
        scope: CAPTURE_ANY_GTIN,
        expiresAt: IN_AN_HOUR,
        parentGrantId: root.grant.id,
        actor: AGENT,
      }),
    )
    const leaf = unwrap(
      await svc.grant({
        tenantId: TENANT,
        subject: { kind: 'agent', id: 'agent_leaf' },
        scope: CAPTURE_ANY_GTIN,
        expiresAt: IN_AN_HOUR,
        parentGrantId: mid.grant.id,
        actor: SUPERVISOR,
      }),
    )
    const r = unwrap(await svc.revoke({ tenantId: TENANT, grantId: root.grant.id, actor: KIM }))
    expect(r.cascaded.sort()).toEqual([mid.grant.id, leaf.grant.id].sort())
    for (const id of [root.grant.id, mid.grant.id, leaf.grant.id]) {
      const view = unwrap(await svc.introspect({ tenantId: TENANT, grantId: id }))
      expect(view.grant!.status).toBe('revoked')
    }
  })

  it('FAILS CLOSED on an unreadable descendant and writes nothing at all', async () => {
    const root = await mintFromAsk()
    // A child indexed but unreadable. Reporting the parent revoked here would
    // claim an authority was stopped while a descendant of it still stands.
    await storage.put(`authority:children:${root.grant.id}`, ['grant_ghost'])
    const r = await svc.revoke({ tenantId: TENANT, grantId: root.grant.id, actor: KIM })
    expect(slugOf(r)).toBe('revocation-incomplete')
    const after = unwrap(await svc.introspect({ tenantId: TENANT, grantId: root.grant.id }))
    expect(after.grant!.status).toBe('active')
    expect(sink.byName('authority.revoke')).toHaveLength(0)
  })

  it('is idempotent: a second revocation from another channel is not an error', async () => {
    const receipt = await mintFromAsk()
    await svc.revoke({ tenantId: TENANT, grantId: receipt.grant.id, actor: KIM })
    const second = unwrap(
      await svc.revoke({ tenantId: TENANT, grantId: receipt.grant.id, revokeToken: receipt.revokeToken }),
    )
    expect(second.alreadyRevoked).toBe(true)
    expect(sink.byName('authority.revoke')).toHaveLength(1)
  })

  it('states the non-retroactive limit verbatim on every receipt', async () => {
    const receipt = await mintFromAsk()
    expect(receipt.revoke.disclosure).toBe(NON_RETROACTIVE_DISCLOSURE)
    const r = unwrap(await svc.revoke({ tenantId: TENANT, grantId: receipt.grant.id, actor: KIM }))
    expect(r.revoke.disclosure).toBe(NON_RETROACTIVE_DISCLOSURE)
    expect(r.revoke.nonRetroactive).toBe(true)
    // The limit is a sentence, not a flag and not a tooltip.
    expect(NON_RETROACTIVE_DISCLOSURE).toContain('cannot retract what has already been read')
    expect(NON_RETROACTIVE_DISCLOSURE).toContain('free and needs no seat')
  })

  it('stops future use immediately, through the whole chain', async () => {
    const root = await mintFromAsk({ scope: CAPTURE_ANY_GTIN, fromAsk: askRef('ask_1', CAPTURE_ANY_GTIN) })
    const child = unwrap(
      await svc.grant({
        tenantId: TENANT,
        subject: { kind: 'agent', id: SUPERVISOR },
        scope: CAPTURE_ANY_GTIN,
        expiresAt: IN_AN_HOUR,
        parentGrantId: root.grant.id,
        actor: AGENT,
      }),
    )
    const before = unwrap(
      await svc.authorize({
        tenantId: TENANT,
        grantId: child.grant.id,
        verb: 'epcis.capture',
        resource: 'gtin/1',
        actor: SUPERVISOR,
      }),
    )
    expect(before.allowed).toBe(true)
    await svc.revoke({ tenantId: TENANT, grantId: root.grant.id, actor: KIM })
    const after = unwrap(
      await svc.authorize({
        tenantId: TENANT,
        grantId: child.grant.id,
        verb: 'epcis.capture',
        resource: 'gtin/1',
        actor: SUPERVISOR,
      }),
    )
    expect(after.allowed).toBe(false)
  })

  it('does not erase the record -- revocation is not deletion', async () => {
    const receipt = await mintFromAsk()
    await svc.revoke({ tenantId: TENANT, grantId: receipt.grant.id, actor: KIM })
    const after = unwrap(await svc.introspect({ tenantId: TENANT, grantId: receipt.grant.id }))
    expect(after.grant!.status).toBe('revoked')
    expect(after.grant!.revokedBy).toBe(KIM)
    expect(after.grant!.scope).toEqual(CAPTURE_GTIN)
  })
})

describe('refuse: a decline that leaves no trace is a request never seen (#358)', () => {
  it('distinguishes all four settlement states', async () => {
    // unasked
    expect(unwrap(await svc.settlement({ tenantId: TENANT, askId: 'ask_never' })).state).toBe('unasked')
    // pending
    await dispatchAsk('ask_p')
    expect(unwrap(await svc.settlement({ tenantId: TENANT, askId: 'ask_p' })).state).toBe('pending')
    // refused
    await dispatchAsk('ask_r')
    await svc.refuse({ tenantId: TENANT, askId: 'ask_r', refusedBy: KIM, cause: 'scope-too-wide' })
    expect(unwrap(await svc.settlement({ tenantId: TENANT, askId: 'ask_r' })).state).toBe('refused')
    // granted
    await mintFromAsk()
    expect(unwrap(await svc.settlement({ tenantId: TENANT, askId: 'ask_1' })).state).toBe('granted')
  })

  it('records who refused, when, and under which cause', async () => {
    await dispatchAsk()
    const r = unwrap(await svc.refuse({ tenantId: TENANT, askId: 'ask_1', refusedBy: KIM, cause: 'not-authorised' }))
    expect(r.refusal.refusedBy).toBe(KIM)
    expect(r.refusal.cause).toBe('not-authorised')
    expect(r.settlement.state).toBe('refused')
    expect(r.settlement.cause).toBe('not-authorised')
    expect(sink.byName('authority.refuse')).toHaveLength(1)
  })

  it('refuses a free-text cause -- the enum is fixed per deployment', async () => {
    await dispatchAsk()
    const r = await svc.refuse({
      tenantId: TENANT,
      askId: 'ask_1',
      refusedBy: KIM,
      cause: 'because I did not like it' as never,
    })
    expect(slugOf(r)).toBe('refusal-cause-unknown')
  })

  it('refuses a refusal recorded against an agent', async () => {
    await dispatchAsk()
    const r = await svc.refuse({ tenantId: TENANT, askId: 'ask_1', refusedBy: AGENT as never, cause: 'policy' })
    expect(slugOf(r)).toBe('not-the-warrantor')
  })

  it('refuses an unknown ask, and an ask belonging to another tenant', async () => {
    expect(slugOf(await svc.refuse({ tenantId: TENANT, askId: 'ask_ghost', refusedBy: KIM, cause: 'policy' }))).toBe(
      'ask-not-found',
    )
    await dispatchAsk('ask_other', CAPTURE_GTIN, OTHER_TENANT)
    expect(slugOf(await svc.refuse({ tenantId: TENANT, askId: 'ask_other', refusedBy: KIM, cause: 'policy' }))).toBe(
      'ask-not-found',
    )
  })

  it('BLOCKS a later grant on the same ask -- the refusal is load-bearing, not decorative', async () => {
    await dispatchAsk()
    await svc.refuse({ tenantId: TENANT, askId: 'ask_1', refusedBy: KIM, cause: 'scope-too-wide' })
    const r = await svc.grant({
      tenantId: TENANT,
      subject: { kind: 'agent', id: AGENT },
      scope: CAPTURE_GTIN,
      expiresAt: IN_A_DAY,
      fromAsk: askRef(),
      actor: KIM,
    })
    expect(slugOf(r)).toBe('ask-already-settled')
  })

  it('refuses a second refusal and names who got there first', async () => {
    await dispatchAsk()
    await svc.refuse({ tenantId: TENANT, askId: 'ask_1', refusedBy: KIM, cause: 'policy' })
    const r = await svc.refuse({ tenantId: TENANT, askId: 'ask_1', refusedBy: DANA, cause: 'policy' })
    expect(slugOf(r)).toBe('ask-already-settled')
    if (!r.success) {
      expect(r.error.detail!.settledBy).toBe(KIM)
      expect(r.error.detail!.state).toBe('refused')
    }
  })

  it('reports an UNCONFIRMED artifact rather than fabricating an event hash', async () => {
    await dispatchAsk()
    const r = unwrap(await svc.refuse({ tenantId: TENANT, askId: 'ask_1', refusedBy: KIM, cause: 'policy' }))
    expect(r.artifact.state).toBe('unconfirmed')
    expect(r.artifact.eventHash).toBeNull()
    expect(r.refusal.eventHash).toBeUndefined()
  })

  it('carries the artifact when the write door confirms it', async () => {
    const confirming = new MemoryActionSink(true)
    const s = new AuthorityServiceImpl({ storage, actions: confirming, now: () => NOW })
    await s.recordAsk({
      askId: 'ask_c',
      tenantId: TENANT,
      requestedBy: AGENT,
      onBehalfOf: KIM,
      scope: CAPTURE_GTIN,
      expiresAt: IN_AN_HOUR,
      createdAt: NOW.toISOString(),
    })
    const r = unwrap(await s.refuse({ tenantId: TENANT, askId: 'ask_c', refusedBy: KIM, cause: 'policy' }))
    expect(r.artifact.state).toBe('confirmed')
    expect(r.artifact.eventHash).toMatch(/^[0-9a-f]{64}$/)
    expect(r.refusal.eventHash).toBe(r.artifact.eventHash)
  })
})

describe('authorize: the decision call, and the denial that writes nothing', () => {
  it('allows an in-scope act and records exactly one use Action', async () => {
    const receipt = await mintFromAsk()
    sink.clear()
    const d = unwrap(
      await svc.authorize({
        tenantId: TENANT,
        grantId: receipt.grant.id,
        verb: 'epcis.capture',
        resource: 'gtin/09506000134376',
        amount: { value: 10, unit: 'events' },
        actor: AGENT,
      }),
    )
    expect(d.allowed).toBe(true)
    expect(sink.emitted.map((a) => a.action)).toEqual(['authority.use'])
  })

  it('DENIES a probe and writes NOTHING -- probing must not fill a customer ledger', async () => {
    const receipt = await mintFromAsk()
    sink.clear()
    for (let i = 0; i < 20; i++) {
      const d = unwrap(
        await svc.authorize({
          tenantId: TENANT,
          grantId: receipt.grant.id,
          verb: 'epcis.capture',
          resource: `gtin/probe-${i}`,
          amount: { value: 1, unit: 'events' },
          actor: AGENT,
        }),
      )
      expect(d.allowed).toBe(false)
      expect(d.artifact).toBeNull()
    }
    expect(sink.emitted).toHaveLength(0)
  })

  it('denies a caller that is not the holder', async () => {
    const receipt = await mintFromAsk()
    const d = unwrap(
      await svc.authorize({
        tenantId: TENANT,
        grantId: receipt.grant.id,
        verb: 'epcis.capture',
        resource: 'gtin/09506000134376',
        amount: { value: 1, unit: 'events' },
        actor: 'agent_stranger',
      }),
    )
    expect(d.allowed).toBe(false)
  })

  it('denies a child written WIDER than its parent by a bug', async () => {
    const parent = await mintFromAsk()
    // A record only a defect could produce: a child whose Scope its parent
    // never covered. The mint path refuses it; the read path must too.
    const forged: GrantRecord = {
      id: 'grant_forged',
      tenantId: TENANT,
      subject: { kind: 'agent', id: SUPERVISOR },
      warrantor: KIM,
      parentGrantId: parent.grant.id,
      scope: EVERYTHING,
      standing: false,
      narrowingAsksIncluded: false,
      expiresAt: IN_AN_HOUR,
      status: 'active',
      createdAt: NOW.toISOString(),
      revokeTokenHash: 'x'.repeat(64),
      actChain: [{ sub: SUPERVISOR, grantId: 'grant_forged' }, { sub: KIM, grantId: null }],
    }
    await storage.put('authority:grant:grant_forged', forged)
    const d = unwrap(
      await svc.authorize({
        tenantId: TENANT,
        grantId: 'grant_forged',
        verb: 'anything.at.all',
        resource: 'secrets/1',
        actor: SUPERVISOR,
      }),
    )
    expect(d.allowed).toBe(false)
  })

  it('denies when a presented act chain does not match the ledger', async () => {
    const receipt = await mintFromAsk()
    const d = unwrap(
      await svc.authorize({
        tenantId: TENANT,
        grantId: receipt.grant.id,
        verb: 'epcis.capture',
        resource: 'gtin/09506000134376',
        amount: { value: 1, unit: 'events' },
        actor: AGENT,
        presentedActClaim: { sub: DANA, act: { sub: AGENT } },
      }),
    )
    expect(d.allowed).toBe(false)
    expect(d.slug).toBe('act-chain-mismatch')
  })

  it('accepts the act chain the ledger itself would build', async () => {
    const receipt = await mintFromAsk()
    const d = unwrap(
      await svc.authorize({
        tenantId: TENANT,
        grantId: receipt.grant.id,
        verb: 'epcis.capture',
        resource: 'gtin/09506000134376',
        amount: { value: 1, unit: 'events' },
        actor: AGENT,
        presentedActClaim: receipt.actClaim,
      }),
    )
    expect(d.allowed).toBe(true)
  })

  it('denies an expired grant without any write to flip its status', async () => {
    const receipt = await mintFromAsk({ expiresAt: IN_AN_HOUR })
    const later = new AuthorityServiceImpl({
      storage,
      actions: sink,
      now: () => new Date('2026-08-05T14:00:00.000Z'),
    })
    const d = unwrap(
      await later.authorize({
        tenantId: TENANT,
        grantId: receipt.grant.id,
        verb: 'epcis.capture',
        resource: 'gtin/09506000134376',
        amount: { value: 1, unit: 'events' },
        actor: AGENT,
      }),
    )
    expect(d.allowed).toBe(false)
    expect(d.slug).toBe('grant-not-active')
  })

  it('denies a ceiling-bearing grant when the request declares no amount', async () => {
    const receipt = await mintFromAsk()
    const d = unwrap(
      await svc.authorize({
        tenantId: TENANT,
        grantId: receipt.grant.id,
        verb: 'epcis.capture',
        resource: 'gtin/09506000134376',
        actor: AGENT,
      }),
    )
    expect(d.allowed).toBe(false)
  })
})

describe('listGrants: you cannot revoke what you cannot list', () => {
  it('lists active grants and every row is revocable', async () => {
    const a = await mintFromAsk()
    await dispatchAsk('ask_2')
    const b = unwrap(
      await svc.grant({
        tenantId: TENANT,
        subject: { kind: 'agent', id: SUPERVISOR },
        scope: CAPTURE_GTIN,
        expiresAt: IN_A_DAY,
        fromAsk: askRef('ask_2'),
        actor: KIM,
      }),
    )
    const list = unwrap(await svc.listGrants({ tenantId: TENANT }))
    expect(list.grants.map((g) => g.id).sort()).toEqual([a.grant.id, b.grant.id].sort())
    for (const row of list.grants) {
      const detail = unwrap(await svc.introspect({ tenantId: TENANT, grantId: row.id }))
      expect(detail.revoke.address).toContain(row.id)
    }
    expect(list.revoke.disclosure).toBe(NON_RETROACTIVE_DISCLOSURE)
  })

  it('has no total -- a count across Actions is an aggregate this surface does not compute', async () => {
    await mintFromAsk()
    const list = unwrap(await svc.listGrants({ tenantId: TENANT }))
    expect(Object.keys(list)).toEqual(['grants', 'cursor', 'revoke', 'asOf'])
    expect(list).not.toHaveProperty('total')
  })

  it('filters to standing envelopes', async () => {
    await mintFromAsk()
    await dispatchAsk('ask_s')
    await svc.grant({
      tenantId: TENANT,
      subject: { kind: 'agent', id: SUPERVISOR },
      scope: CAPTURE_GTIN,
      expiresAt: IN_A_DAY,
      fromAsk: askRef('ask_s'),
      standing: true,
      bindsToTier: 'agentic',
      actor: KIM,
    })
    const list = unwrap(await svc.listGrants({ tenantId: TENANT, standingOnly: true }))
    expect(list.grants).toHaveLength(1)
    expect(list.grants[0].standing).toBe(true)
  })

  it('excludes revoked rows by default and includes them on request', async () => {
    const a = await mintFromAsk()
    await svc.revoke({ tenantId: TENANT, grantId: a.grant.id, actor: KIM })
    expect(unwrap(await svc.listGrants({ tenantId: TENANT })).grants).toHaveLength(0)
    const all = unwrap(await svc.listGrants({ tenantId: TENANT, includeInactive: true }))
    expect(all.grants).toHaveLength(1)
    expect(all.grants[0].status).toBe('revoked')
  })

  it('never returns another tenant s rows', async () => {
    await mintFromAsk()
    const list = unwrap(await svc.listGrants({ tenantId: OTHER_TENANT }))
    expect(list.grants).toHaveLength(0)
  })

  it('paginates with an opaque forward cursor', async () => {
    for (let i = 0; i < 5; i++) {
      await dispatchAsk(`ask_${i}`)
      await svc.grant({
        tenantId: TENANT,
        subject: { kind: 'agent', id: `agent_${i}` },
        scope: CAPTURE_GTIN,
        expiresAt: IN_A_DAY,
        fromAsk: askRef(`ask_${i}`),
        actor: KIM,
      })
    }
    const first = unwrap(await svc.listGrants({ tenantId: TENANT, limit: 2 }))
    expect(first.grants).toHaveLength(2)
    expect(first.cursor).toBeTruthy()
    expect(first.cursor).not.toContain(first.grants[1].id)

    const second = unwrap(await svc.listGrants({ tenantId: TENANT, limit: 2, cursor: first.cursor! }))
    expect(second.grants).toHaveLength(2)
    const overlap = second.grants.filter((g) => first.grants.some((f) => f.id === g.id))
    expect(overlap).toHaveLength(0)
  })

  it('lists by principal', async () => {
    const a = await mintFromAsk()
    const list = unwrap(await svc.listGrants({ tenantId: TENANT, principal: AGENT }))
    expect(list.grants.map((g) => g.id)).toEqual([a.grant.id])
    expect(unwrap(await svc.listGrants({ tenantId: TENANT, principal: DANA })).grants).toHaveLength(0)
  })
})

describe('the error slugs the cross-door registry already pinned', () => {
  // packages/shared-surface/src/errors.ts in dot-do/vis is the one registry.
  // A door may add an error; it may never re-spell a shared one. These eight
  // are copied from it by hand and this test is what catches a drift.
  const PINNED = [
    'ask-not-found',
    'ask-already-settled',
    'ask-expired',
    'not-the-warrantor',
    'chain-incomplete',
    'authz-expired',
  ]

  it('spells every pinned slug exactly as the registry spells it', () => {
    for (const slug of PINNED) {
      expect(Object.keys(AUTHORITY_SLUGS)).toContain(slug)
      expect(AUTHORITY_SLUGS[slug as keyof typeof AUTHORITY_SLUGS].registry).toBe('pinned')
    }
  })

  it('does not spell a registry slug a second way', () => {
    const forbidden = ['authorization-expired', 'unknown-view-id', 'ask_not_found', 'notTheWarrantor']
    for (const wrong of forbidden) expect(Object.keys(AUTHORITY_SLUGS)).not.toContain(wrong)
  })

  it('marks every slug the registry does not yet hold as proposed', () => {
    for (const [slug, meta] of Object.entries(AUTHORITY_SLUGS)) {
      if (PINNED.includes(slug)) continue
      expect(meta.registry, `${slug} claims to be pinned and is not in the registry`).toBe('proposed')
    }
  })

  it('pins a status and a retryable flag for every slug', () => {
    for (const [slug, meta] of Object.entries(AUTHORITY_SLUGS)) {
      expect(typeof meta.retryable, slug).toBe('boolean')
      expect(meta.status, slug).toBeGreaterThanOrEqual(400)
    }
  })
})
