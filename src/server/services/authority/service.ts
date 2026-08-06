/**
 * AuthorityServiceImpl — grant · introspect · revoke · refuse.
 *
 * Read `types.ts` first; it carries the four load-bearing properties and the
 * storage key map. This file is the enforcement.
 *
 * Two rules govern everything below and are worth stating before the code:
 *
 * **Fail closed, and say which way you failed.** Every refusal carries a slug
 * from a fixed catalogue, and the catalogue distinguishes conditions a caller
 * can act on (`scope-widens-parent`) from conditions it cannot (`grant-not-
 * found`). A cross-tenant read returns `grant-not-found` rather than a
 * forbidden — an authorization failure that confirms the existence of what it
 * protected is a disclosure.
 *
 * **A denial writes nothing.** `authorize` records an Action when it allows and
 * records NOTHING when it denies. REQ-6's argument is that an agent which
 * cannot introspect discovers its authority by probing; a service that writes a
 * denial event per probe turns that discovery into the customer's evidence
 * ledger. Introspection is the remedy. Denial noise is not.
 */

import { Ok, Err } from '../../../sdk/foundation'
import type { Result } from '../../../sdk/foundation'
import type { StorageAdapter } from '../../../sdk/storage'
import { narrows, isScope, scopeSatisfies } from '../../../sdk/auth/scope'
import type { Scope, Measure } from '../../../sdk/auth/scope'
import { MAX_CHAIN_DEPTH, envelopeFromChain, verifyActChain } from './act-chain'
import {
  AuthorityError,
  isPendingSubject,
  isRefusalCause,
  subjectId,
} from './types'
import type {
  ActClaimShape,
  ActHop,
  ActionSink,
  Artifact,
  AskRecord,
  AskSettlement,
  AuthorityAction,
  AuthorityService,
  AuthorizeDecision,
  AuthorizeInput,
  ChainHop,
  ClaimInput,
  GrantInput,
  GrantReceipt,
  GrantRecord,
  GrantView,
  IntrospectResult,
  ListGrantsInput,
  ListGrantsResult,
  RefuseInput,
  RefuseReceipt,
  RefusalRecord,
  RevokeDisclosure,
  RevokeInput,
  RevokeReceipt,
  ResolvedSubject,
  Subject,
} from './types'

// ============================================================================
// The disclosure — REQ-7
// ============================================================================

/**
 * The exact string every face renders on a settled receipt and on every
 * revocation. **It is not a tooltip, not an info icon and not a link** — a
 * limit disclosed only on hover is not disclosed, and a revocation claim
 * without this limit stated is a false claim under the estate's own claims
 * discipline.
 */
export const NON_RETROACTIVE_DISCLOSURE =
  'Revoking stops future use. It cannot retract what has already been read. ' +
  'Revoking is free and needs no seat.'

// ============================================================================
// Keys
// ============================================================================

const K = {
  grant: (id: string) => `authority:grant:${id}`,
  children: (id: string) => `authority:children:${id}`,
  held: (principal: string) => `authority:held:${principal}`,
  revokeToken: (hash: string) => `authority:revoke-token:${hash}`,
  claimToken: (hash: string) => `authority:claim-token:${hash}`,
  ask: (askId: string) => `authority:ask:${askId}`,
  settlement: (askId: string) => `authority:settlement:${askId}`,
  refusal: (id: string) => `authority:refusal:${id}`,
  grantPrefix: 'authority:grant:',
}

// ============================================================================
// Small helpers
// ============================================================================

function hex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

function randomHex(byteLength: number): string {
  const bytes = new Uint8Array(byteLength)
  crypto.getRandomValues(bytes)
  return hex(bytes)
}

async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input))
  return hex(new Uint8Array(digest))
}

/** Constant-time-ish compare over equal-length hex digests. */
function digestsEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i)
  return diff === 0
}

function isIsoInstant(v: unknown): v is string {
  if (typeof v !== 'string') return false
  const t = Date.parse(v)
  return Number.isFinite(t) && new Date(t).toISOString().slice(0, 10) === v.slice(0, 10)
}

/** A human principal. The tier exists or it does not; this is where it is checked. */
function isHumanPrincipal(p: unknown): p is string {
  return typeof p === 'string' && p.startsWith('human:') && p.length > 'human:'.length
}

/** The single per-call ceiling a grant imposes, when it imposes exactly one. */
function singleCeiling(scope: Scope): Measure | null {
  const withCeiling = scope.grants.filter((g) => g.ceiling)
  if (withCeiling.length !== 1) return null
  return withCeiling[0].ceiling ?? null
}

// ============================================================================
// Config
// ============================================================================

export interface AuthorityServiceConfig {
  storage: StorageAdapter
  /** The one write door, injected. Never called from inside a read path. */
  actions: ActionSink
  /** Origin the seatless revoke address and the claim URL are rooted at. */
  origin?: string
  /** Injectable clock. Tests pin it; production leaves it. */
  now?: () => Date
}

/**
 * An `ActionSink` that records in memory and confirms nothing. Used by tests
 * and by any deployment where the public write door is not yet reachable —
 * a receipt whose artifact is `unconfirmed` is honest; a fabricated hash is
 * not.
 */
export class MemoryActionSink implements ActionSink {
  readonly emitted: AuthorityAction[] = []
  constructor(private readonly confirm: boolean = false) {}
  async emit(action: AuthorityAction): Promise<{ eventHash?: string; confirmed: boolean }> {
    this.emitted.push(action)
    if (!this.confirm) return { confirmed: false }
    const hash = await sha256Hex(JSON.stringify(action))
    return { eventHash: hash, confirmed: true }
  }
  byName(name: AuthorityAction['action']): AuthorityAction[] {
    return this.emitted.filter((a) => a.action === name)
  }
  clear(): void {
    this.emitted.length = 0
  }
}

// ============================================================================
// Implementation
// ============================================================================

export class AuthorityServiceImpl implements AuthorityService {
  private readonly storage: StorageAdapter
  private readonly actions: ActionSink
  private readonly origin: string
  private readonly now: () => Date

  constructor(config: AuthorityServiceConfig) {
    this.storage = config.storage
    this.actions = config.actions
    this.origin = (config.origin ?? 'https://id.org.ai').replace(/\/$/, '')
    this.now = config.now ?? (() => new Date())
  }

  // ── Disclosure ───────────────────────────────────────────────────────────

  /**
   * The seatless revoke address is tenant-addressable on purpose: a caller
   * holding only the revoke secret has no session to resolve a tenant from, and
   * an address that cannot be reached without first logging in is not seatless.
   *
   * The secret is NOT composed into the address. A bearer secret in a URL leaks
   * through referrers, proxy logs and shoulder-surfing; the caller receives it
   * once, separately, and decides where to put it.
   */
  private disclosure(tenantId: string, grantId: string | null): RevokeDisclosure {
    return {
      address: grantId ? `${this.origin}/authority/revoke/${tenantId}/${grantId}` : null,
      disclosure: NON_RETROACTIVE_DISCLOSURE,
      free: true,
      seatRequired: false,
      nonRetroactive: true,
    }
  }

  // ── Reads ────────────────────────────────────────────────────────────────

  /**
   * Load a grant, tenant-checked. A record belonging to another tenant is
   * reported as MISSING, never as forbidden — confirming that a grant exists
   * in a tenant the caller cannot see is the disclosure, not the read.
   */
  private async loadGrant(tenantId: string, grantId: string): Promise<GrantRecord | null> {
    const rec = await this.storage.get<GrantRecord>(K.grant(grantId))
    if (!rec) return null
    if (rec.tenantId !== tenantId) return null
    return rec
  }

  /** Status as of NOW. Storage holds the last written status; expiry is a clock fact. */
  private effectiveStatus(rec: GrantRecord): GrantRecord['status'] {
    if (rec.status === 'revoked') return 'revoked'
    if (rec.status === 'pending') return 'pending'
    return Date.parse(rec.expiresAt) <= this.now().getTime() ? 'expired' : 'active'
  }

  private view(rec: GrantRecord): GrantView {
    return {
      id: rec.id,
      tenantId: rec.tenantId,
      subject: rec.subject,
      warrantor: rec.warrantor,
      parentGrantId: rec.parentGrantId ?? null,
      scope: rec.scope,
      standing: rec.standing,
      bindsToTier: rec.bindsToTier ?? null,
      narrowingAsksIncluded: rec.narrowingAsksIncluded,
      expiresAt: rec.expiresAt,
      status: this.effectiveStatus(rec),
      createdAt: rec.createdAt,
      askId: rec.fromAsk?.askId ?? null,
      ceiling: singleCeiling(rec.scope),
      revokedAt: rec.revokedAt ?? null,
      revokedBy: rec.revokedBy ?? null,
      revocationCause: rec.revocationCause ?? null,
      cascadedFrom: rec.cascadedFrom ?? null,
      claimUrl: rec.claim && !rec.claim.claimedAt ? rec.claim.url : null,
    }
  }

  private async appendIndex(key: string, value: string): Promise<void> {
    const list = (await this.storage.get<string[]>(key)) ?? []
    if (!list.includes(value)) list.push(value)
    await this.storage.put(key, list)
  }

  private artifactFrom(receipt: { eventHash?: string; confirmed: boolean }): Artifact {
    return receipt.confirmed && receipt.eventHash
      ? { eventHash: receipt.eventHash, state: 'confirmed' }
      : { eventHash: null, state: 'unconfirmed' }
  }

  private async emit(action: AuthorityAction): Promise<Artifact> {
    return this.artifactFrom(await this.actions.emit(action))
  }

  // ── recordAsk ────────────────────────────────────────────────────────────

  async recordAsk(input: AskRecord): Promise<Result<AskRecord, AuthorityError>> {
    if (!isScope(input.scope)) {
      return Err(new AuthorityError('malformed-scope', 'The ask carries no structurally valid Scope'))
    }
    if (!isIsoInstant(input.expiresAt)) {
      return Err(new AuthorityError('invalid-expiry', 'The ask carries no valid ISO 8601 expiry'))
    }
    const existing = await this.storage.get<AskRecord>(K.ask(input.askId))
    if (existing && existing.tenantId === input.tenantId) return Ok(existing)
    const rec: AskRecord = { ...input, createdAt: input.createdAt || this.now().toISOString() }
    await this.storage.put(K.ask(rec.askId), rec)
    await this.storage.put(K.settlement(rec.askId), {
      askId: rec.askId,
      state: 'pending',
      grantId: null,
      refusalId: null,
      settledBy: null,
      settledAt: null,
      cause: null,
    } satisfies AskSettlement)
    return Ok(rec)
  }

  // ── grant ────────────────────────────────────────────────────────────────

  /**
   * Mint a Scope.
   *
   * The origin check is first and is the one that matters: a grant with neither
   * a settled ask nor a parent is authority authored from parameters, and there
   * is no surface in this family permitted to do that. Every other check below
   * bounds a grant that has a legitimate origin.
   */
  async grant(input: GrantInput): Promise<Result<GrantReceipt, AuthorityError>> {
    const { tenantId, subject, scope, expiresAt } = input

    if (!isScope(scope)) {
      return Err(new AuthorityError('malformed-scope', 'scope is not a structurally valid Scope'))
    }
    if (!isIsoInstant(expiresAt)) {
      return Err(new AuthorityError('invalid-expiry', 'expiresAt is not a valid ISO 8601 instant'))
    }
    const nowMs = this.now().getTime()
    if (Date.parse(expiresAt) <= nowMs) {
      return Err(new AuthorityError('invalid-expiry', 'expiresAt is already in the past'))
    }

    const hasAsk = !!input.fromAsk
    const hasParent = !!input.parentGrantId
    if (hasAsk === hasParent) {
      return Err(
        new AuthorityError(
          'authority-authoring-refused',
          hasAsk
            ? 'A grant carries exactly one origin: a settled ask OR an attenuation, never both'
            : 'A grant is never authored from parameters. It is born from a concrete ask a human ' +
              'settled, or as an attenuation of a grant that already exists.',
        ),
      )
    }

    let warrantor: string
    let parent: GrantRecord | null = null
    let parentChain: ActHop[] = []

    if (input.fromAsk) {
      const ask = input.fromAsk
      if (!isHumanPrincipal(ask.settledBy)) {
        return Err(
          new AuthorityError(
            'not-the-warrantor',
            'Only a human settles an authority ask. An agent that can approve its own ask has abolished the tier.',
            { settledBy: ask.settledBy },
          ),
        )
      }
      if (!isScope(ask.askedScope)) {
        return Err(new AuthorityError('malformed-scope', 'fromAsk.askedScope is not a structurally valid Scope'))
      }
      // The envelope identity: what is minted is never wider than what was read.
      if (!narrows(scope, ask.askedScope)) {
        return Err(
          new AuthorityError('grant-widens-ask', 'The minted Scope is wider than the ask the human read', {
            askId: ask.askId,
          }),
        )
      }
      const settlement = await this.storage.get<AskSettlement>(K.settlement(ask.askId))
      if (settlement && settlement.state !== 'pending') {
        return Err(
          new AuthorityError('ask-already-settled', 'That ask was already settled through another channel', {
            askId: ask.askId,
            state: settlement.state,
            settledBy: settlement.settledBy,
            settledAt: settlement.settledAt,
          }),
        )
      }
      const askRecord = await this.storage.get<AskRecord>(K.ask(ask.askId))
      if (askRecord && askRecord.tenantId !== tenantId) {
        // Cross-tenant settlement of another tenant's ask. Report as missing.
        return Err(new AuthorityError('ask-not-found', 'No such ask in this tenant', { askId: ask.askId }))
      }
      if (askRecord && Date.parse(askRecord.expiresAt) <= nowMs) {
        return Err(new AuthorityError('ask-expired', 'The ask expired before it was settled', { askId: ask.askId }))
      }
      warrantor = input.warrantor ?? ask.settledBy
      if (warrantor !== ask.settledBy) {
        return Err(
          new AuthorityError('warrantor-mismatch', 'The warrantor of a settled ask is the human who settled it', {
            declared: input.warrantor,
            settledBy: ask.settledBy,
          }),
        )
      }
      parentChain = [{ sub: warrantor, grantId: null }]
    } else {
      parent = await this.loadGrant(tenantId, input.parentGrantId!)
      if (!parent) {
        return Err(new AuthorityError('grant-not-found', 'No such grant in this tenant', { grantId: input.parentGrantId }))
      }
      const parentStatus = this.effectiveStatus(parent)
      if (parentStatus !== 'active') {
        return Err(
          new AuthorityError('grant-not-active', `Cannot attenuate a ${parentStatus} grant`, {
            grantId: parent.id,
            status: parentStatus,
          }),
        )
      }
      // Only the parent's holder or its warrantor may attenuate it. Anyone else
      // attenuating is minting authority they were never delegated.
      const holder = subjectId(parent.subject)
      if (input.actor !== holder && input.actor !== parent.warrantor) {
        return Err(
          new AuthorityError('not-the-warrantor', 'Only the holder or the warrantor may attenuate a grant', {
            grantId: parent.id,
          }),
        )
      }
      if (!narrows(scope, parent.scope)) {
        return Err(
          new AuthorityError('scope-widens-parent', 'A delegation may only ever shrink', { grantId: parent.id }),
        )
      }
      if (Date.parse(expiresAt) > Date.parse(parent.expiresAt)) {
        return Err(
          new AuthorityError('expiry-widens-parent', 'A child grant may not outlive its parent', {
            grantId: parent.id,
            parentExpiresAt: parent.expiresAt,
          }),
        )
      }
      if (input.warrantor && input.warrantor !== parent.warrantor) {
        return Err(
          new AuthorityError('warrantor-mismatch', 'A child grant inherits its warrantor; it may not re-declare one', {
            declared: input.warrantor,
            inherited: parent.warrantor,
          }),
        )
      }
      // A standing envelope is born only from an ask a human read. An
      // attenuation minting one would create a cascade-readable envelope that
      // no human ever saw.
      if (input.standing) {
        return Err(
          new AuthorityError(
            'authority-authoring-refused',
            'A standing envelope is minted only from a concrete ask a human settled, never by attenuation',
          ),
        )
      }
      warrantor = parent.warrantor
      parentChain = parent.actChain
    }

    if (input.standing && !input.bindsToTier) {
      return Err(
        new AuthorityError(
          'authority-authoring-refused',
          'A standing envelope must name the cascade rung it binds to, or nothing can read it',
        ),
      )
    }

    // Chain depth. Checked BEFORE any write, so an over-deep delegation never
    // half-exists.
    const holderSub = subjectId(subject)
    const chain: ActHop[] = holderSub
      ? [{ sub: holderSub, grantId: 'self' }, ...parentChain]
      : [...parentChain]
    if (chain.length > MAX_CHAIN_DEPTH) {
      return Err(
        new AuthorityError('chain-depth-exceeded', `A delegation chain may not exceed ${MAX_CHAIN_DEPTH} hops`, {
          depth: chain.length,
        }),
      )
    }

    const id = `grant_${randomHex(12)}`
    const revokeToken = `rvk_${randomHex(24)}`
    const revokeTokenHash = await sha256Hex(revokeToken)
    const createdAt = this.now().toISOString()

    // The chain records THIS grant's id at hop 0 once the id exists.
    const actChain: ActHop[] = chain.map((h, i) => (i === 0 && h.grantId === 'self' ? { sub: h.sub, grantId: id } : h))

    let claimToken: string | null = null
    let claim: GrantRecord['claim']
    if (isPendingSubject(subject)) {
      // REQ-9 — the subject has never resolved. The grant is minted `pending`,
      // authorises NOTHING until claimed, and is revocable before claim.
      claimToken = `clm_${randomHex(24)}`
      const base = (input.claimUrlBase ?? `${this.origin}/authority/claim`).replace(/\/$/, '')
      claim = {
        tokenHash: await sha256Hex(claimToken),
        url: `${base}/${claimToken}`,
      }
    }

    const rec: GrantRecord = {
      id,
      tenantId,
      subject,
      warrantor,
      parentGrantId: parent?.id,
      scope,
      standing: !!input.standing,
      bindsToTier: input.bindsToTier,
      narrowingAsksIncluded: !!input.narrowingAsksIncluded,
      expiresAt,
      status: claim ? 'pending' : 'active',
      createdAt,
      fromAsk: input.fromAsk,
      claim,
      revokeTokenHash,
      actChain,
    }

    await this.storage.put(K.grant(id), rec)
    await this.storage.put(K.revokeToken(revokeTokenHash), id)
    if (claim) await this.storage.put(K.claimToken(claim.tokenHash), id)
    if (parent) await this.appendIndex(K.children(parent.id), id)
    if (holderSub) await this.appendIndex(K.held(holderSub), id)
    if (input.fromAsk) {
      await this.storage.put(K.settlement(input.fromAsk.askId), {
        askId: input.fromAsk.askId,
        state: 'granted',
        grantId: id,
        refusalId: null,
        settledBy: input.fromAsk.settledBy,
        settledAt: createdAt,
        cause: null,
      } satisfies AskSettlement)
    }

    const artifact = await this.emit({
      action: parent ? 'authority.attenuate' : 'authority.mint',
      tenantId,
      actor: input.actor,
      subject: holderSub ?? '(pending)',
      grantId: id,
      askId: input.fromAsk?.askId,
      at: createdAt,
      metadata: {
        standing: rec.standing,
        parentGrantId: parent?.id ?? null,
        expiresAt,
        pendingSubject: !!claim,
      },
    })

    return Ok({
      grant: this.view(rec),
      revokeToken,
      revoke: this.disclosure(tenantId, id),
      claimToken,
      artifact,
      actClaim: envelopeFromChain(actChain) ?? { sub: warrantor },
    })
  }

  // ── claim — REQ-9's second half ──────────────────────────────────────────

  /**
   * Bind a pending grant to a subject that has now resolved.
   *
   * The claim token is single-use and is deleted before the record is written:
   * two concurrent claims must not both succeed, and the failure mode we prefer
   * is a claim that reports failure over one that silently re-binds a grant to
   * a second person.
   */
  async claim(input: ClaimInput): Promise<Result<GrantReceipt, AuthorityError>> {
    const tokenHash = await sha256Hex(input.claimToken)
    const grantId = await this.storage.get<string>(K.claimToken(tokenHash))
    if (!grantId || grantId !== input.grantId) {
      return Err(new AuthorityError('claim-token-invalid', 'That claim token does not open this grant'))
    }
    const rec = await this.loadGrant(input.tenantId, input.grantId)
    if (!rec) return Err(new AuthorityError('grant-not-found', 'No such grant in this tenant'))
    if (!rec.claim || rec.claim.claimedAt) {
      return Err(new AuthorityError('claim-token-invalid', 'That grant has already been claimed'))
    }
    if (rec.status === 'revoked') {
      // REQ-9 — revocable BEFORE claim, and a revoked pending grant stays dead.
      return Err(new AuthorityError('grant-not-active', 'That grant was revoked before it was claimed'))
    }
    if (!digestsEqual(tokenHash, rec.claim.tokenHash)) {
      return Err(new AuthorityError('claim-token-invalid', 'That claim token does not open this grant'))
    }
    if (isPendingSubject(input.subject as Subject)) {
      return Err(new AuthorityError('subject-unclaimed', 'A claim must name a resolved subject'))
    }

    await this.storage.delete(K.claimToken(tokenHash))

    const at = this.now().toISOString()
    const subject: ResolvedSubject = input.subject
    const claimed: GrantRecord = {
      ...rec,
      subject,
      status: Date.parse(rec.expiresAt) <= this.now().getTime() ? 'expired' : 'active',
      claim: { ...rec.claim, claimedAt: at, claimedBy: subject.id },
      actChain: [{ sub: subject.id, grantId: rec.id }, ...rec.actChain],
    }
    await this.storage.put(K.grant(rec.id), claimed)
    await this.appendIndex(K.held(subject.id), rec.id)

    const artifact = await this.emit({
      action: 'authority.claim',
      tenantId: rec.tenantId,
      actor: input.actor,
      subject: subject.id,
      grantId: rec.id,
      at,
    })

    return Ok({
      grant: this.view(claimed),
      // The revoke secret was returned once, at mint. Claiming does not re-mint it.
      revokeToken: '',
      revoke: this.disclosure(rec.tenantId, rec.id),
      claimToken: null,
      artifact,
      actClaim: envelopeFromChain(claimed.actChain) ?? { sub: claimed.warrantor },
    })
  }

  // ── introspect — REQ-6 ───────────────────────────────────────────────────

  /**
   * The full chain to its human root, **with explicit gaps**.
   *
   * An unresolvable hop is RETURNED as an unresolved hop. It is never omitted
   * and the walk never stops early and reports the remainder as whole: a chain
   * that stops early and looks complete is the exact lie the four presence
   * states exist to prevent, and it is also how an agent concludes it has less
   * authority than it does and re-asks a human who already answered.
   *
   * This call returns Ok even when the chain is broken. `chainComplete: false`
   * and `rootsAtHuman: false` are the honest report; erroring instead would
   * destroy the gap information REQ-6 exists to deliver.
   */
  async introspect(input: { tenantId: string; grantId: string }): Promise<Result<IntrospectResult, AuthorityError>> {
    const rec = await this.loadGrant(input.tenantId, input.grantId)
    if (!rec) {
      return Err(new AuthorityError('grant-not-found', 'No such grant in this tenant', { grantId: input.grantId }))
    }

    const chain: ChainHop[] = []
    const seen = new Set<string>()
    let cursor: GrantRecord | null = rec
    let hop = 0
    let complete = true
    let rootsAtHuman = false

    while (cursor) {
      if (seen.has(cursor.id)) {
        chain.push({
          hop: hop++,
          principal: null,
          grantId: cursor.id,
          grantedBy: null,
          expiresAt: null,
          scope: null,
          status: null,
          resolution: 'unresolved',
          gap: 'cycle-detected',
        })
        complete = false
        break
      }
      seen.add(cursor.id)

      const holder = subjectId(cursor.subject)
      const status = this.effectiveStatus(cursor)
      chain.push({
        hop: hop++,
        principal: holder,
        grantId: cursor.id,
        grantedBy: cursor.parentGrantId ? null : cursor.warrantor,
        expiresAt: cursor.expiresAt,
        scope: cursor.scope,
        status,
        // A pending subject is a REAL gap: the hop exists, and who stands at it
        // is not yet known. Rendering it as resolved would name nobody.
        resolution: holder ? 'resolved' : 'unresolved',
        gap: holder ? null : 'subject-unclaimed',
      })
      if (!holder) complete = false

      if (hop > MAX_CHAIN_DEPTH) {
        chain.push({
          hop: hop++,
          principal: null,
          grantId: null,
          grantedBy: null,
          expiresAt: null,
          scope: null,
          status: null,
          resolution: 'unresolved',
          gap: 'depth-exceeded',
        })
        complete = false
        break
      }

      if (!cursor.parentGrantId) {
        // The root hop: the human whose authority this ultimately spends.
        const humanRoot = isHumanPrincipal(cursor.warrantor)
        chain.push({
          hop: hop++,
          principal: humanRoot ? cursor.warrantor : null,
          grantId: null,
          grantedBy: null,
          expiresAt: null,
          scope: null,
          status: null,
          resolution: humanRoot ? 'resolved' : 'unresolved',
          gap: humanRoot ? null : 'grant-missing',
        })
        rootsAtHuman = humanRoot && !!cursor.fromAsk
        if (!humanRoot) complete = false
        break
      }

      const parent: GrantRecord | undefined = await this.storage.get<GrantRecord>(K.grant(cursor.parentGrantId))
      if (!parent) {
        chain.push({
          hop: hop++,
          principal: null,
          grantId: cursor.parentGrantId,
          grantedBy: null,
          expiresAt: null,
          scope: null,
          status: null,
          resolution: 'unresolved',
          gap: 'grant-missing',
        })
        complete = false
        break
      }
      if (parent.tenantId !== cursor.tenantId) {
        chain.push({
          hop: hop++,
          principal: null,
          grantId: parent.id,
          grantedBy: null,
          expiresAt: null,
          scope: null,
          status: null,
          resolution: 'unresolved',
          gap: 'tenant-mismatch',
        })
        complete = false
        break
      }
      cursor = parent
    }

    return Ok({
      grant: this.view(rec),
      chain,
      chainComplete: complete,
      rootsAtHuman: complete && rootsAtHuman,
      warrantor: rec.warrantor,
      actClaim: envelopeFromChain(rec.actChain),
      revoke: this.disclosure(rec.tenantId, rec.id),
      asOf: this.now().toISOString(),
    })
  }

  // ── revoke — REQ-7 ───────────────────────────────────────────────────────

  /**
   * Stop a grant. **Free, seatless, non-retroactive, and it cascades.**
   *
   * Three authorised callers and no seat on any path: the warrantor, the holder
   * (self-revocation is always permitted), and anyone presenting the grant's
   * revoke secret — which is the address the warrantor was handed at mint and
   * can reach from a link with no session at all. You pay to govern at scale,
   * never to stop an agent.
   *
   * **The cascade fails closed.** Every descendant is collected first; if any
   * child id in the index has no record behind it, the whole revocation is
   * refused with `revocation-incomplete` and NOTHING is written. A parent
   * reported revoked while a descendant of it still authorises calls is worse
   * than a refusal the caller can retry.
   */
  async revoke(input: RevokeInput): Promise<Result<RevokeReceipt, AuthorityError>> {
    const rec = await this.loadGrant(input.tenantId, input.grantId)
    if (!rec) {
      return Err(new AuthorityError('grant-not-found', 'No such grant in this tenant', { grantId: input.grantId }))
    }

    let authorisedAs: string | null = null
    if (input.revokeToken) {
      const presented = await sha256Hex(input.revokeToken)
      if (digestsEqual(presented, rec.revokeTokenHash)) authorisedAs = input.actor ?? rec.warrantor
    }
    if (!authorisedAs && input.actor) {
      const holder = subjectId(rec.subject)
      if (input.actor === rec.warrantor || (holder && input.actor === holder)) authorisedAs = input.actor
    }
    if (!authorisedAs) {
      return Err(
        new AuthorityError(
          'not-the-warrantor',
          'Revocation is reachable by the warrantor, by the holder, or by the grant’s revoke address — and by nobody else',
          { grantId: rec.id },
        ),
      )
    }

    if (rec.status === 'revoked') {
      // Multi-channel delivery guarantees a second revoke arrives. It is the
      // normal case, not an error.
      return Ok({
        grantId: rec.id,
        revokedAt: rec.revokedAt!,
        revokedBy: rec.revokedBy!,
        cause: rec.revocationCause ?? 'warrantor-revoked',
        cascaded: [],
        alreadyRevoked: true,
        revoke: this.disclosure(rec.tenantId, rec.id),
        artifact: { eventHash: null, state: 'unconfirmed' },
      })
    }

    // Collect descendants BEFORE writing anything.
    const descendants: GrantRecord[] = []
    const queue = [rec.id]
    const walked = new Set<string>([rec.id])
    while (queue.length) {
      const current = queue.shift()!
      const childIds = (await this.storage.get<string[]>(K.children(current))) ?? []
      for (const childId of childIds) {
        if (walked.has(childId)) continue
        walked.add(childId)
        const child = await this.storage.get<GrantRecord>(K.grant(childId))
        if (!child) {
          return Err(
            new AuthorityError(
              'revocation-incomplete',
              'A descendant of this grant is indexed but unreadable — refusing to report a partial revocation',
              { grantId: rec.id, missingChild: childId },
            ),
          )
        }
        descendants.push(child)
        queue.push(childId)
      }
    }

    const at = this.now().toISOString()
    const cause = input.cause ?? (authorisedAs === rec.warrantor ? 'warrantor-revoked' : 'holder-revoked')

    for (const d of descendants) {
      if (d.status === 'revoked') continue
      await this.storage.put(K.grant(d.id), {
        ...d,
        status: 'revoked',
        revokedAt: at,
        revokedBy: authorisedAs,
        revocationCause: 'cascade',
        cascadedFrom: rec.id,
      } satisfies GrantRecord)
    }
    await this.storage.put(K.grant(rec.id), {
      ...rec,
      status: 'revoked',
      revokedAt: at,
      revokedBy: authorisedAs,
      revocationCause: cause,
    } satisfies GrantRecord)

    const artifact = await this.emit({
      action: 'authority.revoke',
      tenantId: rec.tenantId,
      actor: authorisedAs,
      subject: subjectId(rec.subject) ?? '(pending)',
      grantId: rec.id,
      at,
      metadata: { cause, cascaded: descendants.map((d) => d.id), seatless: !!input.revokeToken },
    })

    return Ok({
      grantId: rec.id,
      revokedAt: at,
      revokedBy: authorisedAs,
      cause,
      cascaded: descendants.map((d) => d.id),
      alreadyRevoked: false,
      revoke: this.disclosure(rec.tenantId, rec.id),
      artifact,
    })
  }

  // ── refuse — #358 ────────────────────────────────────────────────────────

  /**
   * A human read the ask and said no, and the ledger says so.
   *
   * `revoke` cannot serve here — it acts on a grant, and a refusal has no grant
   * to act on. Nor can the absence of a grant: *no answer yet* and *a human
   * read this and said no* are two different facts, and an agent that cannot
   * tell them apart retries a refusal until the SLA kills it.
   *
   * The cause is a fixed enum, never free text. A free-text field on a human
   * decision is a per-person note on an append-only ledger.
   */
  async refuse(input: RefuseInput): Promise<Result<RefuseReceipt, AuthorityError>> {
    if (!isHumanPrincipal(input.refusedBy)) {
      return Err(
        new AuthorityError(
          'not-the-warrantor',
          'Only a human settles an authority ask — a refusal recorded against an agent would claim a human read it',
          { refusedBy: input.refusedBy },
        ),
      )
    }
    if (!isRefusalCause(input.cause)) {
      return Err(
        new AuthorityError('refusal-cause-unknown', 'The refusal cause is a fixed enum, never free text', {
          cause: input.cause,
        }),
      )
    }

    const ask = await this.storage.get<AskRecord>(K.ask(input.askId))
    if (!ask || ask.tenantId !== input.tenantId) {
      return Err(new AuthorityError('ask-not-found', 'No such ask in this tenant', { askId: input.askId }))
    }
    const settlement = await this.storage.get<AskSettlement>(K.settlement(input.askId))
    if (settlement && settlement.state !== 'pending') {
      return Err(
        new AuthorityError('ask-already-settled', 'That ask was already settled through another channel', {
          askId: input.askId,
          state: settlement.state,
          settledBy: settlement.settledBy,
          settledAt: settlement.settledAt,
        }),
      )
    }

    const at = this.now().toISOString()
    const id = `rfs_${randomHex(12)}`
    const artifact = await this.emit({
      action: 'authority.refuse',
      tenantId: input.tenantId,
      actor: input.refusedBy,
      askId: input.askId,
      at,
      metadata: { cause: input.cause },
    })

    const refusal: RefusalRecord = {
      id,
      tenantId: input.tenantId,
      askId: input.askId,
      refusedBy: input.refusedBy,
      cause: input.cause,
      at,
      ...(artifact.eventHash ? { eventHash: artifact.eventHash } : {}),
    }
    const nextSettlement: AskSettlement = {
      askId: input.askId,
      state: 'refused',
      grantId: null,
      refusalId: id,
      settledBy: input.refusedBy,
      settledAt: at,
      cause: input.cause,
    }
    await this.storage.put(K.refusal(id), refusal)
    await this.storage.put(K.settlement(input.askId), nextSettlement)

    return Ok({ refusal, settlement: nextSettlement, artifact })
  }

  // ── settlement ───────────────────────────────────────────────────────────

  /**
   * Four states, four different facts. `unasked` is what an agent gets when no
   * ask by that id was ever dispatched here; it is NOT `pending`, and neither
   * is `refused`. This is the whole of #358 in one return value.
   */
  async settlement(input: { tenantId: string; askId: string }): Promise<Result<AskSettlement, AuthorityError>> {
    const ask = await this.storage.get<AskRecord>(K.ask(input.askId))
    if (!ask || ask.tenantId !== input.tenantId) {
      return Ok({
        askId: input.askId,
        state: 'unasked',
        grantId: null,
        refusalId: null,
        settledBy: null,
        settledAt: null,
        cause: null,
      })
    }
    const settlement = await this.storage.get<AskSettlement>(K.settlement(input.askId))
    return Ok(
      settlement ?? {
        askId: input.askId,
        state: 'pending',
        grantId: null,
        refusalId: null,
        settledBy: null,
        settledAt: null,
        cause: null,
      },
    )
  }

  // ── listGrants — you cannot revoke what you cannot list ──────────────────

  /**
   * REQ-6's other half. **Every row this returns is revocable** — including
   * rows minted before this session and rows minted through a channel this
   * device never saw. A grant that appears in a list without a revoke address
   * is a bug of the same class as a grant that cannot be listed at all.
   *
   * Cursor-paginated, opaque forward cursor, **no totals** — a count across
   * Actions is an aggregate this surface is not permitted to compute.
   */
  async listGrants(input: ListGrantsInput): Promise<Result<ListGrantsResult, AuthorityError>> {
    const limit = Math.min(Math.max(input.limit ?? 50, 1), 200)
    let ids: string[]

    if (input.principal) {
      ids = (await this.storage.get<string[]>(K.held(input.principal))) ?? []
      ids.sort()
    } else {
      const entries = await this.storage.list<GrantRecord>({ prefix: K.grantPrefix })
      ids = Array.from(entries.keys())
        .map((k) => k.slice(K.grantPrefix.length))
        .sort()
    }

    const start = input.cursor ? decodeCursor(input.cursor) : null
    const out: GrantView[] = []
    let next: string | null = null

    for (const id of ids) {
      if (start !== null && id <= start) continue
      const rec = await this.loadGrant(input.tenantId, id)
      if (!rec) continue
      const status = this.effectiveStatus(rec)
      if (!input.includeInactive && status !== 'active' && status !== 'pending') continue
      if (input.standingOnly && !rec.standing) continue
      if (out.length === limit) {
        next = encodeCursor(out[out.length - 1].id)
        break
      }
      out.push(this.view(rec))
    }

    return Ok({
      grants: out,
      cursor: next,
      revoke: this.disclosure(input.tenantId, null),
      asOf: this.now().toISOString(),
    })
  }

  // ── authorize — the decision call ────────────────────────────────────────

  /**
   * Allow or deny one act under one grant.
   *
   * Two properties worth reading twice:
   *
   * **Every ancestor is re-checked.** The grant's own Scope satisfying the
   * request is not enough: every hop up the chain must satisfy it too, and
   * every hop must still be active. Revocation kills access instantly means
   * instantly through the chain — a child that a cascade has not yet reached,
   * or a child written wider than its parent by a bug, is refused here.
   *
   * **A denial writes nothing.** See the file header.
   */
  async authorize(input: AuthorizeInput): Promise<Result<AuthorizeDecision, AuthorityError>> {
    const rec = await this.loadGrant(input.tenantId, input.grantId)
    if (!rec) {
      return Err(new AuthorityError('grant-not-found', 'No such grant in this tenant', { grantId: input.grantId }))
    }

    const deny = (reason: string, slug: AuthorizeDecision['slug']): Result<AuthorizeDecision, AuthorityError> =>
      Ok({ allowed: false, grantId: rec.id, reason, slug, artifact: null })

    const status = this.effectiveStatus(rec)
    if (status === 'pending') {
      return deny('The subject of this grant has never resolved; a pending grant authorises nothing', 'subject-unclaimed')
    }
    if (status !== 'active') {
      return deny(`The grant is ${status}`, 'grant-not-active')
    }

    const holder = subjectId(rec.subject)
    if (holder && input.actor !== holder) {
      return deny('The caller is not the holder of this grant', 'not-the-warrantor')
    }

    if (input.presentedActClaim !== undefined) {
      const verdict = verifyActChain(input.presentedActClaim, rec.actChain)
      if (!verdict.ok) {
        return deny(`The presented act chain does not match the ledger (${verdict.reason} at hop ${verdict.at})`, 'act-chain-mismatch')
      }
    }

    // Walk up. Every hop must be active AND must itself satisfy the request.
    const required = { verb: input.verb, resource: input.resource, amount: input.amount }
    let cursor: GrantRecord | null = rec
    const seen = new Set<string>()
    let depth = 0
    while (cursor) {
      if (seen.has(cursor.id)) return deny('The authority chain contains a cycle', 'chain-incomplete')
      seen.add(cursor.id)
      if (++depth > MAX_CHAIN_DEPTH) return deny('The authority chain is too deep to verify', 'chain-depth-exceeded')
      if (this.effectiveStatus(cursor) !== 'active') {
        return deny(`An ancestor grant is ${this.effectiveStatus(cursor)}`, 'grant-not-active')
      }
      if (!scopeCovers(cursor.scope, required)) {
        return deny('No grant in the chain covers that verb, resource and amount', 'not-the-warrantor')
      }
      if (!cursor.parentGrantId) break
      const parent: GrantRecord | undefined = await this.storage.get<GrantRecord>(K.grant(cursor.parentGrantId))
      if (!parent || parent.tenantId !== cursor.tenantId) {
        return deny('The authority chain does not resolve to its human root', 'chain-incomplete')
      }
      cursor = parent
    }

    const at = this.now().toISOString()
    const artifact = await this.emit({
      action: 'authority.use',
      tenantId: rec.tenantId,
      actor: input.actor,
      subject: holder ?? '(pending)',
      grantId: rec.id,
      at,
      metadata: { verb: input.verb, resource: input.resource, amount: input.amount ?? null },
    })

    return Ok({ allowed: true, grantId: rec.id, reason: null, slug: null, artifact })
  }
}

// ============================================================================
// Cursor + scope helpers
// ============================================================================

/** Opaque forward cursor. Opaque because a client that parses it depends on it. */
function encodeCursor(id: string): string {
  return btoa(`authority:${id}`).replace(/=+$/, '')
}

function decodeCursor(cursor: string): string | null {
  try {
    const decoded = atob(cursor.padEnd(Math.ceil(cursor.length / 4) * 4, '='))
    return decoded.startsWith('authority:') ? decoded.slice('authority:'.length) : null
  } catch {
    return null
  }
}

/**
 * Test one hop's Scope against a concrete requirement. Delegates to the shared
 * `scopeSatisfies` predicate rather than restating its glob, ceiling and
 * path-traversal rules — a second implementation of those is a second set of
 * bugs.
 */
function scopeCovers(scope: Scope, required: { verb: string; resource: string; amount?: Measure }): boolean {
  return scopeSatisfies(scope, required)
}
