/**
 * registry/memory.ts — `MemoryRegistryPort`, the seedable in-memory registry
 * fixture (mirrors `src/sdk/storage.ts` MemoryStorageAdapter).
 *
 * Backed by four Maps — one per independent-lifecycle record (identifier /
 * owner / linkset / policy, lens-A §2). `lookup` JOINS the four into a
 * `ResolvedManifest`. Models two lens-A behaviours:
 *   - policy inheritance: class → lot → instance. A key with no policyRef of its
 *     own inherits the policy of its class-grain parent key.
 *   - instance-owner shadowing: an instance-scoped OwnerRef on one `/21/{serial}`
 *     key shadows the class owner without touching the class record.
 *
 * This is the tests' registry. No live binding (RAILS). The real schema is
 * `registry/schema.sql`.
 */

import type {
  RegistryPort,
  RegistryLookup,
  IdentifierRecord,
  OwnerRef,
  Linkset,
  PolicyRef,
  ResolvedManifest,
  Grain,
} from './port'

export interface RegistrySeed {
  identifier?: IdentifierRecord[]
  owner?: OwnerRef[]
  linkset?: Linkset[]
  policy?: PolicyRef[]
}

/**
 * Derive the class-grain parent key of a DL key for policy inheritance.
 *   "01/{gtin}/21/{serial}" (instance) → "01/{gtin}" (class)
 *   "01/{gtin}/10/{lot}"    (lot)      → "01/{gtin}" (class)
 * A bare class/place/asset/document key has no parent.
 */
function classParentKey(key: string): string | null {
  const segs = key.split('/')
  // primary key + value = 2 segs (class). A qualifier adds an AI/value pair.
  if (segs.length >= 4 && segs[0] === '01') {
    return `${segs[0]}/${segs[1]}`
  }
  return null
}

export class MemoryRegistryPort implements RegistryPort {
  private identifiers = new Map<string, IdentifierRecord>()
  private owners = new Map<string, OwnerRef>()
  private linksets = new Map<string, Linkset>()
  private policies = new Map<string, PolicyRef>()

  constructor(seed?: RegistrySeed) {
    if (seed) this.seed(seed)
  }

  /** Seed (or add to) the four record stores. Idempotent per id. */
  seed(seed: RegistrySeed): this {
    for (const r of seed.identifier ?? []) this.identifiers.set(r.key, r)
    for (const o of seed.owner ?? []) this.owners.set(o.ownerId, o)
    for (const l of seed.linkset ?? []) this.linksets.set(l.id, l)
    for (const p of seed.policy ?? []) this.policies.set(p.id, p)
    return this
  }

  /**
   * Resolve the effective PolicyRef for an IdentifierRecord, honouring class →
   * lot → instance inheritance: if the record's own policyRef resolves, use it;
   * otherwise inherit from the class-grain parent key's record.
   */
  private resolvePolicy(record: IdentifierRecord): PolicyRef | undefined {
    const own = this.policies.get(record.policyRef)
    if (own) return own
    const parentKey = classParentKey(record.key)
    if (parentKey) {
      const parent = this.identifiers.get(parentKey)
      if (parent) return this.policies.get(parent.policyRef)
    }
    return undefined
  }

  /**
   * Resolve the effective OwnerRef, honouring instance-owner shadowing: the
   * record's own ownerRef (an instance-scoped OwnerRef, when present) shadows any
   * class owner. If the record's ownerRef does not itself resolve, inherit from
   * the class-grain parent.
   */
  private resolveOwner(record: IdentifierRecord): OwnerRef | undefined {
    const own = this.owners.get(record.ownerRef)
    if (own) return own
    const parentKey = classParentKey(record.key)
    if (parentKey) {
      const parent = this.identifiers.get(parentKey)
      if (parent) return this.owners.get(parent.ownerRef)
    }
    return undefined
  }

  async lookup(key: string, _grain: Grain): Promise<RegistryLookup> {
    const record = this.identifiers.get(key)
    if (!record) {
      return { found: false, reason: 'no-record', detail: `no registry record for key: ${key}` }
    }
    const owner = this.resolveOwner(record)
    const linkset = this.linksets.get(record.linksetRef)
    const policy = this.resolvePolicy(record)
    // A record whose joined refs are incomplete is treated as no-record rather
    // than a half-built manifest — existence-neutral, never fabricated.
    if (!owner || !linkset || !policy) {
      return {
        found: false,
        reason: 'no-record',
        detail: `registry record for ${key} has unresolved refs` +
          ` (owner:${!!owner} linkset:${!!linkset} policy:${!!policy})`,
      }
    }
    const manifest: ResolvedManifest = {
      key: record.key,
      grain: record.grain,
      canonicalId: record.canonicalId,
      owner,
      linkset,
      defaultLink: record.defaultLink,
      policy,
      provenance: record.provenance,
      etag: record.etag,
      updatedAt: record.updatedAt,
    }
    return { found: true, manifest }
  }
}
