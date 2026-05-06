# Tenant/Agent Schema Split — Design Spec

> **Status:** Design — for review. **Issue:** id-ax7. **Date:** 2026-05-05.
>
> Greenfield migration: ~5 users, no production load, no migration burden.
> Pick the cleanest target shape; do not carry compat scaffolding.

## Background

id.org.ai today uses a flat `IdentityType = 'human' | 'agent' | 'service'`. The
`'agent'` type covers what AAP (Agent Auth Protocol v1.0) calls a **Host** — the
persistent claim-by-commit principal that owns Ed25519 keypairs. AAP further
distinguishes a per-session **Agent** under each host, which today we represent
loosely as `agent_keys` records hanging off an Identity.

This spec promotes that distinction to first-class.

### Naming reservation

`host` is reserved in id.org.ai for "custom domain hostname" — Cloudflare custom
domains managed per customer. AAP's protocol-level `Host` therefore translates
to **`Tenant`** in our internal vocabulary. The translation happens only at the
AAP wire surface (`/agent/*` routes, `host+jwt` typ header, well-known doc).

| AAP wire | id.org.ai code |
|---|---|
| User | `Identity{type:'human'}` |
| Host | `Identity{type:'tenant'}` |
| Agent | `Agent` (new first-class entity) |
| Service | `Identity{type:'service'}` (id.org.ai-only) |

## Decisions (D1–D10, locked)

| # | Question | Decision |
|---|---|---|
| D1 | How does today's `agent_keys` map to AAP? | Promote to first-class `Agent` entity under a Tenant. Rename `IdentityType='agent'` → `'tenant'`. |
| D2 | Naming for AAP's `Host`? | **`Tenant`** — `host` is reserved for custom domain hostnames. Translation at AAP wire surface only. |
| D3 | Who owns entity data (`mcpDo` `owner`)? | Tenant. Sibling agents share their tenant's entity store. |
| D4 | Audit `actor` shape? | `actor: string` stays. Add `tenantId?: string` peer field on AuditEvent. AAP `cnf.jkt` lands as a third peer field when DPoP arrives. |
| D5 | Rate-limit subject? | Per-agent for v1. Per-tenant cap as v2 follow-up (separate issue). |
| D6 | Migration approach? | Greenfield: wipe existing `type='agent'` rows or hand-fix the ~5 users. No dual-shape compat code. |
| D7 | Claim continuity vs AAP-strict? | Default: continuity (id.org.ai differentiator). Tenants may opt into AAP-strict via `mode: 'autonomous'` + `strict: true` at provision/register time. |
| D8 | Token plurality? | Keep `oai_*` / `hly_sk_*` as bearer credential shape; internally translate to ephemeral `agent+jwt` after credential extraction. One downstream authz path. Direct `agent+jwt` also accepted for AAP-native callers. |
| D9 | Service identities? | Unchanged. Outside AAP wire surface. |
| D10 | FGA relationship? | id.org.ai owns the principal model in DO SQLite. Project tuples into WorkOS FGA for authz checks. Replaces `LEVEL_SCOPES`. Future consumers can swap FGA backends. |
| Vault | `key_context` granularity? | Tenant-keyed. Agents inherit access to their tenant's secrets. |

## Schema changes

### `IdentityType` rename

```diff
- export type IdentityType = 'human' | 'agent' | 'service'
+ export type IdentityType = 'human' | 'tenant' | 'service'
```

`Identity` shape is otherwise unchanged. Tenants keep `claimToken`,
`claimStatus`, `level`, `frozen`, etc.

### New `Agent` entity

```ts
export type AgentStatus =
  | 'pending'    // awaiting approval (delegated mode only)
  | 'active'     // operational
  | 'expired'    // session/max-lifetime elapsed; reactivable
  | 'revoked'    // permanent — cannot reactivate
  | 'rejected'   // user denied registration
  | 'claimed'    // autonomous agent terminal state (AAP-strict mode only)

export type AgentMode = 'delegated' | 'autonomous'

export interface Agent {
  id: string                  // 'agent_*' prefix
  tenantId: string            // FK → Identity{type:'tenant'}
  name: string
  publicKey: string           // JWK, Ed25519, kty='OKP', crv='Ed25519'
  jwksUrl?: string            // optional; alternative to inline publicKey
  status: AgentStatus
  mode: AgentMode
  capabilities: string[]      // grant names (FGA tuples projected from these)
  createdAt: number
  activatedAt?: number
  expiresAt?: number
  lastUsedAt?: number
  revokedAt?: number
  // AAP lifecycle clocks
  sessionTtlMs: number        // measured from lastUsedAt; → 'expired' if idle
  maxLifetimeMs: number       // measured from activatedAt; → 'expired' if exceeded
  absoluteLifetimeMs: number  // measured from createdAt; → 'revoked' if exceeded
}
```

Storage keys (per Tenant DO):

```
identity:{id}                  → Identity{type:'tenant'|'human'|'service'}
agent:{id}                     → Agent
agent-by-tenant:{tenantId}     → string[]                   // agent IDs for a tenant
agent-by-pubkey:{thumbprint}   → agent ID                   // JWK thumbprint reverse index
idx:claimtoken:{token}         → tenant ID                  // unchanged
idx:github:{userId}            → identity ID                // unchanged
```

### `agent_keys` removal

The `AgentKeyRecord` / `agentkey:{id}` / `agentkey-did:{did}` / `agentkeys:{identityId}`
storage and the `AgentKeyService` interface are deleted. The AAP `/agent/register`
endpoint is the new ingress for keypair registration; the new `Agent` row carries
the public key directly.

DID format `did:agent:ed25519:{base58pubkey}` is no longer the primary identifier
— Agent ID is. The DID can be computed on demand from `publicKey` if needed for
backward compat or external systems.

### `LEVEL_SCOPES` removal (deferred to id-lkj)

Within id-ax7 we keep `LEVEL_SCOPES` operational. id-lkj migrates authz to FGA
tuple checks. The schema is FGA-ready: `Agent.capabilities` is a list of grant
names that will project to FGA tuples.

### AuditEvent shape change

```diff
  export interface AuditEvent {
    event: string
    actor?: string
+   tenantId?: string         // NEW — set on tenant-scoped events
    target?: string
    ip?: string
    userAgent?: string
    metadata?: Record<string, unknown>
    timestamp: string
  }
```

Going forward, `actor` is one of:
- `'system'`, `'anonymous'`, `'webhook:github'` (string literals for non-principal events)
- `agent_*` (when an Agent did the action)
- `tenant_*` (when a tenant-level action happened, e.g., claim completion)
- `user_*` (when a human did the action via session/JWT)

`tenantId` is set whenever the event is tenant-scoped — `entity.create`,
`agent.registered`, `claim.completed`, etc.

### `IdentityType` callers — knock-on edits

Search-and-replace targets (greenfield, no compat needed):

```
src/sdk/types.ts                          IdentityType union, Identity.type
src/server/services/identity/types.ts     same
src/server/services/identity/service.ts   create() default-type handling
src/server/do/Identity.ts                 createIdentity('agent') → 'tenant',
                                          provisionAnonymous() → tenant
src/sdk/mcp/auth.ts                       no change (operates on Identity, not type)
test/identity-do.test.ts                  fixtures: 'agent' → 'tenant'
test/identity-service.test.ts             same
test/auth-service.test.ts                 same
worker/routes/auth.ts                     workos-callback creates 'human' identity (unchanged)
worker/routes/claim.ts                    claim() updates type='tenant' (was 'agent')
```

### RPC surface additions

`IdentityStub` (in `src/sdk/types.ts`) adds:

```ts
// Agents (AAP-aligned)
registerAgent(input: { tenantId: string; name: string; publicKey: string; mode: AgentMode; capabilities?: string[]; strict?: boolean }): Promise<Result<{ agent: Agent; status: AgentStatus }, ValidationError | ConflictError | NotFoundError>>
getAgent(id: string): Promise<Agent | null>
listAgents(tenantId: string): Promise<Agent[]>
updateAgentStatus(id: string, status: AgentStatus, reason?: string): Promise<Result<Agent, NotFoundError | ValidationError>>
revokeAgent(id: string): Promise<Result<Agent, NotFoundError>>
reactivateAgent(id: string): Promise<Result<Agent, NotFoundError | ValidationError>>
verifyAgentJWT(jwt: string): Promise<Result<{ agentId: string; tenantId: string; claims: Record<string, unknown> }, AuthError>>
```

The legacy `registerAgentKey` / `verifyAgentSignature` / `listAgentKeys` /
`revokeAgentKey` RPCs are deleted.

### Token shape (D8 implementation note)

`AuthBroker.identify(req)` flow:

1. **Bearer `oai_*` / `hly_sk_*`:** look up agent → if active, return
   `Identity{type:'agent', id: agentId, tenantId, scopes: agent.capabilities}`.
2. **Bearer `agent+jwt` (AAP):** verify signature against agent's stored
   public key → return same Identity shape.
3. **Bearer JWT (OAuth):** verify against signing keys → return
   `Identity{type:'human'|'tenant', id: sub, ...}` per claim.
4. **Cookie / `ses_*`:** unchanged.

`Identity` for an authenticated agent now carries a `tenantId` field — this is
the new bit. Sibling code uses it to scope entity ops, audit, FGA checks.

```diff
  export interface Identity {
    id: string                // 'agent_*' for agents, 'tenant_*' for tenants, ...
    type: IdentityType
    name: string
+   tenantId?: string         // set when type='agent'; the parent tenant
    ...
  }
```

## Out of scope for id-ax7

- AAP wire surface (`/agent/*`, `/.well-known/agent-configuration`) — that's id-9s0
- FGA tuple projection from `Agent.capabilities` — that's id-lkj
- Vault tenant-keyed secret API — that's id-z7d
- DPoP / mTLS (`cnf.jkt` audit field) — separate issue, post-AAP-wire
- Per-tenant rate-limit cap (D5 v2) — separate issue
- Session-TTL + max-lifetime + absolute-lifetime expiry enforcement — id-ax7 stores
  the fields; lifecycle ticking lives in id-9s0

## Implementation phases

1. **Types + Drizzle schema** — `Agent` entity, `IdentityType` rename, `AuditEvent.tenantId`,
   `Identity.tenantId` (only on agent identities — see "Open question" below)
2. **Storage migration** — wipe existing `type='agent'` rows in pre-launch DOs, or hand-fix
3. **AgentService** — new `services/agents/` directory; `register`/`get`/`list`/`updateStatus`/`revoke`/`reactivate`/`verifyJWT`
4. **AuthBroker rewire** — `oai_*`/`hly_sk_*` lookup goes via Agent table; bearer JWT path adds AAP `agent+jwt` handling
5. **Identity surface cleanup** — remove old `agent_keys` paths, RPCs, KeyService.agentKeys subservice
6. **Audit wiring** — set `tenantId` on entity events, agent events, claim events
7. **Tests** — update fixtures, add Agent service tests, broker tests for the new paths

## Resolved questions

1. **`Identity.tenantId` placement: runtime synthesis only.** Agents do not have
   `Identity` rows in storage. The `Agent` table is their home. `AuthBroker`
   synthesizes an `Identity` shape on demand from an `Agent` row + the parent
   `Tenant` row, populating `tenantId` from the `Agent.tenantId` foreign key.
   Downstream code consumes the runtime `Identity` and never queries an
   `identity:agent_*` storage key.

2. **Agents and Identities are separate tables.** `Identity` is reserved for
   state-owning principals (human, tenant, service). `Agent` is a runtime actor
   under a Tenant with its own lifecycle. They share neither storage namespace
   nor secondary-index code paths. `AuthBroker` returns an `Identity` shape
   regardless of whether the underlying row was a stored Identity or a
   synthesized-from-Agent record, so downstream consumers stay polymorphic.

3. **`mcpDo` switches data-ownership key from `identityId` to `tenantId`.**
   ```diff
   - const owner = params.identityId ?? 'global'
   + const owner = params.tenantId ?? 'global'
   ```
   Audit `actor` for entity events becomes the agent ID; `tenantId` peer field
   is set to the parent. `MCPAuth.fromIdentity` returns `identityId =` agent
   ID for agent callers, with the new `tenantId` field on `Identity` carrying
   the parent. Sibling agents under one tenant see one shared entity store.

4. **`provisionAgent` renamed to `provisionTenant`.** The "provision an
   anonymous agent" flow has always been "provision a Tenant." Greenfield —
   no compat cost. Renames:
   - `IdentityWriter.provisionAgent` → `IdentityWriter.provisionTenant`
   - `ProvisionAgentInput` → `ProvisionTenantInput`
   - `ProvisionAgentResult` → `ProvisionTenantResult`
   - `IdentityDO.provisionAnonymous` keeps its name (the worker route's terms
     stay agent-flavored externally; only the service surface renames).

## Test impact

- `test/identity-service.test.ts` — fixtures use `type: 'tenant'` instead of `'agent'`
- `test/identity-do.test.ts` — same
- `test/keys-service.test.ts` — agent-keys section deleted; new `test/agents-service.test.ts` covers the AAP-aligned API
- `test/mcp-auth.test.ts` — bearer `oai_*` flow now goes through Agent table
- `test/auth-broker.test.ts` — adds `agent+jwt` case
- New: `test/agents-service.test.ts`, `test/agent-jwt-verify.test.ts`

Net test delta: +400 LOC roughly, -200 LOC (agent-keys section).

## Estimated work

3-5 days of execution. Schema + AgentService is most of it; AuthBroker rewire
and test updates are the rest. No deployment regression (greenfield).
