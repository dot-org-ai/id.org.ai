# id.org.ai Storage Abstraction & SDK/Server Separation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Introduce a portable `StorageAdapter` interface to decouple services from `DurableObjectStorage`, then reorganize `src/` into `sdk/` and `server/` directories with clean export boundaries.

**Architecture:** Define a `StorageAdapter` interface matching the subset of `DurableObjectStorage` that services use (get/put/delete/list). Provide `DurableObjectStorageAdapter` for production and `MemoryStorageAdapter` for tests. Move portable code to `src/sdk/`, Cloudflare-specific code to `src/server/`. Existing import paths stay working via compatibility shims.

**Tech Stack:** TypeScript, Vitest, Cloudflare Workers (Durable Objects), tsup

**Design Spec:** `docs/specs/2026-04-14-sdk-server-separation-design.md`

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `src/storage.ts` | **Create** | `StorageAdapter` interface + `MemoryStorageAdapter` (test impl) |
| `src/server/storage.ts` | **Create** (Phase 2) | `DurableObjectStorageAdapter` |
| `src/services/keys/api-keys.ts` | Modify | Change `DurableObjectStorage` → `StorageAdapter` |
| `src/services/keys/agent-keys.ts` | Modify | Change `DurableObjectStorage` → `StorageAdapter` |
| `src/services/keys/rate-limit.ts` | Modify | Change `DurableObjectStorage` → `StorageAdapter` |
| `src/services/keys/service.ts` | Modify | Change `DurableObjectStorage` → `StorageAdapter` |
| `src/services/audit/service.ts` | Modify | Change `AuditLog` constructor dep |
| `src/services/entity-store/service.ts` | Modify | Change `DurableObjectStorage` → `StorageAdapter` |
| `src/services/identity/service.ts` | Modify | Change `DurableObjectStorage` → `StorageAdapter` |
| `src/services/auth/service.ts` | Modify | Change `DurableObjectStorage` → `StorageAdapter` |
| `src/services/oauth/service.ts` | Modify | Change `DurableObjectStorage` → `StorageAdapter`, remove `buildStorageBridge()` |
| `src/audit/index.ts` | Modify | Change `AuditLog` constructor `DurableObjectStorage` → `StorageAdapter` |
| `src/do/Identity.ts` | Modify | Wrap `ctx.storage` in `DurableObjectStorageAdapter`, pass to services |
| `test/keys-service.test.ts` | Modify | Replace `createMockStorage()` with `MemoryStorageAdapter` |
| `test/identity-service.test.ts` | Modify | Replace mock with `MemoryStorageAdapter` |
| `test/audit-service.test.ts` | Modify | Replace mock with `MemoryStorageAdapter` |
| `test/entity-store-service.test.ts` | Modify | Replace mock with `MemoryStorageAdapter` |
| `test/session-service.test.ts` | Modify | Replace mock with `MemoryStorageAdapter` |
| `test/storage-adapter.test.ts` | **Create** | Unit tests for `MemoryStorageAdapter` |

---

## Phase 1: Storage Abstraction

### Task 1: Create StorageAdapter interface and MemoryStorageAdapter

**Files:**
- Create: `src/storage.ts`
- Create: `test/storage-adapter.test.ts`

- [x] **Step 1: Write the test file**

```typescript
// test/storage-adapter.test.ts
import { describe, it, expect, beforeEach } from 'vitest'
import { MemoryStorageAdapter } from '../src/storage'

describe('MemoryStorageAdapter', () => {
  let storage: MemoryStorageAdapter

  beforeEach(() => {
    storage = new MemoryStorageAdapter()
  })

  it('get returns undefined for missing key', async () => {
    expect(await storage.get('nope')).toBeUndefined()
  })

  it('put then get returns value', async () => {
    await storage.put('k', { name: 'test' })
    expect(await storage.get('k')).toEqual({ name: 'test' })
  })

  it('delete returns true for existing key', async () => {
    await storage.put('k', 'v')
    expect(await storage.delete('k')).toBe(true)
    expect(await storage.get('k')).toBeUndefined()
  })

  it('delete returns false for missing key', async () => {
    expect(await storage.delete('nope')).toBe(false)
  })

  it('list with prefix filters keys', async () => {
    await storage.put('user:1', { id: '1' })
    await storage.put('user:2', { id: '2' })
    await storage.put('session:1', { id: 's1' })

    const result = await storage.list({ prefix: 'user:' })
    expect(result.size).toBe(2)
    expect(result.has('user:1')).toBe(true)
    expect(result.has('session:1')).toBe(false)
  })

  it('list with limit caps results', async () => {
    await storage.put('a:1', 1)
    await storage.put('a:2', 2)
    await storage.put('a:3', 3)

    const result = await storage.list({ prefix: 'a:', limit: 2 })
    expect(result.size).toBe(2)
  })

  it('list with reverse returns keys in reverse order', async () => {
    await storage.put('a:1', 1)
    await storage.put('a:2', 2)
    await storage.put('a:3', 3)

    const result = await storage.list({ prefix: 'a:', reverse: true })
    const keys = [...result.keys()]
    expect(keys).toEqual(['a:3', 'a:2', 'a:1'])
  })

  it('list with start skips keys before start', async () => {
    await storage.put('a:1', 1)
    await storage.put('a:2', 2)
    await storage.put('a:3', 3)

    const result = await storage.list({ prefix: 'a:', start: 'a:2' })
    expect(result.has('a:1')).toBe(false)
    expect(result.has('a:2')).toBe(false)
    expect(result.has('a:3')).toBe(true)
  })
})
```

- [x] **Step 2: Run test to verify it fails**

Run: `pnpm vitest run test/storage-adapter.test.ts`
Expected: FAIL — cannot resolve `../src/storage`

- [x] **Step 3: Create the StorageAdapter interface and MemoryStorageAdapter**

```typescript
// src/storage.ts

/**
 * Portable key-value storage interface.
 *
 * Mirrors the subset of DurableObjectStorage that id.org.ai services use.
 * This is the same shape that OAuthProvider already accepts (see worker/routes/oauth.ts).
 *
 * Implementations:
 *   - MemoryStorageAdapter (tests, in this file)
 *   - DurableObjectStorageAdapter (production, in server/storage.ts)
 */
export interface StorageAdapter {
  get<T = unknown>(key: string): Promise<T | undefined>
  put(key: string, value: unknown, options?: { expirationTtl?: number }): Promise<void>
  delete(key: string): Promise<boolean>
  list<T = unknown>(options?: {
    prefix?: string
    limit?: number
    start?: string
    reverse?: boolean
  }): Promise<Map<string, T>>
}

/**
 * In-memory StorageAdapter for tests.
 * Replaces the createMockStorage() pattern used across test files.
 */
export class MemoryStorageAdapter implements StorageAdapter {
  private data = new Map<string, unknown>()

  async get<T = unknown>(key: string): Promise<T | undefined> {
    return this.data.get(key) as T | undefined
  }

  async put(key: string, value: unknown): Promise<void> {
    this.data.set(key, value)
  }

  async delete(key: string): Promise<boolean> {
    return this.data.delete(key)
  }

  async list<T = unknown>(options?: {
    prefix?: string
    limit?: number
    start?: string
    reverse?: boolean
  }): Promise<Map<string, T>> {
    const prefix = options?.prefix ?? ''
    let entries: [string, unknown][] = []

    for (const [k, v] of this.data) {
      if (k.startsWith(prefix)) {
        if (options?.start && k <= options.start) continue
        entries.push([k, v])
      }
    }

    // Sort lexicographically (matches DO storage behavior)
    entries.sort((a, b) => a[0].localeCompare(b[0]))

    if (options?.reverse) entries.reverse()
    if (options?.limit) entries = entries.slice(0, options.limit)

    return new Map(entries) as Map<string, T>
  }
}
```

- [x] **Step 4: Run test to verify it passes**

Run: `pnpm vitest run test/storage-adapter.test.ts`
Expected: All 7 tests PASS

- [x] **Step 5: Commit**

```bash
git add src/storage.ts test/storage-adapter.test.ts
git commit -m "feat: add StorageAdapter interface and MemoryStorageAdapter"
```

---

### Task 2: Migrate AuditLog to StorageAdapter

**Files:**
- Modify: `src/audit/index.ts`
- Modify: `test/audit.test.ts`

- [x] **Step 1: Update AuditLog constructor**

In `src/audit/index.ts`, change the constructor and private field:

Replace:
```typescript
export class AuditLog {
  private storage: DurableObjectStorage

  constructor(storage: DurableObjectStorage) {
    this.storage = storage
  }
```

With:
```typescript
import type { StorageAdapter } from '../storage'

export class AuditLog {
  private storage: StorageAdapter

  constructor(storage: StorageAdapter) {
    this.storage = storage
  }
```

Also add the import at the top of the file (after existing imports).

- [x] **Step 2: Update AuditLog.query() list call**

The `list()` call on line ~195 passes `reverse: true`. Verify the `StorageAdapter` interface supports this (it does — we defined it in Task 1). No code change needed.

- [x] **Step 3: Update test to use MemoryStorageAdapter**

In `test/audit.test.ts`, find the mock storage creation and replace with:

```typescript
import { MemoryStorageAdapter } from '../src/storage'
```

Replace `createMockStorage()` or the `DurableObjectStorage` mock with `new MemoryStorageAdapter()`.

- [x] **Step 4: Run tests**

Run: `pnpm vitest run test/audit.test.ts test/audit-service.test.ts`
Expected: PASS

- [x] **Step 5: Commit**

```bash
git add src/audit/index.ts test/audit.test.ts
git commit -m "refactor: migrate AuditLog to StorageAdapter interface"
```

---

### Task 3: Migrate AuditServiceImpl to StorageAdapter

**Files:**
- Modify: `src/services/audit/service.ts`
- Modify: `test/audit-service.test.ts`

- [x] **Step 1: Update AuditServiceImpl**

`AuditServiceImpl` wraps `AuditLog`. It constructs `AuditLog` internally. Since `AuditLog` now accepts `StorageAdapter`, `AuditServiceImpl` doesn't directly hold storage — it delegates to `AuditLog`. Check if `AuditServiceImpl` has its own `storage` field.

From what we read: `AuditServiceImpl` creates an `AuditLog` in its constructor. The `AuditLog` constructor was the one taking `DurableObjectStorage`. Since we changed `AuditLog` in Task 2, `AuditServiceImpl` should already work if it passes storage through to `AuditLog`. Verify by checking the constructor and updating the type annotation if it explicitly types the param as `DurableObjectStorage`.

- [x] **Step 2: Update test to use MemoryStorageAdapter**

In `test/audit-service.test.ts`, replace mock storage with `new MemoryStorageAdapter()`.

- [x] **Step 3: Run tests**

Run: `pnpm vitest run test/audit-service.test.ts`
Expected: PASS

- [x] **Step 4: Commit**

```bash
git add src/services/audit/service.ts test/audit-service.test.ts
git commit -m "refactor: migrate AuditServiceImpl to StorageAdapter"
```

---

### Task 4: Migrate EntityStoreServiceImpl to StorageAdapter

**Files:**
- Modify: `src/services/entity-store/service.ts`
- Modify: `test/entity-store-service.test.ts`

- [x] **Step 1: Update EntityStoreServiceImpl constructor**

In `src/services/entity-store/service.ts`, change:

```typescript
export class EntityStoreServiceImpl implements EntityStoreService {
  private readonly storage: DurableObjectStorage

  constructor(deps: { storage: DurableObjectStorage }) {
    this.storage = deps.storage
  }
```

To:

```typescript
import type { StorageAdapter } from '../../storage'

export class EntityStoreServiceImpl implements EntityStoreService {
  private readonly storage: StorageAdapter

  constructor(deps: { storage: StorageAdapter }) {
    this.storage = deps.storage
  }
```

- [x] **Step 2: Update test to use MemoryStorageAdapter**

In `test/entity-store-service.test.ts`, replace mock storage with `new MemoryStorageAdapter()`.

- [x] **Step 3: Run tests**

Run: `pnpm vitest run test/entity-store-service.test.ts`
Expected: PASS

- [x] **Step 4: Commit**

```bash
git add src/services/entity-store/service.ts test/entity-store-service.test.ts
git commit -m "refactor: migrate EntityStoreServiceImpl to StorageAdapter"
```

---

### Task 5: Migrate IdentityServiceImpl to StorageAdapter

**Files:**
- Modify: `src/services/identity/service.ts`
- Modify: `test/identity-service.test.ts`

- [x] **Step 1: Update IdentityServiceImpl constructor**

In `src/services/identity/service.ts`, change:

```typescript
export class IdentityServiceImpl implements IdentityWriter {
  private storage: DurableObjectStorage
  private audit: AuditService
```

And the constructor param type from `storage: DurableObjectStorage` to:

```typescript
import type { StorageAdapter } from '../../storage'

export class IdentityServiceImpl implements IdentityWriter {
  private storage: StorageAdapter
  private audit: AuditService
```

Update the constructor signature:
```typescript
constructor(deps: { storage: StorageAdapter; audit: AuditService }) {
```

- [x] **Step 2: Update test to use MemoryStorageAdapter**

In `test/identity-service.test.ts`, replace mock storage with `new MemoryStorageAdapter()`.

- [x] **Step 3: Run tests**

Run: `pnpm vitest run test/identity-service.test.ts`
Expected: PASS

- [x] **Step 4: Commit**

```bash
git add src/services/identity/service.ts test/identity-service.test.ts
git commit -m "refactor: migrate IdentityServiceImpl to StorageAdapter"
```

---

### Task 6: Migrate SessionServiceImpl to StorageAdapter

**Files:**
- Modify: `src/services/auth/service.ts`
- Modify: `test/session-service.test.ts`

- [x] **Step 1: Update SessionServiceImpl constructor**

In `src/services/auth/service.ts`, change:

```typescript
import type { StorageAdapter } from '../../storage'

export class SessionServiceImpl implements SessionService {
  private storage: StorageAdapter
  private identityReader: IdentityReader

  constructor(deps: { storage: StorageAdapter; identityReader: IdentityReader }) {
    this.storage = deps.storage
    this.identityReader = deps.identityReader
  }
```

- [x] **Step 2: Update test to use MemoryStorageAdapter**

In `test/session-service.test.ts`, replace mock storage with `new MemoryStorageAdapter()`.

- [x] **Step 3: Run tests**

Run: `pnpm vitest run test/session-service.test.ts`
Expected: PASS

- [x] **Step 4: Commit**

```bash
git add src/services/auth/service.ts test/session-service.test.ts
git commit -m "refactor: migrate SessionServiceImpl to StorageAdapter"
```

---

### Task 7: Migrate Key Services to StorageAdapter

**Files:**
- Modify: `src/services/keys/api-keys.ts`
- Modify: `src/services/keys/agent-keys.ts`
- Modify: `src/services/keys/rate-limit.ts`
- Modify: `src/services/keys/service.ts`
- Modify: `test/keys-service.test.ts`

- [x] **Step 1: Update RateLimitServiceImpl**

In `src/services/keys/rate-limit.ts`:

```typescript
import type { StorageAdapter } from '../../storage'

export class RateLimitServiceImpl implements RateLimitService {
  private storage: StorageAdapter

  constructor({ storage }: { storage: StorageAdapter }) {
    this.storage = storage
  }
```

- [x] **Step 2: Update ApiKeyServiceImpl**

In `src/services/keys/api-keys.ts`:

```typescript
import type { StorageAdapter } from '../../storage'

export class ApiKeyServiceImpl implements ApiKeyWriter {
  private storage: StorageAdapter
  private audit: AuditService
  private getIdentityLevel: (id: string) => Promise<CapabilityLevel | null>

  constructor({
    storage,
    audit,
    getIdentityLevel,
  }: {
    storage: StorageAdapter
    audit: AuditService
    getIdentityLevel?: (id: string) => Promise<CapabilityLevel | null>
  }) {
    this.storage = storage
    this.audit = audit
    this.getIdentityLevel = getIdentityLevel ?? (async () => null)
  }
```

- [x] **Step 3: Update AgentKeyServiceImpl**

In `src/services/keys/agent-keys.ts`:

```typescript
import type { StorageAdapter } from '../../storage'

export class AgentKeyServiceImpl implements AgentKeyWriter {
  private storage: StorageAdapter
  private audit: AuditService
  private identityExists: (id: string) => Promise<boolean>
  private isIdentityFrozen: (id: string) => Promise<boolean>

  constructor({
    storage,
    ...rest
  }: {
    storage: StorageAdapter
    audit: AuditService
    identityExists?: (id: string) => Promise<boolean>
    isIdentityFrozen?: (id: string) => Promise<boolean>
  }) {
```

- [x] **Step 4: Update KeyServiceImpl (composite)**

In `src/services/keys/service.ts`:

```typescript
import type { StorageAdapter } from '../../storage'

export class KeyServiceImpl implements KeyService {
  readonly apiKeys: ApiKeyServiceImpl
  readonly agentKeys: AgentKeyServiceImpl
  readonly rateLimit: RateLimitServiceImpl

  constructor({
    storage,
    audit,
    identity,
  }: {
    storage: StorageAdapter
    audit: AuditService
    identity?: IdentityReader
  }) {
```

- [x] **Step 5: Update test to use MemoryStorageAdapter**

In `test/keys-service.test.ts`, replace `createMockStorage()` function with:

```typescript
import { MemoryStorageAdapter } from '../src/storage'
```

Replace all `createMockStorage()` calls with `new MemoryStorageAdapter()`.

- [x] **Step 6: Run tests**

Run: `pnpm vitest run test/keys-service.test.ts`
Expected: PASS

- [x] **Step 7: Commit**

```bash
git add src/services/keys/api-keys.ts src/services/keys/agent-keys.ts src/services/keys/rate-limit.ts src/services/keys/service.ts test/keys-service.test.ts
git commit -m "refactor: migrate all Key services to StorageAdapter"
```

---

### Task 8: Migrate OAuthServiceImpl and remove buildStorageBridge

**Files:**
- Modify: `src/services/oauth/service.ts`
- Modify: `test/oauth-facade-service.test.ts`

- [x] **Step 1: Update OAuthServiceImpl**

In `src/services/oauth/service.ts`, change the constructor to accept `StorageAdapter` and pass it directly to `OAuthProvider` instead of building a bridge:

```typescript
import type { StorageAdapter } from '../../storage'

export class OAuthServiceImpl implements OAuthService {
  private provider: OAuthProvider
  private storage: StorageAdapter
  private config: OAuthConfig

  constructor(deps: { storage: StorageAdapter; config: OAuthConfig }) {
    this.storage = deps.storage
    this.config = deps.config
    this.provider = new OAuthProvider({
      storage: deps.storage,
      config: deps.config,
      getIdentity: async () => null,
    })
  }
```

Delete the `buildStorageBridge()` private method entirely (~lines 179-199). The `StorageAdapter` interface is already the same shape that `OAuthProvider` expects.

- [x] **Step 2: Update test if needed**

In `test/oauth-facade-service.test.ts`, replace mock storage with `new MemoryStorageAdapter()`.

- [x] **Step 3: Run tests**

Run: `pnpm vitest run test/oauth-facade-service.test.ts`
Expected: PASS

- [x] **Step 4: Commit**

```bash
git add src/services/oauth/service.ts test/oauth-facade-service.test.ts
git commit -m "refactor: migrate OAuthServiceImpl to StorageAdapter, remove buildStorageBridge"
```

---

### Task 9: Create DurableObjectStorageAdapter and wire into Identity.ts

**Files:**
- Create: `src/do/storage-adapter.ts`
- Modify: `src/do/Identity.ts`

- [x] **Step 1: Create the DO adapter**

```typescript
// src/do/storage-adapter.ts
import type { StorageAdapter } from '../storage'

/**
 * Adapts DurableObjectStorage to the StorageAdapter interface.
 * Used by Identity.ts to bridge ctx.storage to all services.
 */
export class DurableObjectStorageAdapter implements StorageAdapter {
  constructor(private storage: DurableObjectStorage) {}

  get<T = unknown>(key: string): Promise<T | undefined> {
    return this.storage.get(key) as Promise<T | undefined>
  }

  put(key: string, value: unknown, options?: { expirationTtl?: number }): Promise<void> {
    return this.storage.put(key, value, options)
  }

  async delete(key: string): Promise<boolean> {
    return !!(await this.storage.delete(key))
  }

  list<T = unknown>(options?: {
    prefix?: string
    limit?: number
    start?: string
    reverse?: boolean
  }): Promise<Map<string, T>> {
    return this.storage.list(options) as Promise<Map<string, T>>
  }
}
```

- [x] **Step 2: Wire adapter into Identity.ts**

In `src/do/Identity.ts`, add a private field and getter for the adapter, then update all service getters to use it instead of `this.ctx.storage`.

Add near the top of the class (after existing private fields):

```typescript
import { DurableObjectStorageAdapter } from './storage-adapter'
import type { StorageAdapter } from '../storage'

// Inside the class:
private _storageAdapter?: StorageAdapter

private get storageAdapter(): StorageAdapter {
  if (!this._storageAdapter) {
    this._storageAdapter = new DurableObjectStorageAdapter(this.ctx.storage)
  }
  return this._storageAdapter
}
```

Then update each service getter. Change all `this.ctx.storage` → `this.storageAdapter`:

```typescript
// auditService getter:
this._auditService = new AuditServiceImpl({ storage: this.storageAdapter })

// entityStore getter:
this._entityStore = new EntityStoreServiceImpl({ storage: this.storageAdapter })

// identityService getter:
this._identityService = new IdentityServiceImpl({ storage: this.storageAdapter, audit: this.auditService })

// keyService getter:
this._keyService = new KeyServiceImpl({ storage: this.storageAdapter, audit: this.auditService, identity: this.identityService })

// sessionService getter:
this._sessionService = new SessionServiceImpl({ storage: this.storageAdapter, identityReader: this.identityService })

// oauthService getter:
this._oauthService = new OAuthServiceImpl({ storage: this.storageAdapter, config: { ... } })
```

**Important:** `Identity.ts` also uses `this.ctx.storage` directly in many RPC methods (lines ~316-627). Leave those as-is for now — they're DO-specific operations (direct key reads/writes) that don't go through services. The storage abstraction is for service constructors only.

- [x] **Step 3: Run full test suite**

Run: `pnpm vitest run`
Expected: All tests PASS

- [x] **Step 4: Type-check**

Run: `pnpm typecheck`
Expected: No errors

- [x] **Step 5: Commit**

```bash
git add src/do/storage-adapter.ts src/do/Identity.ts
git commit -m "refactor: wire DurableObjectStorageAdapter into Identity.ts"
```

---

### Task 10: Export StorageAdapter from package

**Files:**
- Modify: `src/index.ts`

- [x] **Step 1: Add storage exports to main barrel**

In `src/index.ts`, add:

```typescript
// Storage abstraction
export type { StorageAdapter } from './storage'
export { MemoryStorageAdapter } from './storage'
```

This lets consumers (like oauth.do) use `MemoryStorageAdapter` in their tests too.

- [x] **Step 2: Type-check**

Run: `pnpm typecheck`
Expected: No errors

- [x] **Step 3: Commit**

```bash
git add src/index.ts
git commit -m "feat: export StorageAdapter interface from package"
```

---

## Phase 2: SDK/Server Directory Separation

> **Note:** Phase 2 is a larger structural refactor. It can be executed independently after Phase 1 is complete and stable. The steps below are higher-level than Phase 1 because the moves are mechanical (rename/move files) rather than logic changes.

### Task 11: Create `src/sdk/` directory and move portable code

**Files:**
- Move all portable modules from `src/` to `src/sdk/`
- Create: `src/sdk/index.ts`

- [x] **Step 1: Create sdk directory and move modules**

```bash
mkdir -p src/sdk
# Move portable modules
mv src/auth src/sdk/auth
mv src/cli src/sdk/cli
mv src/claim src/sdk/claim
mv src/crypto src/sdk/crypto
mv src/jwt src/sdk/jwt
mv src/csrf src/sdk/csrf
mv src/foundation src/sdk/foundation
mv src/oauth src/sdk/oauth
mv src/github src/sdk/github
mv src/workos src/sdk/workos
mv src/mcp src/sdk/mcp
mv src/storage.ts src/sdk/storage.ts
mv src/errors.ts src/sdk/errors.ts
```

- [x] **Step 2: Create `src/sdk/index.ts`**

Mirror the current `src/index.ts` exports but without `IdentityDO` and server internals:

```typescript
// src/sdk/index.ts
// Portable SDK exports — no cloudflare:workers dependency

export * from './oauth'
export * from './mcp'
export * from './auth'
export * from './claim'
export * from './github'
export * from './crypto'
export * from './jwt'
export * from './workos'
export * from './csrf'
export * from './audit'
export * from './errors'

// Storage abstraction
export type { StorageAdapter } from './storage'
export { MemoryStorageAdapter } from './storage'

// Foundation
export { Ok, Err, isOk, isErr, map, flatMap, unwrapOr, toErrorResponse } from './foundation'
export type { Result, DomainError } from './foundation'
export { NotFoundError, AuthError, ConflictError, RateLimitError, ClaimError, KeyError } from './foundation'
```

- [x] **Step 3: Fix all internal imports within sdk/**

Every file in `src/sdk/` that imports from sibling modules needs path updates. For example:

- `src/sdk/oauth/provider.ts` imports from `../jwt/signing` → stays `../jwt/signing` (both moved together)
- `src/sdk/services/audit/service.ts` imports from `../../audit` → this file is in server/, not sdk/
- Cross-boundary imports (sdk → foundation, etc.) stay relative within sdk/

Run `pnpm typecheck` after each batch of fixes.

- [x] **Step 4: Type-check**

Run: `pnpm typecheck`
Fix any broken imports iteratively.

- [x] **Step 5: Commit**

```bash
git add src/sdk/
git commit -m "refactor: move portable code to src/sdk/"
```

---

### Task 12: Create `src/server/` directory and move Cloudflare-specific code

**Files:**
- Move DO, services, audit implementation to `src/server/`
- Create: `src/server/index.ts`

- [x] **Step 1: Create server directory and move modules**

```bash
mkdir -p src/server
mv src/do src/server/do
mv src/services src/server/services
mv src/audit src/server/audit
mv src/db src/server/db
```

- [x] **Step 2: Create `src/server/index.ts`**

```typescript
// src/server/index.ts
// Cloudflare-specific exports — requires cloudflare:workers runtime

export { IdentityDO } from './do/Identity'
export type { Identity, IdentityType, IdentityEnv } from './do/Identity'
export { DurableObjectStorageAdapter } from './do/storage-adapter'

// Services (for direct use or testing)
export { AuditServiceImpl } from './services/audit/service'
export { EntityStoreServiceImpl } from './services/entity-store/service'
export { IdentityServiceImpl } from './services/identity/service'
export { KeyServiceImpl } from './services/keys/service'
export { SessionServiceImpl } from './services/auth/service'
export { OAuthServiceImpl } from './services/oauth/service'

// AuditLog
export { AuditLog } from './audit'
```

- [x] **Step 3: Fix all internal imports within server/**

Files in `src/server/` that import from `src/sdk/` need updated paths:

- `src/server/services/audit/service.ts`: `../../audit` → `../../../sdk/audit` (or `../../sdk/audit` depending on depth)
- `src/server/services/*/service.ts`: `../../foundation` → `../../../sdk/foundation`
- `src/server/do/Identity.ts`: all imports from `../services/`, `../oauth/`, `../jwt/` need updating

Run `pnpm typecheck` after each batch.

- [x] **Step 4: Type-check**

Run: `pnpm typecheck`
Fix broken imports iteratively.

- [x] **Step 5: Commit**

```bash
git add src/server/
git commit -m "refactor: move Cloudflare-specific code to src/server/"
```

---

### Task 13: Update `src/index.ts` as compatibility shim

**Files:**
- Modify: `src/index.ts`

- [x] **Step 1: Replace src/index.ts with compatibility re-exports**

```typescript
// src/index.ts — compatibility shim
// SDK exports (portable)
export * from './sdk'

// Server exports (Cloudflare-specific) — deprecated from main barrel
// Consumers should use 'id.org.ai/server' instead
export { IdentityDO } from './server'
export type { Identity, IdentityType, IdentityEnv } from './server'
```

- [x] **Step 2: Type-check**

Run: `pnpm typecheck`
Expected: No errors

- [x] **Step 3: Run full test suite**

Run: `pnpm vitest run`
Expected: All tests PASS

- [x] **Step 4: Commit**

```bash
git add src/index.ts
git commit -m "refactor: src/index.ts now re-exports from sdk/ and server/"
```

---

### Task 14: Update tsup.config.ts and package.json exports

**Files:**
- Modify: `tsup.config.ts`
- Modify: `package.json`

- [x] **Step 1: Update tsup entry points**

```typescript
import { defineConfig } from 'tsup'

export default defineConfig({
  entry: [
    'src/sdk/index.ts',
    'src/sdk/cli/index.ts',
    'src/sdk/cli/device.ts',
    'src/sdk/cli/auth.ts',
    'src/sdk/cli/storage.ts',
    'src/sdk/auth/index.ts',
    'src/sdk/oauth/index.ts',
    'src/sdk/mcp/index.ts',
    'src/sdk/github/index.ts',
    'src/sdk/claim/index.ts',
    'src/sdk/jwt/index.ts',
    'src/sdk/workos/index.ts',
    'src/server/index.ts',
    'src/server/db/index.ts',
    'src/index.ts',           // compatibility shim
  ],
  format: ['esm'],
  dts: true,
  sourcemap: true,
  clean: true,
  splitting: false,
  external: ['open', 'drizzle-orm', 'drizzle-orm/sqlite-core', 'cloudflare:workers', 'hono', 'hono/cors'],
})
```

- [x] **Step 2: Add `id.org.ai/server` export to package.json**

In the `exports` field of `package.json`, add:

```json
"./server": {
  "types": "./dist/server/index.d.ts",
  "import": "./dist/server/index.js"
}
```

Update existing export paths to point to `sdk/`:

```json
".": {
  "types": "./dist/index.d.ts",
  "import": "./dist/index.js"
},
"./auth": {
  "types": "./dist/sdk/auth/index.d.ts",
  "import": "./dist/sdk/auth/index.js"
},
"./oauth": {
  "types": "./dist/sdk/oauth/index.d.ts",
  "import": "./dist/sdk/oauth/index.js"
}
```

(Apply the same pattern to all existing export paths — just insert `sdk/` in the path.)

- [x] **Step 3: Build and verify**

Run: `pnpm build`
Expected: Build succeeds, `dist/` contains both `sdk/` and `server/` subdirectories

- [x] **Step 4: Type-check**

Run: `pnpm typecheck`
Expected: No errors

- [x] **Step 5: Run full test suite**

Run: `pnpm vitest run`
Expected: All tests PASS

- [x] **Step 6: Commit**

```bash
git add tsup.config.ts package.json
git commit -m "feat: add id.org.ai/server export path, update tsup entries for sdk/server split"
```

---

### Task 15: Update worker/ imports

**Files:**
- Modify: `worker/index.ts`
- Modify: `worker/routes/*.ts`
- Modify: `worker/middleware/*.ts`

- [x] **Step 1: Update worker imports**

All files in `worker/` that import from `../../src/` need path updates:

- `../../src/errors` → `../../src/sdk/errors`
- `../../src/oauth/provider` → `../../src/sdk/oauth/provider`
- `../../src/csrf` → `../../src/sdk/csrf`
- `../../src/audit` → `../../src/sdk/audit`
- `../../src/jwt/signing` → `../../src/sdk/jwt/signing`
- `../../src/do/Identity` → `../../src/server/do/Identity`
- `../../src/services/*` → `../../src/server/services/*`

- [x] **Step 2: Update test imports**

All test files that import from `../src/` need similar path updates.

- [x] **Step 3: Type-check**

Run: `pnpm typecheck`
Expected: No errors

- [x] **Step 4: Run full test suite**

Run: `pnpm vitest run`
Expected: All tests PASS

- [x] **Step 5: Commit**

```bash
git add worker/ test/
git commit -m "refactor: update worker and test imports for sdk/server split"
```

---

### Task 16: Final verification and deploy

**Files:** None (verification only)

- [x] **Step 1: Full type-check**

Run: `pnpm typecheck`
Expected: No errors

- [x] **Step 2: Full test suite**

Run: `pnpm vitest run`
Expected: All tests PASS

- [x] **Step 3: Build**

Run: `pnpm build`
Expected: Clean build, all entry points produce dist files

- [x] **Step 4: Verify export paths work**

```bash
# Check that dist has the expected structure
ls dist/sdk/index.js dist/sdk/index.d.ts
ls dist/server/index.js dist/server/index.d.ts
ls dist/index.js dist/index.d.ts
```

- [x] **Step 5: Deploy**

Run: `pnpm deploy`
Expected: Worker deploys successfully

- [x] **Step 6: Commit and push**

```bash
git push
```

---

## Phases Not Planned Here

### Phase 3: Remove compatibility shims

**When:** After Phase 2 is merged and all three consumers verified working (`auto-dot-dev/sdk`, `auto-dot-dev/mcp`, `dot-do/oauth.do`).

**What:** Remove `IdentityDO` re-export from the main `src/index.ts` barrel. Consumers that need it should use `id.org.ai/server` instead.

**Scope:** ~5 lines changed, no planning needed. Just delete the shim, verify, push.

### Future Phase: Split oauth exports (optional)

**When:** If/when you want `id.org.ai/oauth` to be pure portable (no Hono dependency).

**What:**
1. Create `id.org.ai/oauth/server` export path for `createOAuth21Server` + Hono routes
2. Update oauth.do to import Hono stuff from `id.org.ai/oauth/server`
3. Remove Hono exports from `id.org.ai/oauth`

**Why not planned now:** oauth.do is the only consumer of the Hono parts, and it works fine today. This is a design decision, not a committed task.

**Planning approach:** Brainstorming skill recommended — touches oauth.do's architecture and import path design. Not just a mechanical refactor.
