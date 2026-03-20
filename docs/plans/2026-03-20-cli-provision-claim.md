# CLI Provision & Claim Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `provision` and `claim` CLI commands + SDK exports so agents can create anonymous sandboxes and claim them via GitHub commit, and fix the broken OAuth device flow login.

**Architecture:** Two new CLI commands call existing server endpoints. `buildClaimWorkflow()` extracted from worker to shared `src/claim/workflow.ts`. New `src/claim/client.ts` provides HTTP client SDK. `ProvisionStorage` class stores provision data separately from OAuth tokens. OAuth client seeding via lazy `ensureCliClient()` in IdentityDO. New `GET /api/claim/:token/status` endpoint for claim polling.

**Tech Stack:** TypeScript, Hono (worker routes), Vitest + @cloudflare/vitest-pool-workers (tests), tsup (build), child_process (git commands), fs/promises (file writes)

**Spec:** `docs/specs/2026-03-20-cli-provision-claim-design.md`

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `src/claim/workflow.ts` | Create | `buildClaimWorkflow()` — pure function, no Node imports (worker-safe) |
| `src/claim/workflow-fs.ts` | Create | `writeClaimWorkflow()` — Node-only, writes file to disk |
| `src/claim/client.ts` | Create | HTTP client SDK: `provision()`, `getClaimStatus()` |
| `src/claim/index.ts` | Create | Re-export new functions (file does not exist yet — tsup entry point) |
| `src/cli/provision-storage.ts` | Create | `ProvisionStorage` class — read/write `~/.id.org.ai/provision` |
| `src/cli/provision.ts` | Create | `provisionCommand()` CLI handler |
| `src/cli/claim.ts` | Create | `claimCommand()` CLI handler |
| `src/cli/index.ts` | Modify | Add provision/claim to switch/case + printHelp() |
| `src/do/Identity.ts` | Modify | Add `ensureCliClient()` for OAuth client seeding |
| `worker/index.ts` | Modify | Import shared `buildClaimWorkflow`, add `/api/claim/:token/status` |
| `test/claim-workflow.test.ts` | Create | Tests for workflow generation |
| `test/claim-client.test.ts` | Create | Tests for HTTP client SDK |
| `test/provision-storage.test.ts` | Create | Tests for provision storage |
| `test/cli-provision.test.ts` | Create | Tests for provision command |
| `test/cli-claim.test.ts` | Create | Tests for claim command |
| `test/oauth-client-seeding.test.ts` | Create | Tests for ensureCliClient |
| `test/worker-routes.test.ts` | Modify | Import shared `buildClaimWorkflow`, remove mirror |

---

## Task 1: Extract `buildClaimWorkflow` to shared module

**Files:**
- Create: `src/claim/workflow.ts`
- Create: `test/claim-workflow.test.ts`
- Modify: `src/claim/index.ts`
- Modify: `worker/index.ts` (~line 3118)
- Modify: `test/worker-routes.test.ts` (~line 1719)

- [ ] **Step 1: Write failing test for `buildClaimWorkflow`**

Create `test/claim-workflow.test.ts`:

```typescript
import { describe, it, expect } from 'vitest'
import { buildClaimWorkflow } from '../src/claim/workflow'

describe('buildClaimWorkflow', () => {
  it('generates valid workflow YAML with claim token', () => {
    const yaml = buildClaimWorkflow('clm_abc123')
    expect(yaml).toContain('name: Claim headless.ly tenant')
    expect(yaml).toContain("tenant: 'clm_abc123'")
    expect(yaml).toContain('uses: dot-org-ai/id@v1')
    expect(yaml).toContain('uses: actions/checkout@v4')
    expect(yaml).toContain('id-token: write')
    expect(yaml).toContain('branches: [main, master]')
  })

  it('throws on invalid claim token', () => {
    expect(() => buildClaimWorkflow('')).toThrow()
    expect(() => buildClaimWorkflow('invalid')).toThrow()
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/chrisrisner/Workspace/dot-do/headless.ly/.org.ai/id && pnpm vitest run test/claim-workflow.test.ts`
Expected: FAIL — module `../src/claim/workflow` not found

- [ ] **Step 3: Implement `buildClaimWorkflow` in shared module**

Create `src/claim/workflow.ts`:

```typescript
/**
 * Claim Workflow Generation
 *
 * Generates the GitHub Actions workflow YAML that agents commit
 * to claim a tenant via the claim-by-commit flow.
 */

/**
 * Generate the GitHub Actions workflow YAML for claim-by-commit.
 *
 * @param claimToken - The clm_* claim token from provisioning
 * @returns Complete workflow YAML string
 */
export function buildClaimWorkflow(claimToken: string): string {
  if (!claimToken || !claimToken.startsWith('clm_')) {
    throw new Error(`Invalid claim token: expected clm_* prefix, got "${claimToken}"`)
  }

  return `name: Claim headless.ly tenant
on:
  push:
    branches: [main, master]
permissions:
  id-token: write
  contents: read
jobs:
  claim:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dot-org-ai/id@v1
        with:
          tenant: '${claimToken}'
`
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/chrisrisner/Workspace/dot-do/headless.ly/.org.ai/id && pnpm vitest run test/claim-workflow.test.ts`
Expected: PASS (2 tests)

- [ ] **Step 5: Create `src/claim/index.ts`**

This file does not exist yet but is listed as a tsup entry point. Create it:

```typescript
export { ClaimService } from './provision'
export type { ProvisionResult, FreezeResult, TenantStatus } from './provision'
export { verifyClaim } from './verify'
export type { ClaimStatus } from './verify'
export { buildClaimWorkflow } from './workflow'
```

Note: Check the existing exports from `./provision` and `./verify` to ensure all current re-exports are preserved. The above is based on the existing module structure.

- [ ] **Step 6: Update worker to import from shared module**

In `worker/index.ts` (~line 3118), replace the local `buildClaimWorkflow` function with:

```typescript
import { buildClaimWorkflow } from '../src/claim/workflow'
```

Remove the local function definition. Verify the worker still references `buildClaimWorkflow` the same way in all call sites.

- [ ] **Step 7: Update worker route test to import from shared module**

In `test/worker-routes.test.ts` (~line 1719), replace the mirror copy of `buildClaimWorkflow` with:

```typescript
import { buildClaimWorkflow } from '../src/claim/workflow'
```

Remove the mirror function definition.

- [ ] **Step 8: Run full test suite**

Run: `cd /Users/chrisrisner/Workspace/dot-do/headless.ly/.org.ai/id && pnpm test`
Expected: All tests pass (271 + new tests)

- [ ] **Step 9: Run build**

Run: `cd /Users/chrisrisner/Workspace/dot-do/headless.ly/.org.ai/id && pnpm build`
Expected: Build succeeds

- [ ] **Step 10: Commit**

```bash
git add src/claim/workflow.ts src/claim/index.ts worker/index.ts test/claim-workflow.test.ts test/worker-routes.test.ts
git commit -m "refactor: extract buildClaimWorkflow to shared src/claim/workflow.ts"
```

---

## Task 2: Create HTTP client SDK (`src/claim/client.ts`)

**Files:**
- Create: `src/claim/client.ts`
- Create: `test/claim-client.test.ts`
- Modify: `src/claim/index.ts`

- [ ] **Step 1: Write failing tests for client SDK**

Create `test/claim-client.test.ts`:

```typescript
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

// These are Node tests (not workers pool) — test HTTP client behavior
describe('provision', () => {
  let mockFetch: ReturnType<typeof vi.fn>

  beforeEach(() => {
    mockFetch = vi.fn()
    vi.stubGlobal('fetch', mockFetch)
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('calls POST /api/provision and returns result', async () => {
    const { provision } = await import('../src/claim/client')

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 201,
      json: async () => ({
        tenantId: 'tnt_abc',
        identityId: 'id_123',
        sessionToken: 'ses_xyz',
        claimToken: 'clm_def',
        level: 1,
        limits: { maxEntities: 1000, ttlHours: 24, maxRequestsPerMinute: 100 },
        upgrade: { nextLevel: 2, action: 'claim' },
      }),
    })

    const result = await provision('https://id.org.ai')

    expect(mockFetch).toHaveBeenCalledWith('https://id.org.ai/api/provision', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    })
    expect(result.tenantId).toBe('tnt_abc')
    expect(result.claimToken).toBe('clm_def')
    expect(result.level).toBe(1)
  })

  it('throws on non-ok response', async () => {
    const { provision } = await import('../src/claim/client')

    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 500,
      statusText: 'Internal Server Error',
    })

    await expect(provision('https://id.org.ai')).rejects.toThrow()
  })
})

describe('getClaimStatus', () => {
  let mockFetch: ReturnType<typeof vi.fn>

  beforeEach(() => {
    mockFetch = vi.fn()
    vi.stubGlobal('fetch', mockFetch)
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('calls GET /api/claim/:token/status', async () => {
    const { getClaimStatus } = await import('../src/claim/client')

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ status: 'claimed', level: 2 }),
    })

    const result = await getClaimStatus('clm_abc', 'https://id.org.ai')

    expect(mockFetch).toHaveBeenCalledWith('https://id.org.ai/api/claim/clm_abc/status')
    expect(result.status).toBe('claimed')
    expect(result.level).toBe(2)
  })

  it('returns unclaimed on 404', async () => {
    const { getClaimStatus } = await import('../src/claim/client')

    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 404,
    })

    const result = await getClaimStatus('clm_unknown', 'https://id.org.ai')

    expect(result.status).toBe('unclaimed')
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/chrisrisner/Workspace/dot-do/headless.ly/.org.ai/id && npx vitest run test/claim-client.test.ts --config vitest.node.config.ts`
Expected: FAIL — module not found

Note: These tests use Node vitest config (not workers pool) since client SDK runs outside Cloudflare.

- [ ] **Step 3: Implement client SDK**

Create `src/claim/client.ts`:

```typescript
/**
 * Claim Client SDK
 *
 * HTTP client functions for provisioning and claim status.
 * Designed for use outside Cloudflare Workers (CLI, Node scripts, agents).
 * Server-side code should use ClaimService (DO RPC) instead.
 */

const DEFAULT_BASE_URL = 'https://id.org.ai'

export interface ProvisionResult {
  tenantId: string
  identityId: string
  sessionToken: string
  claimToken: string
  level: number
  limits: {
    maxEntities: number
    ttlHours: number
    maxRequestsPerMinute: number
  }
  upgrade: {
    nextLevel: number
    action: string
    description?: string
    url?: string
  }
}

export interface ClaimStatusResult {
  status: 'unclaimed' | 'pending' | 'claimed' | 'expired'
  level?: number
}

/**
 * Provision an anonymous sandbox via the HTTP API.
 */
export async function provision(baseUrl = DEFAULT_BASE_URL): Promise<ProvisionResult> {
  const response = await fetch(`${baseUrl}/api/provision`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
  })

  if (!response.ok) {
    throw new Error(`Provision failed: ${response.status} ${response.statusText}`)
  }

  return response.json() as Promise<ProvisionResult>
}

/**
 * Get the current status of a claim token (single request).
 * Caller owns the retry/polling loop.
 */
export async function getClaimStatus(
  claimToken: string,
  baseUrl = DEFAULT_BASE_URL,
): Promise<ClaimStatusResult> {
  const response = await fetch(`${baseUrl}/api/claim/${claimToken}/status`)

  if (!response.ok) {
    return { status: 'unclaimed' }
  }

  return response.json() as Promise<ClaimStatusResult>
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/chrisrisner/Workspace/dot-do/headless.ly/.org.ai/id && npx vitest run test/claim-client.test.ts --config vitest.node.config.ts`
Expected: PASS

- [ ] **Step 5: Update `src/claim/index.ts` to re-export client SDK**

Add to `src/claim/index.ts`:

```typescript
export { provision, getClaimStatus } from './client'
export type { ProvisionResult, ClaimStatusResult } from './client'
```

- [ ] **Step 6: Commit**

```bash
git add src/claim/client.ts src/claim/index.ts test/claim-client.test.ts
git commit -m "feat: add HTTP client SDK for provision and claim status"
```

---

## Task 3: Add `GET /api/claim/:token/status` endpoint

**Files:**
- Modify: `worker/index.ts`

- [ ] **Step 1: Add the claim status route**

In `worker/index.ts`, near the existing `/api/provision` route (~line 1505), add:

```typescript
app.get('/api/claim/:token/status', async (c) => {
  const token = c.req.param('token')

  if (!token || !token.startsWith('clm_')) {
    return c.json({ status: 'unclaimed' }, 404)
  }

  // Resolve identity ID from claim token KV
  const identityId = await c.env.SESSIONS.get(`claim:${token}`)
  if (!identityId) {
    return c.json({ status: 'expired' })
  }

  // Get the identity DO stub and verify claim status
  const stub = getIdentityStub(c.env, identityId)
  const result = await stub.verifyClaimToken(token)

  if (!result.valid) {
    return c.json({ status: 'unclaimed' })
  }

  return c.json({
    status: result.status || 'unclaimed',
    level: result.level,
  })
})
```

Note: Check how `getIdentityStub` is used elsewhere in the worker for the correct pattern. The KV key `claim:{token}` is set by the existing `/api/provision` handler.

- [ ] **Step 2: Run existing tests to verify no regressions**

Run: `cd /Users/chrisrisner/Workspace/dot-do/headless.ly/.org.ai/id && pnpm test`
Expected: All existing tests pass

- [ ] **Step 3: Commit**

```bash
git add worker/index.ts
git commit -m "feat: add GET /api/claim/:token/status endpoint"
```

---

## Task 4: Create `ProvisionStorage`

**Files:**
- Create: `src/cli/provision-storage.ts`
- Create: `test/provision-storage.test.ts`

- [ ] **Step 1: Write failing tests**

Create `test/provision-storage.test.ts`:

```typescript
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { ProvisionStorage } from '../src/cli/provision-storage'
import { mkdtemp, rm } from 'fs/promises'
import { join } from 'path'
import { tmpdir } from 'os'

describe('ProvisionStorage', () => {
  let tempDir: string
  let storage: ProvisionStorage

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'id-test-'))
    storage = new ProvisionStorage(join(tempDir, 'provision'))
  })

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true })
  })

  it('returns null when no provision data exists', async () => {
    const data = await storage.getProvisionData()
    expect(data).toBeNull()
  })

  it('stores and retrieves provision data', async () => {
    const data = {
      tenantId: 'tnt_abc',
      sessionToken: 'ses_xyz',
      claimToken: 'clm_def',
      createdAt: Date.now(),
    }
    await storage.setProvisionData(data)
    const retrieved = await storage.getProvisionData()
    expect(retrieved).toEqual(data)
  })

  it('removes provision data', async () => {
    await storage.setProvisionData({
      tenantId: 'tnt_abc',
      sessionToken: 'ses_xyz',
      claimToken: 'clm_def',
      createdAt: Date.now(),
    })
    await storage.removeProvisionData()
    const data = await storage.getProvisionData()
    expect(data).toBeNull()
  })

  it('creates parent directory if it does not exist', async () => {
    const nested = new ProvisionStorage(join(tempDir, 'nested', 'deep', 'provision'))
    await nested.setProvisionData({
      tenantId: 'tnt_abc',
      sessionToken: 'ses_xyz',
      claimToken: 'clm_def',
      createdAt: Date.now(),
    })
    const data = await nested.getProvisionData()
    expect(data?.tenantId).toBe('tnt_abc')
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/chrisrisner/Workspace/dot-do/headless.ly/.org.ai/id && npx vitest run test/provision-storage.test.ts --config vitest.node.config.ts`
Expected: FAIL — module not found

- [ ] **Step 3: Implement ProvisionStorage**

Create `src/cli/provision-storage.ts`:

```typescript
/**
 * Provision Data Storage
 *
 * Stores provision data (tenantId, sessionToken, claimToken) separately
 * from OAuth tokens. File-based, lives at ~/.id.org.ai/provision.
 */

import { readFile, writeFile, unlink, mkdir } from 'fs/promises'
import { dirname } from 'path'
import { homedir } from 'os'
import { join } from 'path'

export interface ProvisionData {
  tenantId: string
  sessionToken: string
  claimToken: string
  createdAt: number
}

const DEFAULT_PATH = join(homedir(), '.id.org.ai', 'provision')

export class ProvisionStorage {
  private filePath: string

  constructor(filePath = DEFAULT_PATH) {
    this.filePath = filePath
  }

  async getProvisionData(): Promise<ProvisionData | null> {
    try {
      const raw = await readFile(this.filePath, 'utf-8')
      return JSON.parse(raw) as ProvisionData
    } catch {
      return null
    }
  }

  async setProvisionData(data: ProvisionData): Promise<void> {
    await mkdir(dirname(this.filePath), { recursive: true })
    await writeFile(this.filePath, JSON.stringify(data, null, 2), 'utf-8')
  }

  async removeProvisionData(): Promise<void> {
    try {
      await unlink(this.filePath)
    } catch {
      // File doesn't exist — that's fine
    }
  }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/chrisrisner/Workspace/dot-do/headless.ly/.org.ai/id && npx vitest run test/provision-storage.test.ts --config vitest.node.config.ts`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add src/cli/provision-storage.ts test/provision-storage.test.ts
git commit -m "feat: add ProvisionStorage for CLI provision data"
```

---

## Task 5: Implement `provision` CLI command

**Files:**
- Create: `src/cli/provision.ts`
- Create: `test/cli-provision.test.ts`
- Modify: `src/cli/index.ts`

- [ ] **Step 1: Write failing tests**

Create `test/cli-provision.test.ts`:

```typescript
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

describe('provisionCommand', () => {
  let mockFetch: ReturnType<typeof vi.fn>
  let mockStorage: { setProvisionData: ReturnType<typeof vi.fn>; getProvisionData: ReturnType<typeof vi.fn>; removeProvisionData: ReturnType<typeof vi.fn> }
  let logs: string[]

  beforeEach(() => {
    mockFetch = vi.fn()
    vi.stubGlobal('fetch', mockFetch)
    mockStorage = { setProvisionData: vi.fn(), getProvisionData: vi.fn(), removeProvisionData: vi.fn() }
    logs = []
    vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
      logs.push(args.join(' '))
    })
    vi.spyOn(console, 'error').mockImplementation(() => {})
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('provisions and prints human-readable output', async () => {
    const { provisionCommand } = await import('../src/cli/provision')

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 201,
      json: async () => ({
        tenantId: 'tnt_abc',
        identityId: 'id_123',
        sessionToken: 'ses_xyz',
        claimToken: 'clm_def',
        level: 1,
        limits: { maxEntities: 1000, ttlHours: 24, maxRequestsPerMinute: 100 },
        upgrade: { nextLevel: 2, action: 'claim' },
      }),
    })

    await provisionCommand({ baseUrl: 'https://id.org.ai', json: false, storage: mockStorage as any })

    const output = logs.join('\n')
    expect(output).toContain('tnt_abc')
    expect(output).toContain('clm_def')
    expect(output).toContain('id.org.ai claim')
  })

  it('outputs JSON with --json flag', async () => {
    const { provisionCommand } = await import('../src/cli/provision')

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 201,
      json: async () => ({
        tenantId: 'tnt_abc',
        identityId: 'id_123',
        sessionToken: 'ses_xyz',
        claimToken: 'clm_def',
        level: 1,
        limits: { maxEntities: 1000, ttlHours: 24, maxRequestsPerMinute: 100 },
        upgrade: { nextLevel: 2, action: 'claim' },
      }),
    })

    await provisionCommand({ baseUrl: 'https://id.org.ai', json: true, storage: mockStorage as any })

    const output = logs.join('\n')
    const parsed = JSON.parse(output)
    expect(parsed.tenantId).toBe('tnt_abc')
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/chrisrisner/Workspace/dot-do/headless.ly/.org.ai/id && npx vitest run test/cli-provision.test.ts --config vitest.node.config.ts`
Expected: FAIL

- [ ] **Step 3: Implement provision command**

Create `src/cli/provision.ts`:

```typescript
/**
 * CLI: provision command
 *
 * Creates an anonymous sandbox (L1) and stores credentials locally.
 */

import { provision } from '../claim/client'
import type { ProvisionStorage } from './provision-storage'

export interface ProvisionCommandOptions {
  baseUrl: string
  json: boolean
  storage: ProvisionStorage
}

export async function provisionCommand(opts: ProvisionCommandOptions): Promise<void> {
  try {
    const result = await provision(opts.baseUrl)

    // Store provision data locally
    await opts.storage.setProvisionData({
      tenantId: result.tenantId,
      sessionToken: result.sessionToken,
      claimToken: result.claimToken,
      createdAt: Date.now(),
    })

    if (opts.json) {
      console.log(JSON.stringify(result, null, 2))
      return
    }

    console.log('')
    console.log('  Anonymous sandbox created')
    console.log('')
    console.log(`  Tenant:      ${result.tenantId}`)
    console.log(`  Claim Token: ${result.claimToken}`)
    console.log(`  Level:       ${result.level}`)
    console.log(`  Expires:     ${result.limits.ttlHours} hours`)
    console.log('')
    console.log('  Next step: id.org.ai claim')
    console.log('')
  } catch (err) {
    console.error(`Provision failed: ${err instanceof Error ? err.message : err}`)
    console.error('Try again, or check https://id.org.ai for status.')
    process.exit(1)
  }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/chrisrisner/Workspace/dot-do/headless.ly/.org.ai/id && npx vitest run test/cli-provision.test.ts --config vitest.node.config.ts`
Expected: PASS

- [ ] **Step 5: Wire into CLI index**

In `src/cli/index.ts`:

Add import at top:
```typescript
import { provisionCommand } from './provision'
import { ProvisionStorage } from './provision-storage'
```

Add to switch/case (after existing `case 'status':`):
```typescript
case 'provision':
  return provisionCommand({
    baseUrl: process.env.ID_ORG_AI_URL || CANONICAL_API_ORIGIN,
    json: args.includes('--json'),
    storage: new ProvisionStorage(),
  })
```

Update `printHelp()` to add provision and claim to the commands list:
```
  provision      Create an anonymous sandbox (Level 1)
  claim          Claim tenant via GitHub commit (Level 1 → 2)
```

- [ ] **Step 6: Commit**

```bash
git add src/cli/provision.ts src/cli/index.ts test/cli-provision.test.ts
git commit -m "feat: add provision CLI command"
```

---

## Task 6: Implement `claim` CLI command

**Files:**
- Create: `src/cli/claim.ts`
- Create: `test/cli-claim.test.ts`
- Modify: `src/cli/index.ts`

- [ ] **Step 1: Write failing tests**

Create `test/cli-claim.test.ts`:

```typescript
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mkdtemp, rm, readFile } from 'fs/promises'
import { join } from 'path'
import { tmpdir } from 'os'

describe('claimCommand', () => {
  let tempDir: string
  let logs: string[]
  let errors: string[]

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'id-claim-test-'))
    logs = []
    errors = []
    vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
      logs.push(args.join(' '))
    })
    vi.spyOn(console, 'error').mockImplementation((...args: unknown[]) => {
      errors.push(args.join(' '))
    })
  })

  afterEach(async () => {
    vi.restoreAllMocks()
    await rm(tempDir, { recursive: true, force: true })
  })

  it('writes workflow file to .github/workflows/', async () => {
    const { writeClaimWorkflow } = await import('../src/claim/workflow-fs')

    const filePath = await writeClaimWorkflow('clm_test123', tempDir)

    expect(filePath).toBe(join(tempDir, '.github', 'workflows', 'headlessly.yml'))
    const content = await readFile(filePath, 'utf-8')
    expect(content).toContain("tenant: 'clm_test123'")
    expect(content).toContain('dot-org-ai/id@v1')
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/chrisrisner/Workspace/dot-do/headless.ly/.org.ai/id && npx vitest run test/cli-claim.test.ts --config vitest.node.config.ts`
Expected: FAIL — `writeClaimWorkflow` not found

- [ ] **Step 3: Create `src/claim/workflow-fs.ts`**

This must be a SEPARATE file from `workflow.ts` because it imports `fs/promises` which is unavailable in Cloudflare Workers. The worker imports `workflow.ts` (pure), CLI imports `workflow-fs.ts` (Node).

Create `src/claim/workflow-fs.ts`:

```typescript
/**
 * Claim Workflow File Writer (Node-only)
 *
 * Writes the claim workflow YAML to disk. NOT importable from Workers.
 */

import { writeFile, mkdir } from 'fs/promises'
import { join, dirname } from 'path'
import { buildClaimWorkflow } from './workflow'

/**
 * Write the claim workflow file to a git repo.
 *
 * @param claimToken - The clm_* claim token
 * @param repoRoot - Root of the git repo (defaults to cwd)
 * @returns Absolute path to the written file
 */
export async function writeClaimWorkflow(claimToken: string, repoRoot = process.cwd()): Promise<string> {
  const yaml = buildClaimWorkflow(claimToken)
  const filePath = join(repoRoot, '.github', 'workflows', 'headlessly.yml')
  await mkdir(dirname(filePath), { recursive: true })
  await writeFile(filePath, yaml, 'utf-8')
  return filePath
}
```

Update `src/claim/index.ts` to re-export both:
```typescript
export { buildClaimWorkflow } from './workflow'
export { writeClaimWorkflow } from './workflow-fs'
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/chrisrisner/Workspace/dot-do/headless.ly/.org.ai/id && npx vitest run test/cli-claim.test.ts --config vitest.node.config.ts`
Expected: PASS

- [ ] **Step 4b: Add claimCommand tests**

Add to `test/cli-claim.test.ts` (after the writeClaimWorkflow test):

```typescript
describe('claimCommand error handling', () => {
  it('errors when not in a git repo', async () => {
    const { claimCommand } = await import('../src/cli/claim')
    const mockExit = vi.spyOn(process, 'exit').mockImplementation(() => { throw new Error('exit') })
    const mockStorage = {
      getProvisionData: vi.fn().mockResolvedValue({ claimToken: 'clm_test' }),
      setProvisionData: vi.fn(),
      removeProvisionData: vi.fn(),
    }

    // Run from a non-git temp dir
    const origCwd = process.cwd()
    process.chdir(tempDir)
    try {
      await expect(claimCommand({
        baseUrl: 'https://id.org.ai',
        json: false,
        noPush: true,
        storage: mockStorage as any,
      })).rejects.toThrow()
    } finally {
      process.chdir(origCwd)
      mockExit.mockRestore()
    }

    expect(errors.join(' ')).toContain('Not a git repository')
  })

  it('errors when no claim token available', async () => {
    const { claimCommand } = await import('../src/cli/claim')
    const mockExit = vi.spyOn(process, 'exit').mockImplementation(() => { throw new Error('exit') })
    const mockStorage = {
      getProvisionData: vi.fn().mockResolvedValue(null),
      setProvisionData: vi.fn(),
      removeProvisionData: vi.fn(),
    }

    try {
      await expect(claimCommand({
        baseUrl: 'https://id.org.ai',
        json: false,
        noPush: true,
        storage: mockStorage as any,
      })).rejects.toThrow()
    } finally {
      mockExit.mockRestore()
    }

    expect(errors.join(' ')).toContain('No claim token found')
  })
})
```

- [ ] **Step 5: Implement claim command**

Create `src/cli/claim.ts`:

```typescript
/**
 * CLI: claim command
 *
 * Generates the claim workflow YAML, commits, and pushes.
 * After push, polls for claim confirmation.
 */

import { execSync } from 'child_process'
import { writeClaimWorkflow } from '../claim/workflow-fs'
import { getClaimStatus } from '../claim/client'
import type { ProvisionStorage } from './provision-storage'

export interface ClaimCommandOptions {
  baseUrl: string
  json: boolean
  token?: string
  noPush: boolean
  storage: ProvisionStorage
}

function exec(cmd: string): string {
  return execSync(cmd, { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] }).trim()
}

function isGitRepo(): boolean {
  try {
    exec('git rev-parse --is-inside-work-tree')
    return true
  } catch {
    return false
  }
}

function getRepoRoot(): string {
  return exec('git rev-parse --show-toplevel')
}

export async function claimCommand(opts: ClaimCommandOptions): Promise<void> {
  try {
    // Verify git repo
    if (!isGitRepo()) {
      console.error('Not a git repository. Run this from inside the repo you want to claim.')
      process.exit(1)
    }

    // Get claim token
    const provisionData = await opts.storage.getProvisionData()
    const claimToken = opts.token || provisionData?.claimToken

    if (!claimToken) {
      console.error('No claim token found. Run `id.org.ai provision` first, or pass `--token clm_xxx`.')
      process.exit(1)
    }

    const repoRoot = getRepoRoot()

    // Write workflow file
    const filePath = await writeClaimWorkflow(claimToken, repoRoot)
    console.log(`  Generated ${filePath.replace(repoRoot + '/', '')}`)

    // Git add + commit
    exec(`git add "${filePath}"`)
    exec('git commit -m "Claim headless.ly tenant"')
    console.log('  Committed: "Claim headless.ly tenant"')

    if (opts.noPush) {
      console.log('')
      console.log('  Skipping push (--no-push). Push manually to trigger the claim.')
      return
    }

    // Push
    exec('git push')
    console.log('  Pushed to origin')

    // Poll for confirmation
    console.log('  Waiting for claim confirmation...')
    const confirmed = await pollForClaim(claimToken, opts.baseUrl)

    if (confirmed) {
      console.log('  Tenant claimed! Upgraded to Level 2')
      await opts.storage.removeProvisionData()
    } else {
      console.log('  Push succeeded but claim not confirmed yet. Check GitHub Actions tab.')
    }

    if (opts.json) {
      console.log(JSON.stringify({ claimToken, confirmed, level: confirmed ? 2 : 1 }))
    }
  } catch (err) {
    console.error(`Claim failed: ${err instanceof Error ? err.message : err}`)
    process.exit(1)
  }
}

async function pollForClaim(claimToken: string, baseUrl: string, timeoutMs = 60_000): Promise<boolean> {
  const start = Date.now()
  const interval = 3_000

  while (Date.now() - start < timeoutMs) {
    const result = await getClaimStatus(claimToken, baseUrl)
    if (result.status === 'claimed') return true
    if (result.status === 'expired') return false
    await new Promise((r) => setTimeout(r, interval))
  }

  return false
}
```

- [ ] **Step 6: Wire into CLI index**

In `src/cli/index.ts`, add import:
```typescript
import { claimCommand } from './claim'
```

Add to switch/case:
```typescript
case 'claim':
  return claimCommand({
    baseUrl: process.env.ID_ORG_AI_URL || CANONICAL_API_ORIGIN,
    json: args.includes('--json'),
    token: args.find(a => a.startsWith('--token='))?.split('=')[1] || (args.includes('--token') ? args[args.indexOf('--token') + 1] : undefined),
    noPush: args.includes('--no-push'),
    storage: new ProvisionStorage(),
  })
```

- [ ] **Step 7: Run full test suite**

Run: `cd /Users/chrisrisner/Workspace/dot-do/headless.ly/.org.ai/id && pnpm test`
Expected: All tests pass

- [ ] **Step 8: Commit**

```bash
git add src/cli/claim.ts src/cli/index.ts test/cli-claim.test.ts
git commit -m "feat: add claim CLI command"
```

---

## Task 7: OAuth client seeding (`ensureCliClient`)

**Files:**
- Modify: `src/do/Identity.ts`
- Create: `test/oauth-client-seeding.test.ts`

- [ ] **Step 1: Write failing test**

Create `test/oauth-client-seeding.test.ts`:

```typescript
import { describe, it, expect } from 'vitest'
import { env } from 'cloudflare:test'

describe('ensureCliClient', () => {
  it('creates id_org_ai_cli client if it does not exist', async () => {
    const id = env.IDENTITY.idFromName('test-seeding')
    const stub = env.IDENTITY.get(id)

    // Call ensureCliClient (exposed as RPC method or tested via side effect)
    await stub.ensureCliClient()

    // Verify the client exists in storage
    const client = await stub.oauthStorageOp('get', 'client:id_org_ai_cli')
    expect(client).toBeTruthy()
    expect(client.id).toBe('id_org_ai_cli')
    expect(client.grantTypes).toContain('urn:ietf:params:oauth:grant-type:device_code')
    expect(client.trusted).toBe(true)
    expect(client.tokenEndpointAuthMethod).toBe('none')
  })

  it('does not overwrite existing client on second call', async () => {
    const id = env.IDENTITY.idFromName('test-seeding-idempotent')
    const stub = env.IDENTITY.get(id)

    await stub.ensureCliClient()
    const first = await stub.oauthStorageOp('get', 'client:id_org_ai_cli')

    await stub.ensureCliClient()
    const second = await stub.oauthStorageOp('get', 'client:id_org_ai_cli')

    expect(second.createdAt).toBe(first.createdAt)
  })
})
```

Note: Adapt this test to match the existing IdentityDO test patterns in `test/identity-do.test.ts`. The test may need to use the actual DO test helper pattern from that file.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/chrisrisner/Workspace/dot-do/headless.ly/.org.ai/id && pnpm vitest run test/oauth-client-seeding.test.ts`
Expected: FAIL — `ensureCliClient` not found

- [ ] **Step 3: Implement `ensureCliClient` in IdentityDO**

In `src/do/Identity.ts`, add method to the `IdentityDO` class:

```typescript
/**
 * Ensure the CLI OAuth client exists in storage.
 * Called lazily on first device-flow request. Idempotent.
 */
async ensureCliClient(): Promise<void> {
  const existing = await this.storage.get('client:id_org_ai_cli')
  if (existing) return

  await this.storage.put('client:id_org_ai_cli', {
    id: 'id_org_ai_cli',
    name: 'id.org.ai CLI',
    redirectUris: [],
    grantTypes: ['urn:ietf:params:oauth:grant-type:device_code'],
    responseTypes: [],
    scopes: ['openid', 'profile', 'email', 'offline_access'],
    trusted: true,
    tokenEndpointAuthMethod: 'none',
    createdAt: Date.now(),
  })
}
```

Then, in the worker route that handles device authorization (search `worker/index.ts` for the `/oauth/device` route or where the OAuthProvider is used), call `ensureCliClient()` before delegating to the provider. Look for where the IdentityDO stub is obtained for OAuth operations and add:

```typescript
await stub.ensureCliClient()
```

This ensures the client exists the first time anyone tries to use device flow.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/chrisrisner/Workspace/dot-do/headless.ly/.org.ai/id && pnpm vitest run test/oauth-client-seeding.test.ts`
Expected: PASS

- [ ] **Step 5: Run full test suite + build**

Run: `cd /Users/chrisrisner/Workspace/dot-do/headless.ly/.org.ai/id && pnpm test && pnpm build`
Expected: All tests pass, build succeeds

- [ ] **Step 6: Commit**

```bash
git add src/do/Identity.ts worker/index.ts test/oauth-client-seeding.test.ts
git commit -m "feat: seed id_org_ai_cli OAuth client on first device flow request"
```

---

## Task 8: Final integration test + cleanup

**Files:**
- All files from tasks 1-7

- [ ] **Step 1: Run full test suite**

Run: `cd /Users/chrisrisner/Workspace/dot-do/headless.ly/.org.ai/id && pnpm test`
Expected: All tests pass (271 original + ~20 new)

- [ ] **Step 2: Run build**

Run: `cd /Users/chrisrisner/Workspace/dot-do/headless.ly/.org.ai/id && pnpm build`
Expected: Build succeeds with all entry points

- [ ] **Step 3: Verify `vitest.node.config.ts` includes new test files**

Check that the Node vitest config includes the new test files (`test/claim-client.test.ts`, `test/provision-storage.test.ts`, `test/cli-provision.test.ts`, `test/cli-claim.test.ts`). These must NOT run under the workers pool config. Update the include/exclude patterns if needed.

- [ ] **Step 4: Run typecheck**

Run: `cd /Users/chrisrisner/Workspace/dot-do/headless.ly/.org.ai/id && pnpm typecheck`
Expected: No type errors

- [ ] **Step 5: Manual smoke test — provision**

Run: `cd /Users/chrisrisner/Workspace/dot-do/headless.ly/.org.ai/id && node dist/cli/index.js provision --json`

If the worker is deployed, this should return a JSON provision result. If not deployed, expect a network error (acceptable — confirms CLI wiring works).

- [ ] **Step 6: Verify CLI help output**

Run: `cd /Users/chrisrisner/Workspace/dot-do/headless.ly/.org.ai/id && node dist/cli/index.js --help`
Expected: Output includes `provision` and `claim` in command list

- [ ] **Step 7: Final commit if any cleanup needed**

```bash
git add -A
git commit -m "chore: final cleanup for CLI provision and claim"
```

- [ ] **Step 8: Push to origin**

```bash
git push origin main
```
