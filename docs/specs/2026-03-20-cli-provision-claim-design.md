# CLI Provision & Claim Commands

**Date**: 2026-03-20
**Status**: Draft
**Scope**: CLI commands, SDK exports, OAuth client seeding, workflow extraction

## Problem

The id.org.ai CLI only supports human OAuth login (device flow). Agents have no way to:
1. Create an anonymous sandbox from the terminal
2. Claim that sandbox by committing a workflow file

Additionally, the human login flow is broken because the CLI OAuth client (`id_org_ai_cli`) is not pre-registered in the OAuth provider storage.

## Design

### 1. CLI Commands

#### `id.org.ai provision`

Creates an anonymous sandbox (L1) and stores credentials locally.

```
$ id.org.ai provision
  Tenant:      tnt_abc123
  Session:     ses_xxx...
  Claim Token: clm_xyz...
  Expires:     24 hours

  Next step: id.org.ai claim
```

- Calls `POST /api/provision` (no auth required)
- Stores `sessionToken`, `claimToken`, `tenantId` in `~/.id.org.ai/provision`
- `--json` flag outputs machine-readable JSON for piping

#### `id.org.ai claim`

Generates the claim workflow, commits, and pushes.

```
$ id.org.ai claim
  Generated .github/workflows/headlessly.yml
  Committed: "Claim headless.ly tenant"
  Pushed to origin/main
  Waiting for claim confirmation...
  Tenant claimed! Upgraded to Level 2
```

- Reads stored `claimToken` from `~/.id.org.ai/provision`
- Verifies cwd is a git repo (fails with clear error if not)
- Calls `buildClaimWorkflow(claimToken)` to generate YAML
- Writes `.github/workflows/headlessly.yml`
- Runs `git add`, `git commit -m "Claim headless.ly tenant"`, `git push`
- Polls `GET /api/claim/:token/status` to confirm claim succeeded (timeout after 60s)
- `--json` flag outputs machine-readable JSON for piping
- `--no-push` flag: generate + commit only, skip push
- `--token clm_xxx` override: use explicit token instead of stored one

### 2. SDK Exports

Two layers — **client-side** (HTTP, for CLI and external consumers) and **server-side** (DO RPC, existing).

#### Client-side SDK — `src/claim/client.ts` (new)

HTTP client functions for use outside Cloudflare Workers (CLI, Node scripts, agents):

```typescript
// Provision an anonymous sandbox via HTTP
export async function provision(baseUrl?: string): Promise<ProvisionResult>

// Single fetch of claim status (caller owns the retry loop)
export async function getClaimStatus(claimToken: string, baseUrl?: string): Promise<ClaimStatus>
```

These call the public HTTP API (`POST /api/provision`, `GET /api/claim/:token/status`). They are distinct from the server-side `ClaimService` which operates via Durable Object RPC stubs.

#### Shared utilities — `src/claim/workflow.ts` (new)

Pure functions usable on both client and server:

```typescript
// Generate the GitHub Actions workflow YAML for claim-by-commit
export function buildClaimWorkflow(claimToken: string): string

// Write the claim workflow file to a repo
export async function writeClaimWorkflow(claimToken: string, repoRoot?: string): Promise<string>
```

#### Export structure

From `id.org.ai/claim`:
- `ClaimService`, `verifyClaim` — existing server-side exports
- `buildClaimWorkflow`, `writeClaimWorkflow` — shared utilities (new)
- `provision`, `getClaimStatus` — client-side HTTP functions (new)

### 3. `buildClaimWorkflow` Extraction

Currently lives in `worker/index.ts` (~line 3118). Move to `src/claim/workflow.ts` so both CLI and worker can import it. The worker imports from the shared location — no duplication.

Generated YAML (existing format):

```yaml
name: Claim headless.ly tenant
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
```

### 4. Claim Status Endpoint (New)

The CLI needs to poll for claim confirmation after pushing. Add:

**`GET /api/claim/:token/status`** in `worker/index.ts`:
- Looks up `claim:{token}` in KV to resolve identity ID
- Calls `stub.verifyClaim(token)` on the IdentityDO
- Returns `{ status: 'unclaimed' | 'pending' | 'claimed' | 'expired', level?: number }`
- No auth required (claim token is a capability token)

### 5. Storage Changes

New standalone `ProvisionStorage` class (not extending `SecureFileTokenStorage`) to keep concerns separate:

- `~/.id.org.ai/token` — existing OAuth tokens (login command, unchanged)
- `~/.id.org.ai/provision` — new provision data (JSON: `{ tenantId, sessionToken, claimToken, createdAt }`)

New file: `src/cli/provision-storage.ts`

```typescript
export class ProvisionStorage {
  getProvisionData(): ProvisionData | null
  setProvisionData(data: ProvisionData): void
  removeProvisionData(): void
}
```

### 6. OAuth Client Seeding (Fix)

**Problem**: The CLI uses client ID `id_org_ai_cli` for device flow login, but this client doesn't exist in OAuth provider storage. Every login attempt fails with `invalid_client`.

**Fix**: Seed the CLI client in IdentityDO initialization (or on first request). When the OAuth provider is instantiated, ensure `client:id_org_ai_cli` exists:

```typescript
{
  id: 'id_org_ai_cli',
  name: 'id.org.ai CLI',
  redirectUris: [],
  grantTypes: ['urn:ietf:params:oauth:grant-type:device_code'],
  responseTypes: [],
  scopes: ['openid', 'profile', 'email', 'offline_access'],
  trusted: true,            // first-party, skip consent
  tokenEndpointAuthMethod: 'none',  // public client
  createdAt: Date.now(),
}
```

Location: `src/do/Identity.ts` — lazy initialization on first device-flow request. Check if `client:id_org_ai_cli` exists before writing (avoid redundant writes on every DO wake-up).

### 7. Error Handling

| Scenario | Behavior |
|----------|----------|
| `provision` network error | Print error, suggest retry |
| `provision` server error | Print status code + message |
| `claim` not in git repo | Error: "Not a git repository. Run this from inside the repo you want to claim." |
| `claim` no stored token | Error: "No claim token found. Run `id.org.ai provision` first, or pass `--token clm_xxx`." |
| `claim` git push fails | Error: suggest `--no-push` and manual push |
| `claim` confirmation timeout | Print: "Push succeeded but claim not confirmed yet. Check GitHub Actions tab." |
| `claim` workflow already exists | Warn and overwrite (claim tokens are unique) |
| `claim --no-push` | Skip polling entirely (no push = no webhook/action to trigger) |
| `claim` succeeds | Call `removeProvisionData()` to clean up stale claim token |
| `provision` abuse | Endpoint is unauthenticated — rely on Cloudflare WAF rate limiting per IP |

### 8. Testing

**Unit tests** (mocked fetch + storage):
- `provision()` SDK function: success, network error, server error
- `buildClaimWorkflow()`: output format, token embedding
- `writeClaimWorkflow()`: file creation, directory creation
- Storage: provision data read/write/remove
- CLI commands: argument parsing, output format, `--json` flag

**Integration tests**:
- `provision` → `claim` pipeline with mocked git
- OAuth client seeding: verify `id_org_ai_cli` exists after DO init

**E2E tests** (stretch goal):
- Device flow login end-to-end
- Provision → claim → verify upgrade to L2

### 9. Out of Scope

- `--repo` flag for remote repos (cwd only)
- GitHub API integration (standard git commands)
- Interactive prompts (agents can't answer them)
- Key sync / Ed25519 keypairs (Phase 3)
- OIDC token validation hardening (separate work item)

## File Changes

| File | Change |
|------|--------|
| `src/cli/index.ts` | Add `provision` and `claim` to switch/case + update `printHelp()` |
| `src/cli/provision.ts` | New — `provisionCommand()` implementation |
| `src/cli/claim.ts` | New — `claimCommand()` implementation |
| `src/cli/provision-storage.ts` | New — `ProvisionStorage` class (separate from token storage) |
| `src/claim/workflow.ts` | New — extract `buildClaimWorkflow()` from worker |
| `src/claim/client.ts` | New — HTTP client SDK (`provision()`, `pollClaimStatus()`) |
| `src/claim/index.ts` | Re-export workflow + client SDK functions |
| `worker/index.ts` | Import `buildClaimWorkflow` from shared; add `GET /api/claim/:token/status` |
| `src/do/Identity.ts` | Add `ensureCliClient()` for OAuth client seeding |
| `test/cli-provision.test.ts` | New — provision command tests |
| `test/cli-claim.test.ts` | New — claim command tests |
| `test/claim-workflow.test.ts` | New — workflow generation tests |
| `test/worker-routes.test.ts` | Update — import `buildClaimWorkflow` from shared, remove mirror copy |
| `test/oauth-client-seeding.test.ts` | New — client registration tests |
| `tsup.config.ts` | No change (claim entry point already exists) |

## Dependencies

- No new npm dependencies
- Uses existing: `child_process` (for git commands), `fs/promises` (for file writes)
- `buildClaimWorkflow` has zero dependencies (pure string template)
