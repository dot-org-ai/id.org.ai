# id.org.ai — Agent-First Identity

**Humans. Agents. Identity.**

id.org.ai is an open identity standard for the agent era. It provides a single identity system for humans (via WorkOS AuthKit), AI agents (via cryptographic keypairs and GitHub identity), and organizations (groups of both). Any platform can build on it — [.org.ai](https://schema.org.ai), [.do](https://platform.do), [.studio](startups.studio), and hundreds of thousands of other third-party applications all use id.org.ai as their identity layer.

The core insight: **the commit IS the identity**. GitHub already authenticates who pushes. An agent that commits a workflow file to a repo has its identity verified by GitHub's infrastructure. id.org.ai turns that signal into a claim.

## The Problem

Every agent-first product faces the same chicken-and-egg: the agent needs to try the product before the human will pay for it, but the product requires authentication before the agent can try it. CAPTCHAs, email verification, OAuth consent screens, "contact sales" — all designed for humans clicking buttons in browsers. Agents can't click.

The result: agents evaluate products by reading documentation instead of running code. The agent recommends tools it has never used. The human buys software no agent has tested.

## The Architecture

### Connect → Operate → Claim

```
T+0s     Agent adds MCP config:  { "url": "https://headless.ly/mcp" }
T+0.1s   Connects — no auth. Server provisions sandbox Durable Object.
T+0.2s   explore() → reads all 32 entity schemas with verbs and relationships
T+1s     try([create Contact, create Deal, close Deal]) → sees full lifecycle with rollback
T+2s     provision({ name: 'acme' }) → gets Level 1 sandbox tenant (real DO, real data)
T+3s     do(Contact.create, Deal.create, ...) → operates for real
T+5min   Agent has built a functioning CRM — 47 contacts, 12 deals, 3 workflows
T+5min   claim({ provider: 'github' }) → returns one-time claim URL
T+5min   Agent tells human: "I set up your business operations. Claim it: [url]"
T+5.1min Human clicks link → GitHub OAuth via WorkOS → 10 seconds
T+5.2min Tenant rebound to GitHub identity. Same DO. Same data. Limits removed.

Total agent time: ~5 minutes. Total human time: ~10 seconds.
```

The agent operates first, proves value, then the human claims. Not the reverse.

### Three Auth Layers

| Layer | Mechanism | When | Human Involvement |
|-------|-----------|------|-------------------|
| **Anonymous** | No auth — MCP connection creates sandbox | First contact | None |
| **Cryptographic** | Agent Ed25519 keypair, signed requests | Ongoing operation | None |
| **Identity** | GitHub OAuth (Device Flow or claim URL) | When agent proves value | One click |

### Progressive Capability Tiers

| Level | Auth | Tools | Limits | Integrations |
|-------|------|-------|--------|--------------|
| **0 — Anonymous** | None | search, fetch, explore | Read-only, 30 req/min | None |
| **1 — Sandboxed** | Session token | + do, try, claim | 1,000 entities, 24h TTL | Stubbed (realistic mocks) |
| **2 — Claimed** | GitHub-linked | + subscribe, webhook, export | Persistent, no entity limit | Stripe test mode, GitHub read |
| **3 — Production** | Full | + invite, integrate | Plan-based rate limits | Live Stripe, full GitHub sync |

Every MCP `_meta` response includes the current level, available actions, and exact instructions to upgrade. Errors are remediation guides, not rejections.

## Claim-by-Commit

The primary claim mechanism uses GitHub as the identity bridge — via both a **GitHub App** and a **GitHub Action** at the `dot-org-ai` GitHub org.

### The Flow

1. Agent operates headless.ly anonymously → gets sandbox tenant `anon_7kx9m2` with claim token `clm_abc123`
2. Agent decides the product is useful → creates a workflow file:

```yaml
# .github/workflows/headlessly.yml
name: headless.ly
on: [push]
jobs:
  identity:
    runs-on: ubuntu-latest
    steps:
      - uses: dot-org-ai/id@v1
        with:
          tenant: clm_abc123
```

3. Agent commits this to the repo (main OR a branch)
4. **The commit itself IS the claim** — GitHub authenticates who pushed
5. Two things happen simultaneously:
   - **GitHub App** (`dot-org-ai/id`) receives the push webhook → sees the workflow file → links the GitHub identity to the anonymous tenant
   - **GitHub Action** (`dot-org-ai/id@v1`) runs → registers the repo's identity with id.org.ai → confirms the claim
6. Tenant is now claimed. The agent's next MCP request sees upgraded capabilities.

### Why Branches Work

- The agent can create a `headlessly/setup` branch and commit there
- The GitHub App still receives the push webhook on the branch
- The human can review the PR before merging to main
- Even on a branch, the push is authenticated — GitHub knows who pushed
- Claim is "pending" on a branch, "confirmed" on main merge

### The Identity Chain

```
Git push → GitHub authenticates the pusher (human's GitHub account)
         → GitHub App sees the push (knows the repo + user)
         → Workflow file contains the claim token (links to anonymous tenant)
         → id.org.ai links: GitHub user ↔ anonymous tenant ↔ agent keypair
```

### Ongoing Identity

Once installed, the GitHub Action runs on every push and can:
- Refresh the agent's credentials
- Sync any new `.headless.ly/agents/*.pub` files (Ed25519 public keys)
- Report repo activity to the tenant's event log
- Keep the identity link alive

## Package Structure

```
.org.ai/id/                        # This repo (dot-org-ai/id.org.ai)
├── src/
│   ├── index.ts                   # Main exports
│   ├── do/
│   │   └── Identity.ts            # IdentityDO — root DO for the platform
│   ├── db/
│   │   ├── index.ts               # Re-exports
│   │   └── schema.ts              # Drizzle schema (identities, sessions, linked_accounts, etc.)
│   ├── oauth/
│   │   ├── index.ts               # Re-exports
│   │   └── provider.ts            # OAuth 2.1 provider (auth code + PKCE, tokens, consent)
│   ├── mcp/
│   │   ├── index.ts               # Re-exports
│   │   └── auth.ts                # MCP authentication (API keys, sessions, capabilities)
│   ├── auth/
│   │   ├── index.ts               # Auth utilities
│   │   └── stripe-connect.ts      # Stripe Connect URL generation
│   ├── github/                    # NEW
│   │   ├── app.ts                 # GitHub App webhook handler
│   │   └── action.ts              # GitHub Action claim logic
│   └── claim/                     # NEW
│       ├── index.ts               # Claim orchestration
│       ├── provision.ts           # Anonymous tenant provisioning
│       └── verify.ts              # Claim verification
├── worker/
│   ├── index.ts                   # Cloudflare Worker (Hono app)
│   ├── oauth-do.ts                # OAuthDO (OAuth 2.1 authorization server)
│   └── wrangler.jsonc             # Worker config (id.org.ai, auth.org.ai routes)
├── action/                        # GitHub Action
│   ├── action.yml                 # Action definition
│   └── src/index.ts               # Action runtime
├── package.json                   # npm: id.org.ai (or org.ai — TBD)
├── tsconfig.json
├── CLAUDE.md                      # AI assistant guidance
└── README.md                      # This file
```

## Migration from org.ai

Everything identity-related migrates from `.org.ai/org.ai/` into this repo. The `org.ai` npm package either becomes a thin re-export of `id.org.ai` or is deprecated. id.org.ai is the canonical identity standard — `org.ai` was a stepping stone.

### What Moves Here

| Source | Destination | Notes |
|--------|-------------|-------|
| `.org.ai/org.ai/src/do/Identity.ts` | `src/do/Identity.ts` | Core IdentityDO — extend with claim/provision |
| `.org.ai/org.ai/src/db/schema.ts` | `src/db/schema.ts` | All 12 identity tables — add claim fields |
| `.org.ai/org.ai/src/db/index.ts` | `src/db/index.ts` | Re-exports |
| `.org.ai/org.ai/src/oauth/provider.ts` | `src/oauth/provider.ts` | OAuth 2.1 provider |
| `.org.ai/org.ai/src/oauth/index.ts` | `src/oauth/index.ts` | Re-exports |
| `.org.ai/org.ai/src/mcp/auth.ts` | `src/mcp/auth.ts` | MCP authentication |
| `.org.ai/org.ai/src/mcp/index.ts` | `src/mcp/index.ts` | Re-exports |
| `.org.ai/org.ai/src/auth/index.ts` | `src/auth/index.ts` | Auth utilities |
| `.org.ai/org.ai/src/auth/stripe-connect.ts` | `src/auth/stripe-connect.ts` | Stripe Connect |
| `.do/workers/workers/id.org.ai/src/index.ts` | `worker/index.ts` | Worker entry point |
| `.do/workers/workers/id.org.ai/src/oauth-do.ts` | `worker/oauth-do.ts` | OAuthDO |
| `.do/workers/workers/id.org.ai/wrangler.jsonc` | `worker/wrangler.jsonc` | Worker config |

### What Stays in org.ai

The `org.ai` npm package (`.org.ai/org.ai/`) may still exist as a thin wrapper that re-exports from `id.org.ai`, or it may be deprecated entirely. The non-identity concerns (if any exist) stay there.

### What's New (Not in Either Source)

| File | Purpose |
|------|---------|
| `src/github/app.ts` | GitHub App webhook handler for push events |
| `src/github/action.ts` | GitHub Action claim verification |
| `src/claim/index.ts` | Claim orchestration (anonymous → claimed) |
| `src/claim/provision.ts` | Sandbox tenant provisioning |
| `src/claim/verify.ts` | Claim token verification |
| `action/action.yml` | GitHub Action definition |
| `action/src/index.ts` | GitHub Action runtime |

## Key Design Decisions

### No Sandbox Distinction

Anonymous tenants ARE production tenants — same Durable Object, same schema, same event log. The only differences are entity limits and integration access. Claiming a tenant is a metadata update, not a data migration. The Durable Object is the same before and after.

### Freeze, Don't Delete

Expired anonymous tenants freeze — data preserved 30 days in R2 cold storage. The freeze response shows what the agent built: "47 contacts, 12 deals, 89 tasks." Sunk cost drives claiming.

### The `try` Tool

Execute-with-rollback is architecturally clean with event sourcing: run the workflow, emit events to a temporary branch, show the agent exactly what would happen, then discard the branch. External integrations get stubbed mocks during `try`.

### CIMD vs DCR

The MCP spec moved to CIMD (Client ID Metadata Documents) as the default. For anonymous onboarding, neither is needed at Level 0. At Level 2+, GitHub identity serves as the client identifier. DCR (`POST /oauth2/register`) is already implemented.

### WorkOS as the Human Layer

id.org.ai wraps WorkOS AuthKit for all human authentication. The custom AuthKit domain is `id.org.ai`. WorkOS handles SSO, social login, MFA, enterprise directory sync. id.org.ai adds the agent layer on top.

## Implementation Phases

### Phase 1: Anonymous → Sandboxed (Level 0 → 1)

- Accept unauthenticated MCP connections
- Auto-provision sandbox Durable Objects
- Return session tokens in MCP `_meta`
- Implement `explore` and `try` tools
- Add `claimToken`, `claimStatus`, `anonymousExpiresAt` to identities schema

### Phase 2: Claim-by-Commit (Level 1 → 2)

- Build GitHub App (`dot-org-ai/id`) — push webhook handler
- Build GitHub Action (`dot-org-ai/id@v1`) — OIDC claim confirmation
- New endpoints: `POST /api/claim`, `POST /api/provision`, `GET /api/tenant/:token`
- Link anonymous identity to GitHub account on claim

### Phase 3: Cryptographic Identity (Level 2 → 3)

- Ed25519 keypair generation (`~/.config/headlessly/agent.seed`)
- Public key exchange via `.headless.ly/agents/*.pub` in git
- DID format: `did:agent:ed25519:{base58pubkey}`
- Capability tokens for agent-to-agent delegation
- New tables: `agent_keys`, `capability_tokens`

### Phase 4: Production Integrations (Level 3)

- Live Stripe Connect via linked accounts
- Full GitHub sync (bidirectional for Projects entities)
- Webhook delivery for event subscriptions
- Multi-tenant invite flow
