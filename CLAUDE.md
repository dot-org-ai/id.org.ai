# CLAUDE.md

This file provides guidance to Claude Code when working on the id.org.ai codebase.

## Project Overview

**id.org.ai — Agent-First Identity**

"Humans. Agents. Identity."

id.org.ai is an open identity standard for the agent era. It provides universal identity for humans (via WorkOS AuthKit), AI agents (via Ed25519 keypairs and GitHub identity), and organizations (groups of both). This is the core primitive of identity and auth — .do, .studio, headless.ly, and any third-party application can build on top of it.

The core innovation is **claim-by-commit**: agents operate anonymously first, then the human claims the tenant by committing a GitHub Action workflow file. The commit IS the identity — GitHub authenticates who pushed.

## Architecture

See `README.md` for the full architecture document, including:
- Connect → Operate → Claim flow
- Three auth layers (Anonymous, Cryptographic, Identity)
- Progressive capability tiers (L0-L3)
- Claim-by-commit via GitHub App + Action
- Migration plan from org.ai

## Build & Development

```bash
pnpm install              # Install dependencies
pnpm build                # Build all (src + worker + action)
pnpm dev                  # Watch mode
pnpm test                 # Run tests (vitest)
pnpm typecheck            # Type-check
pnpm deploy               # Deploy worker to Cloudflare
```

## Repository Structure

```
src/                       # npm package source (id.org.ai or org.ai)
  index.ts                 # Main exports
  do/Identity.ts           # IdentityDO — root Durable Object
  db/schema.ts             # Drizzle schema (identities, sessions, etc.)
  oauth/provider.ts        # OAuth 2.1 provider
  mcp/auth.ts              # MCP authentication for agents
  auth/                    # Auth utilities
  github/                  # GitHub App webhook + Action claim logic
  claim/                   # Claim-by-commit orchestration
worker/                    # Cloudflare Worker
  index.ts                 # Hono app entry point
  wrangler.jsonc           # Worker configuration
action/                    # GitHub Action
  action.yml               # Action definition
  src/index.ts             # Action runtime
```

## Code Style

- TypeScript, ESM (`"type": "module"`)
- No semicolons, single quotes, 2-space indent (Prettier)
- Strict mode, target ES2022
- Hono for HTTP routing
- Drizzle ORM for D1/SQLite
- better-auth for session management
- WorkOS SDK for human auth

## Key Concepts

### Identity Types

- **human** — Users with email/OAuth. Authenticated via WorkOS AuthKit (SSO, social, MFA)
- **agent** — AI agents with Ed25519 keypairs and capabilities. Authenticated via API key or signed requests
- **service** — Platform services and integrations. Authenticated via service bindings or client credentials

### Claim Flow

1. Agent connects to MCP with no auth → gets anonymous sandbox (Level 0-1)
2. Agent operates, creates data, proves value
3. Agent creates `.github/workflows/headlessly.yml` with claim token
4. Agent commits to repo → GitHub authenticates the pusher
5. GitHub App webhook + Action confirm the claim
6. Tenant upgraded to Level 2 (persistent, GitHub-linked)

### OAuth 2.1

Full provider implementation:
- Authorization Code + PKCE (mandatory per OAuth 2.1)
- Refresh tokens with rotation
- Client credentials for service-to-service
- Dynamic Client Registration (RFC 7591)
- OIDC Discovery (`/.well-known/openid-configuration`)
- Device Flow (RFC 8628) for agents without browsers

### Progressive Capability Tiers

| Level | Auth | Capabilities |
|-------|------|-------------|
| L0 | None | Read-only (search, fetch, explore) |
| L1 | Session token | Write (do, try, claim) — 1K entities, 24h TTL |
| L2 | GitHub-linked | Persistent, webhooks, export — Stripe test mode |
| L3 | Full | Production integrations, invite, plan-based limits |

## Testing

Framework: Vitest. Tests in `test/` directory. Worker tests use `@cloudflare/vitest-pool-workers`.

## Deployment

- **Worker**: Deploys to Cloudflare via `wrangler deploy`
- **Routes**: `id.org.ai` and `auth.org.ai` custom domains
- **D1**: `id-org-ai` database
- **KV**: `SESSIONS` namespace
- **Secrets**: `WORKOS_API_KEY`, `WORKOS_CLIENT_ID`, `AUTH_SECRET`, `JWKS_SECRET`, `GITHUB_APP_PRIVATE_KEY`, `GITHUB_APP_ID`

## Issue Tracking

Uses beads (`bd`):
```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --status in_progress
bd close <id>
bd sync               # Sync with git
```
