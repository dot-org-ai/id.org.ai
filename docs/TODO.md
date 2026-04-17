# id.org.ai — Remaining Work

## Split `id.org.ai/oauth` into portable vs Hono exports (optional)

**Priority:** Low — do when needed
**Trigger:** When you want `id.org.ai/oauth` installable without Hono as a transitive dependency

### Background

Currently `id.org.ai/oauth` exports both:
- **Portable:** OAuthProvider, types, PKCE, guards, consent, stripe, JWT verify, storage interface, MemoryOAuthStorage
- **Hono-specific:** `createOAuth21Server`, Hono route handlers

Any consumer importing from `id.org.ai/oauth` gets Hono in their bundle even if they only need types or PKCE helpers.

### What to do

1. Create `src/sdk/oauth/server.ts` (or a `server/` subdirectory) for Hono-dependent code
2. Add `id.org.ai/oauth/server` export path in `package.json` and `tsup.config.ts`
3. Move `createOAuth21Server` + Hono route handlers to the new path
4. Update `oauth.do` to import Hono stuff from `id.org.ai/oauth/server` instead of `id.org.ai/oauth`
5. Remove Hono re-exports from `src/sdk/oauth/index.ts`
6. Verify all three consumers still work

### Consumer impact

- **oauth.do** — only consumer of `createOAuth21Server`. Needs one import path change: `from 'id.org.ai/oauth'` → `from 'id.org.ai/oauth/server'`
- **auto-dot-dev/sdk** — no oauth imports, unaffected
- **auto-dot-dev/mcp** — no oauth imports, unaffected

### Scope

~30 minutes of work. Brainstorming skill recommended since it touches oauth.do's architecture.

### References

- Plan doc: `docs/superpowers/plans/2026-04-14-storage-abstraction-and-sdk-separation.md` — "Future Phase: Split oauth exports"
- Design spec (unmerged): `docs/specs/2026-04-14-sdk-server-separation-design.md` — Section 5
