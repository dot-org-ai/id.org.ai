/**
 * id.org.ai — Agent-First Identity
 *
 * "Humans. Agents. Identity."
 *
 * This is the compatibility shim. It re-exports from sdk/ and server/
 * so existing consumers keep working.
 *
 * New consumers should import from specific paths:
 *   - id.org.ai          → SDK (portable)
 *   - id.org.ai/server   → Cloudflare-specific (IdentityDO, services)
 *   - id.org.ai/auth     → Constants, URLs, RPC types
 *   - id.org.ai/oauth    → OAuth provider + types
 *   - id.org.ai/mcp      → MCP auth + tools
 */

// SDK exports (portable)
export * from './sdk'

// Server exports (Cloudflare-specific) — deprecated from main barrel
// Consumers should use 'id.org.ai/server' instead
export { IdentityDO } from './server/do/Identity'
export type { Identity, IdentityType, IdentityEnv } from './server/do/Identity'
