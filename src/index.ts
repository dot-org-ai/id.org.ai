/**
 * id.org.ai — Agent-First Identity
 *
 * "Humans. Agents. Identity."
 *
 * SDK-only exports. For Cloudflare-specific code (IdentityDO, services),
 * import from 'id.org.ai/server' instead.
 *
 * Import paths:
 *   - id.org.ai          → SDK (portable)
 *   - id.org.ai/server   → Cloudflare-specific (IdentityDO, services)
 *   - id.org.ai/auth     → Constants, URLs, RPC types
 *   - id.org.ai/oauth    → OAuth provider + types
 *   - id.org.ai/mcp      → MCP auth + tools
 */

// SDK exports (portable)
export * from './sdk'
