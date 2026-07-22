/**
 * MCP OAuth 2.1 resource-server helpers (RFC 9728 / RFC 8707).
 *
 * The /mcp endpoint is an OAuth 2.1 protected resource. These helpers produce
 * the canonical identifiers an MCP client needs to discover the authorization
 * server and audience-bind its token:
 *
 *   - `mcpResourceUri(origin)`      → the RFC 8707 audience the client sends as
 *                                     the `resource` parameter and that the
 *                                     resource server enforces as the token
 *                                     audience (`https://<origin>/mcp`).
 *   - `protectedResourceMetadataUrl` → RFC 9728 default protected-resource
 *                                     metadata location (root well-known).
 *   - `mcpWwwAuthenticate(origin)`   → the RFC 9728 §5.1 / RFC 6750
 *                                     `WWW-Authenticate` challenge value that
 *                                     points MCP clients at that metadata.
 *
 * Everything is derived from the request origin so the discovery chain, the
 * audience binding, and the api.qa conformance probe all line up on whatever
 * origin the client actually reached (production or local `wrangler dev`).
 */

function trimSlash(s: string): string {
  return s.replace(/\/$/, '')
}

/** The canonical RFC 8707 audience for the MCP endpoint: `<origin>/mcp`. */
export function mcpResourceUri(origin: string): string {
  return `${trimSlash(origin)}/mcp`
}

/**
 * RFC 9728 default protected-resource metadata URL. api.qa (and most MCP
 * clients) resolve the metadata at the ROOT well-known path derived from the
 * MCP origin, so this is what the WWW-Authenticate challenge references.
 */
export function protectedResourceMetadataUrl(origin: string): string {
  return `${trimSlash(origin)}/.well-known/oauth-protected-resource`
}

/** RFC 9728 §5.1 / RFC 6750 challenge pointing at the protected-resource metadata. */
export function mcpWwwAuthenticate(origin: string, error?: string, description?: string): string {
  let v = `Bearer resource_metadata="${protectedResourceMetadataUrl(origin)}"`
  if (error) v += `, error="${error}"`
  if (description) v += `, error_description="${description.replace(/"/g, "'")}"`
  return v
}

/** True when the request path is the MCP endpoint (`/mcp` or `/mcp/...`). */
export function isMcpPath(pathname: string): boolean {
  return pathname === '/mcp' || pathname.startsWith('/mcp/')
}
