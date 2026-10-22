/**
 * Private-use-scheme callbacks (RFC 8252 §7.1) that native MCP clients register
 * next to an https and a loopback one. Cursor and Grok Bot send all three in one
 * dynamic registration and fail it if any is refused (forum.cursor.com, Cursor
 * staff, 2026-07-15 and 2026-09-17). Exact strings only, public clients only:
 * any app on a device can claim a private-use scheme (RFC 8252 §8.6), so PKCE
 * S256, already mandatory for public clients, is what keeps an intercepted code
 * from being redeemed.
 */
export const NATIVE_CLIENT_REDIRECTS: ReadonlySet<string> = new Set(['cursor://anysphere.cursor-mcp/oauth/callback'])

/** The schemes of those callbacks (`cursor:`), as CSP scheme-sources for the consent form's redirect. */
export const NATIVE_REDIRECT_SCHEMES: ReadonlySet<string> = new Set(
  [...NATIVE_CLIENT_REDIRECTS].map((uri) => new URL(uri).protocol),
)
