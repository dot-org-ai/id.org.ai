/**
 * Redirect relays: where a listed app forwards the browser after it takes the
 * authorization code.
 *
 * Chrome holds a form post's whole redirect chain to the page's CSP
 * `form-action`, not just the first hop. Our consent and code forms allow the
 * app's own origin, which is enough for an app that keeps the browser. An app
 * that forwards it to a second origin of its own gets stopped at that hop: the
 * page sits on "Allowing…" and the person never gets back.
 *
 * Seen live 2026-11-20: OpenAI's developer console connects an MCP server with
 * redirect_uri https://chatgpt.com/connector/oauth/…, and chatgpt.com answers
 * with a 302 to https://platform.openai.com/apps-manage/oauth/….
 *
 * Operator-seeded, like the resource brands: an entry is added here by hand,
 * in a reviewed change, and nothing in a request can add one. An entry only
 * widens `form-action` on a page whose redirect_uri is already at the listed
 * origin; it never changes where the code is sent.
 */
const RELAYS: Readonly<Record<string, readonly string[]>> = {
  'https://chatgpt.com': ['https://platform.openai.com'],
}

/** The origin a form's redirect goes to, plus any origins that app is known to forward the browser to. */
export function withRelayOrigins(origin: string): string[] {
  return [origin, ...(RELAYS[origin] ?? [])]
}
