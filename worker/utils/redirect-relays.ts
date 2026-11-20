/**
 * Apps that forward the browser to a second origin after taking the code.
 * Chrome applies CSP form-action to the whole redirect chain, so both must be listed.
 * Hand-kept. Widens form-action only; never changes where the code goes.
 */
const RELAYS: Readonly<Record<string, readonly string[]>> = {
  // OpenAI dev console: chatgpt.com/connector/oauth 302s to platform.openai.com
  'https://chatgpt.com': ['https://platform.openai.com'],
}

/** origin + its known relay origins */
export function withRelayOrigins(origin: string): string[] {
  return [origin, ...(RELAYS[origin] ?? [])]
}
