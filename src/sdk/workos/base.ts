/**
 * The WorkOS API base URL, as one seam.
 *
 * Production always talks to https://api.workos.com. Browser-level flow tests
 * run `wrangler dev` against a local stub (test-visual/workos-stub.mjs) by
 * setting WORKOS_API_BASE in worker/.dev.vars. The worker calls
 * configureWorkOSBase(env) at the start of every request, and every WorkOS
 * helper builds its URLs with workosUrl().
 *
 * The override only accepts loopback origins (localhost, 127.0.0.1, [::1]),
 * so a mis-set variable can never send WorkOS API keys to another host.
 */

export const WORKOS_API_BASE_DEFAULT = 'https://api.workos.com'

let configured: string = WORKOS_API_BASE_DEFAULT

const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]'])

/** The base to use for this env: WORKOS_API_BASE when it is a loopback URL, otherwise the default. */
export function workosBase(env?: { WORKOS_API_BASE?: string }): string {
  const raw = env?.WORKOS_API_BASE
  if (!raw) return WORKOS_API_BASE_DEFAULT
  let url: URL
  try {
    url = new URL(raw)
  } catch {
    return WORKOS_API_BASE_DEFAULT
  }
  if ((url.protocol === 'http:' || url.protocol === 'https:') && LOOPBACK_HOSTS.has(url.hostname)) {
    return url.origin
  }
  return WORKOS_API_BASE_DEFAULT
}

/** Set the base for the helpers in this module tree. Every request of an isolate shares one env. */
export function configureWorkOSBase(env?: { WORKOS_API_BASE?: string }): void {
  configured = workosBase(env)
}

/**
 * True only when this env talks to a local WorkOS stub and `origin` is a
 * loopback origin: local dev may then use its own /api/callback. Production
 * (WORKOS_API_BASE unset) never qualifies.
 */
export function isLocalStubOrigin(env: { WORKOS_API_BASE?: string } | undefined, origin: string): boolean {
  if (workosBase(env) === WORKOS_API_BASE_DEFAULT) return false
  try {
    const url = new URL(origin)
    return (url.protocol === 'http:' || url.protocol === 'https:') && LOOPBACK_HOSTS.has(url.hostname)
  } catch {
    return false
  }
}

/** An absolute WorkOS API URL for `path` (which starts with `/`). */
export function workosUrl(path: string): string {
  return `${configured}${path}`
}
