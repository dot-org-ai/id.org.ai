import { defineWorkersConfig } from '@cloudflare/vitest-pool-workers/config'
import { fileURLToPath } from 'node:url'
import { unstable_getMiniflareWorkerOptions, unstable_readConfig } from 'wrangler'

// The pool reuses worker/wrangler.jsonc, so wrangler also loads whatever a
// developer has locally (worker/.dev.vars, or .env / .env.local, and
// process.env when CLOUDFLARE_INCLUDE_PROCESS_ENV is set): the gallery on,
// WORKOS_API_BASE at the local stub, feature flags on. Tests must not depend
// on any of it. Every binding wrangler would add or change beyond
// wrangler.jsonc's own vars is put back to the production value, or blanked
// when production has none. The explicit bindings below then apply as before.
function neutralizeLocalEnv(): Record<string, string> {
  const config = fileURLToPath(new URL('./worker/wrangler.jsonc', import.meta.url))
  const prod = unstable_readConfig({ config }).vars as Record<string, unknown>
  const effective = (unstable_getMiniflareWorkerOptions(config).workerOptions.bindings ?? {}) as Record<string, unknown>
  const out: Record<string, string> = {}
  for (const [key, value] of Object.entries(effective)) {
    const prodValue = prod[key]
    if (prodValue === undefined) out[key] = ''
    else if (typeof prodValue === 'string' && value !== prodValue) out[key] = prodValue
  }
  return out
}

export default defineWorkersConfig({
  esbuild: { jsx: 'automatic', jsxImportSource: 'hono/jsx' },
  test: {
    include: ['test/**/*.test.ts'],
    exclude: ['test/cli.test.ts', 'test/provision-storage.test.ts', 'test/cli-claim.test.ts', 'test/cli-login.test.ts'],
    globals: true,
    poolOptions: {
      workers: {
        wrangler: {
          configPath: './worker/wrangler.jsonc',
        },
        miniflare: {
          compatibilityDate: '2025-01-01',
          compatibilityFlags: ['nodejs_compat'],
          // Test-only stand-in for the WORKOS_API_KEY secret so login/callback
          // routes don't 503; the WorkOS API itself is mocked via fetchMock.
          // LOGIN_CONTINUE_POLICY: production runs `report` (worker/wrangler.jsonc)
          // while estate callers are listed; the suite pins `enforce`, the
          // policy's end state. test/continue-policy.test.ts covers `report`.
          // MAGIC_LINK_CLIENTS: the ids tests seed as allowlisted magic-link
          // callers (test/relying-party.test.ts, test/magic-link-callers.test.ts).
          bindings: {
            ...neutralizeLocalEnv(),
            WORKOS_API_KEY: 'sk_test_vitest_placeholder',
            LOGIN_CONTINUE_POLICY: 'enforce',
            // DLVP is off in production (unset); the suite exercises it.
            // test/dlvp-token-separation.test.ts covers the off state.
            DLVP_ENABLED: 'true',
            MAGIC_LINK_CLIENTS: Array.from({ length: 20 }, (_, i) => `cid_magiclink_test_${String(i + 1).padStart(2, '0')}`).join(','),
          },
          kvNamespaces: ['SESSIONS'],
          durableObjects: {
            IDENTITY: 'IdentityDO',
          },
        },
      },
    },
  },
})
