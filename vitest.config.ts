import { defineWorkersConfig } from '@cloudflare/vitest-pool-workers/config'
import { existsSync, readFileSync } from 'node:fs'
import { unstable_readConfig } from 'wrangler'

// The pool reuses worker/wrangler.jsonc, so wrangler also loads a developer's
// local worker/.dev.vars (gallery on, WORKOS_API_BASE at the local stub,
// feature flags on). Tests must not depend on it: every key it sets is put
// back to its wrangler.jsonc value, or blanked when production has none. The
// explicit bindings below then apply as before.
function neutralizeDevVars(): Record<string, string> {
  const path = './worker/.dev.vars'
  if (!existsSync(path)) return {}
  const prodVars = unstable_readConfig({ config: './worker/wrangler.jsonc' }).vars as Record<string, unknown>
  const out: Record<string, string> = {}
  for (const line of readFileSync(path, 'utf8').split('\n')) {
    const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=/)
    if (m) out[m[1]!] = typeof prodVars[m[1]!] === 'string' ? (prodVars[m[1]!] as string) : ''
  }
  return out
}

export default defineWorkersConfig({
  esbuild: { jsx: 'automatic', jsxImportSource: 'hono/jsx' },
  test: {
    include: ['test/**/*.test.ts'],
    exclude: ['test/cli.test.ts', 'test/provision-storage.test.ts', 'test/cli-claim.test.ts'],
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
            ...neutralizeDevVars(),
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
