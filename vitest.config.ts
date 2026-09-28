import { defineWorkersConfig } from '@cloudflare/vitest-pool-workers/config'

export default defineWorkersConfig({
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
