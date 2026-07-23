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
          bindings: { WORKOS_API_KEY: 'sk_test_vitest_placeholder' },
          kvNamespaces: ['SESSIONS'],
          durableObjects: {
            IDENTITY: 'IdentityDO',
          },
        },
      },
    },
  },
})
