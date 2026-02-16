import { defineWorkersConfig } from '@cloudflare/vitest-pool-workers/config'

export default defineWorkersConfig({
  test: {
    include: ['test/**/*.test.ts'],
    exclude: ['test/cli.test.ts'],
    globals: true,
    poolOptions: {
      workers: {
        wrangler: {
          configPath: './worker/wrangler.jsonc',
        },
        miniflare: {
          compatibilityDate: '2025-01-01',
          compatibilityFlags: ['nodejs_compat'],
          kvNamespaces: ['SESSIONS'],
          durableObjects: {
            IDENTITY: 'IdentityDO',
          },
        },
      },
    },
  },
})
