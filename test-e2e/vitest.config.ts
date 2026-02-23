import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['test-e2e/**/*.e2e.test.ts'],
    testTimeout: 120_000,
    hookTimeout: 60_000,
    pool: 'forks',
    retry: 1,
    sequence: { concurrent: false },
    reporters: ['verbose'],
  },
})
