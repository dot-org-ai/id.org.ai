import { defineConfig } from 'vitest/config'
import { resolve } from 'path'
import { existsSync } from 'fs'

// Load .env from test-e2e/, .org.ai/id/, or root project
const envFiles = [
  resolve(__dirname, '.env'),
  resolve(__dirname, '..', '.env'),
  resolve(__dirname, '..', '..', '..', '.env'),
].filter(existsSync)

export default defineConfig({
  envDir: envFiles[0] ? resolve(envFiles[0], '..') : undefined,
  test: {
    include: ['test-e2e/**/*.e2e.test.ts'],
    testTimeout: 120_000,
    hookTimeout: 60_000,
    pool: 'forks',
    retry: 1,
    sequence: { concurrent: false },
    reporters: ['verbose'],
    env: {
      // Ensure dotenv files are loaded in forked processes
      NODE_ENV: 'test',
    },
  },
})
