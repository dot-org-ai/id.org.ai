/**
 * Auth UI tests that need the host filesystem or a DOM: client scripts, the
 * tokens-equality check and component markup contracts (worker/ui/**). The
 * workers pool (vitest.config.ts) can't provide either.
 */
import { defineConfig } from 'vitest/config'

export default defineConfig({
  esbuild: { jsx: 'automatic', jsxImportSource: 'hono/jsx' },
  test: {
    include: ['worker/ui/**/*.test.ts', 'worker/ui/**/*.test.tsx'],
    environment: 'happy-dom',
    globals: true,
  },
})
