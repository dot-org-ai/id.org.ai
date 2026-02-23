import { defineConfig } from 'tsup'

export default defineConfig({
  entry: [
    'src/index.ts',
    'src/cli/index.ts',
    'src/db/index.ts',
    'src/auth/index.ts',
    'src/oauth/index.ts',
    'src/mcp/index.ts',
    'src/github/index.ts',
    'src/claim/index.ts',
    'src/jwt/index.ts',
    'src/workos/index.ts',
  ],
  format: ['esm'],
  dts: true,
  sourcemap: true,
  clean: true,
  splitting: false,
  external: ['open', 'drizzle-orm', 'drizzle-orm/sqlite-core', 'cloudflare:workers'],
})
