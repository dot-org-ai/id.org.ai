import { defineConfig } from 'tsup'

export default defineConfig({
  entry: [
    'src/index.ts',           // compatibility shim
    'src/sdk/index.ts',       // SDK barrel
    'src/sdk/cli/index.ts',
    'src/sdk/cli/device.ts',
    'src/sdk/cli/auth.ts',
    'src/sdk/cli/storage.ts',
    'src/sdk/auth/index.ts',
    'src/sdk/oauth/index.ts',
    'src/sdk/mcp/index.ts',
    'src/sdk/github/index.ts',
    'src/sdk/claim/index.ts',
    'src/sdk/jwt/index.ts',
    'src/sdk/workos/index.ts',
    'src/server/index.ts',    // server barrel
  ],
  format: ['esm'],
  dts: true,
  sourcemap: true,
  clean: true,
  splitting: false,
  external: ['open', 'cloudflare:workers'],
})
