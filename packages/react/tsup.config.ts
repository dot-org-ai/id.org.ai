import { defineConfig } from 'tsup'

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm'],
  dts: true,
  sourcemap: true,
  clean: true,
  splitting: false,
  external: ['react', 'react-dom'],
  // No banner here — each source file has 'use client' inline where needed.
  // index.ts is a type-only barrel and must NOT have 'use client'.
})
