/// <reference types="vitest" />
export default {
  test: {
    include: ['test/cli.test.ts', 'test/oauth-types.test.ts', 'test/oauth-storage.test.ts', 'test/oauth-pkce.test.ts'],
    globals: true,
  },
}
