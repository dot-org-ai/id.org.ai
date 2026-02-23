/// <reference types="vitest" />
export default {
  test: {
    include: [
      'test/cli.test.ts',
      'test/oauth-types.test.ts',
      'test/oauth-storage.test.ts',
      'test/oauth-pkce.test.ts',
      'test/jwt-signing-parity.test.ts',
      'test/oauth-jwt-verify.test.ts',
      'test/oauth-consent.test.ts',
      'test/oauth-guards.test.ts',
      'test/oauth-dev.test.ts',
      'test/oauth-server.test.ts',
    ],
    globals: true,
  },
}
