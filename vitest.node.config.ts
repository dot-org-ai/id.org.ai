/// <reference types="vitest" />
export default {
  test: {
    include: ['test/cli.test.ts', 'test/oauth-types.test.ts'],
    globals: true,
  },
}
