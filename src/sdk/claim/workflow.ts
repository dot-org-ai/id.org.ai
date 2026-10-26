/**
 * A claim token as id.org.ai issues it (`clm_` and hex). It is written into a
 * YAML string the claim command commits and pushes, so anything else (a quote,
 * a newline) could reshape the workflow: refuse it.
 */
const CLAIM_TOKEN = /^clm_[A-Za-z0-9_-]{1,128}$/

export function isClaimToken(value: unknown): value is string {
  return typeof value === 'string' && CLAIM_TOKEN.test(value)
}

export function buildClaimWorkflow(claimToken: string): string {
  if (!isClaimToken(claimToken)) {
    throw new Error('Invalid claim token: expected clm_ followed by letters, digits, - or _')
  }

  // Every branch: the first push, wherever it lands, claims (pending) and so
  // binds the token to this repository before anyone who copies it can (H1).
  // A push to the default branch finalises the claim.
  return `name: Claim headless.ly tenant
on:
  push:
    branches: ['**']
permissions:
  id-token: write
  contents: read
jobs:
  claim:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dot-org-ai/id@v1
        with:
          tenant: '${claimToken}'
`
}
