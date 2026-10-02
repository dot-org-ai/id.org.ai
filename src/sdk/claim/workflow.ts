/**
 * A claim token as id.org.ai issues it (`clm_` and hex). It is written into a
 * YAML string the claim command commits and pushes, so anything else (a quote,
 * a newline) could reshape the workflow: refuse it.
 */
const CLAIM_TOKEN = /^clm_[A-Za-z0-9_-]{1,128}$/

export function buildClaimWorkflow(claimToken: string): string {
  if (!claimToken || !CLAIM_TOKEN.test(claimToken)) {
    throw new Error('Invalid claim token: expected clm_ followed by letters, digits, - or _')
  }

  return `name: Claim headless.ly tenant
on:
  push:
    branches: [main, master]
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
