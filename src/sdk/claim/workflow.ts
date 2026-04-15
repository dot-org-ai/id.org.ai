export function buildClaimWorkflow(claimToken: string): string {
  if (!claimToken || !claimToken.startsWith('clm_')) {
    throw new Error('Invalid claim token: must start with clm_')
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
