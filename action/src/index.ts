/**
 * dot-org-ai/id@v1 — GitHub Action
 *
 * Claims an anonymous headless.ly tenant by linking it to the
 * GitHub identity of the person who triggered the action.
 *
 * Uses GitHub Actions OIDC tokens (not PATs) for authentication.
 *
 * Usage in .github/workflows/headlessly.yml:
 *   - uses: dot-org-ai/id@v1
 *     with:
 *       tenant: clm_abc123
 */

import { verifyClaimFromAction } from '../../src/github/action'

async function run() {
  const tenant = process.env.INPUT_TENANT
  if (!tenant) {
    console.error('Missing required input: tenant')
    process.exit(1)
  }

  const oidcToken = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN
  if (!oidcToken) {
    console.error('OIDC token not available. Add `permissions: { id-token: write }` to your workflow.')
    process.exit(1)
  }

  const result = await verifyClaimFromAction({
    tenant,
    oidcToken,
    repo: process.env.GITHUB_REPOSITORY ?? '',
    branch: (process.env.GITHUB_REF ?? '').replace('refs/heads/', ''),
    actor: process.env.GITHUB_ACTOR ?? '',
    actorId: process.env.GITHUB_ACTOR_ID ?? '',
  })

  if (result.success) {
    console.log(`Tenant claimed successfully.`)
    console.log(`  Tenant ID: ${result.tenantId}`)
    console.log(`  Level: ${result.level}`)
    // Set outputs for subsequent steps
    console.log(`::set-output name=tenant-id::${result.tenantId}`)
    console.log(`::set-output name=level::${result.level}`)
  } else {
    console.error(`Claim failed: ${result.error}`)
    process.exit(1)
  }
}

run()
