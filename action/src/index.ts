/**
 * dot-org-ai/id@v1 — GitHub Action
 *
 * Claims an anonymous headless.ly tenant by linking it to the
 * GitHub identity of the person who triggered the action.
 *
 * Uses GitHub Actions OIDC tokens (not PATs) for authentication.
 *
 * Usage in .github/workflows/headlessly.yml:
 *   permissions:
 *     id-token: write
 *     contents: read
 *   steps:
 *     - uses: actions/checkout@v4
 *     - uses: dot-org-ai/id@v1
 *       with:
 *         tenant: clm_abc123
 */

import {
  requestOIDCToken,
  verifyClaimFromAction,
  setOutput,
  setError,
  setNotice,
  writeTenantConfig,
} from '../../src/github/action'

async function run() {
  // ── Validate inputs ──────────────────────────────────────────────────
  const tenant = process.env.INPUT_TENANT
  if (!tenant) {
    setError('Missing required input: tenant')
    process.exit(1)
  }

  if (!tenant.startsWith('clm_')) {
    setError('Invalid tenant format. Expected a claim token starting with clm_')
    process.exit(1)
  }

  // ── Request OIDC token ───────────────────────────────────────────────
  let oidcToken: string

  try {
    oidcToken = await requestOIDCToken()
  } catch (err: any) {
    setError(
      `Failed to request OIDC token: ${err.message}\n` +
      'Ensure your workflow includes:\n' +
      '  permissions:\n' +
      '    id-token: write',
    )
    process.exit(1)
  }

  // ── Verify claim ─────────────────────────────────────────────────────
  const repo = process.env.GITHUB_REPOSITORY ?? ''
  const branch = (process.env.GITHUB_REF ?? '').replace('refs/heads/', '')
  const actor = process.env.GITHUB_ACTOR ?? ''
  const actorId = process.env.GITHUB_ACTOR_ID ?? ''

  console.log(`Claiming tenant for ${actor} (${actorId}) on ${repo}@${branch}`)

  const result = await verifyClaimFromAction({
    tenant,
    oidcToken,
    repo,
    branch,
    actor,
    actorId,
  })

  if (!result.success) {
    setError(`Claim failed: ${result.error}`)
    process.exit(1)
  }

  // ── Set outputs ──────────────────────────────────────────────────────
  setOutput('tenant-id', result.tenantId ?? '')
  setOutput('level', String(result.level ?? 0))
  setOutput('claimed', String(result.claimed ?? false))

  // ── Write tenant config ──────────────────────────────────────────────
  try {
    await writeTenantConfig(result)
    setNotice(`Tenant config written to .headless.ly/tenant.json`)
  } catch (err: any) {
    // Non-fatal: config file write failure should not fail the action
    console.log(`::warning::Failed to write tenant config: ${err.message}`)
  }

  // ── Sync agent keys (optional) ──────────────────────────────────────
  const syncKeys = (process.env.INPUT_SYNC_KEYS ?? 'false').toLowerCase() === 'true'

  if (syncKeys) {
    try {
      await syncAgentKeys(result.tenantId!, oidcToken)
      setNotice('Agent public keys synced to .headless.ly/agents/')
    } catch (err: any) {
      console.log(`::warning::Failed to sync agent keys: ${err.message}`)
    }
  }

  // ── Summary ──────────────────────────────────────────────────────────
  console.log('')
  console.log('Tenant claimed successfully.')
  console.log(`  Tenant ID: ${result.tenantId}`)
  console.log(`  Level: ${result.level}`)
  console.log(`  Claimed: ${result.claimed}`)
  console.log('')

  // Write job summary if available
  const summaryFile = process.env.GITHUB_STEP_SUMMARY
  if (summaryFile) {
    const fs = require('fs') as typeof import('fs')
    const summary = [
      '## Tenant Claimed',
      '',
      '| Property | Value |',
      '| --- | --- |',
      `| Tenant ID | \`${result.tenantId}\` |`,
      `| Level | ${result.level} |`,
      `| Actor | @${actor} |`,
      `| Repository | ${repo} |`,
      `| Branch | ${branch} |`,
      '',
      'Your headless.ly tenant is now linked to this GitHub identity.',
      '',
    ].join('\n')

    fs.appendFileSync(summaryFile, summary)
  }
}

/**
 * Sync agent public keys from id.org.ai to .headless.ly/agents/*.pub.
 *
 * Fetches the list of agent public keys for the claimed tenant
 * and writes them to the workspace for use by other tools.
 */
async function syncAgentKeys(tenantId: string, oidcToken: string): Promise<void> {
  const fs = require('fs') as typeof import('fs')
  const path = require('path') as typeof import('path')

  const workspace = process.env.GITHUB_WORKSPACE ?? process.cwd()
  const agentsDir = path.join(workspace, '.headless.ly', 'agents')

  // Fetch agent keys from the API
  const res = await fetch(`https://id.org.ai/api/identity/${tenantId}/agents`, {
    headers: {
      Authorization: `Bearer ${oidcToken}`,
      Accept: 'application/json',
    },
  })

  if (!res.ok) {
    throw new Error(`Failed to fetch agent keys (${res.status})`)
  }

  const data = await res.json() as {
    agents: Array<{ id: string; publicKey: string; name?: string }>
  }

  if (!data.agents || data.agents.length === 0) {
    console.log('No agent keys to sync.')
    return
  }

  // Ensure directory exists
  if (!fs.existsSync(agentsDir)) {
    fs.mkdirSync(agentsDir, { recursive: true })
  }

  // Write each agent's public key
  for (const agent of data.agents) {
    const filename = `${agent.name ?? agent.id}.pub`
    const filepath = path.join(agentsDir, filename)
    fs.writeFileSync(filepath, agent.publicKey + '\n')
  }

  console.log(`Synced ${data.agents.length} agent key(s) to .headless.ly/agents/`)
}

run().catch((err) => {
  setError(`Unexpected error: ${err.message}`)
  process.exit(1)
})
