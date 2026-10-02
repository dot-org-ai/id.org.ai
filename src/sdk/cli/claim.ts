import { execSync } from 'child_process'
import { writeClaimWorkflow } from '../claim/workflow-fs'
import { getClaimStatus } from '../claim/client'
import type { ProvisionStorage } from './provision-storage'
import { cleanText, terminalSafeJson } from './untrusted'

/** Runs a git command; returns its output, trimmed, or throws when it fails. */
export type GitExec = (command: string) => string

export interface ClaimCommandOptions {
  baseUrl: string
  json: boolean
  token?: string
  noPush: boolean
  storage: ProvisionStorage
  /** Runs the git commands. Tests pass a fake, so no git runs. */
  exec?: GitExec
}

const runGit: GitExec = (cmd) => execSync(cmd, { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] }).trim()

function isGitRepo(exec: GitExec): boolean {
  try {
    exec('git rev-parse --is-inside-work-tree')
    return true
  } catch {
    return false
  }
}

export async function claimCommand(opts: ClaimCommandOptions): Promise<void> {
  const exec = opts.exec ?? runGit
  try {
    if (!isGitRepo(exec)) {
      console.error('Not a git repository. Run this from inside the repo you want to claim.')
      process.exit(1)
    }

    const provisionData = await opts.storage.getProvisionData()
    const claimToken = opts.token || provisionData?.claimToken

    if (!claimToken) {
      console.error('No claim token found. Run `id.org.ai provision` first, or pass `--token clm_xxx`.')
      process.exit(1)
    }

    const repoRoot = exec('git rev-parse --show-toplevel')

    const filePath = await writeClaimWorkflow(claimToken, repoRoot)
    console.log(`  Generated ${filePath.replace(repoRoot + '/', '')}`)

    exec(`git add "${filePath}"`)
    exec('git commit -m "Claim headless.ly tenant"')
    console.log('  Committed: "Claim headless.ly tenant"')

    if (opts.noPush) {
      console.log('')
      console.log('  Skipping push (--no-push). Push manually to trigger the claim.')
      return
    }

    exec('git push')
    console.log('  Pushed to origin')

    console.log('  Waiting for claim confirmation...')
    const confirmed = await pollForClaim(claimToken, opts.baseUrl)

    if (confirmed) {
      console.log('  Tenant claimed! Upgraded to Level 2')
      await opts.storage.removeProvisionData()
    } else {
      console.log('  Push succeeded but claim not confirmed yet. Check GitHub Actions tab.')
    }

    if (opts.json) {
      // JSON.stringify leaves C1 and bidi characters raw; the claim token may have come from a server.
      console.log(terminalSafeJson({ claimToken, confirmed, level: confirmed ? 2 : 1 }))
    }
  } catch (err) {
    if (err instanceof Error && err.message === 'exit') throw err
    console.error(`Claim failed: ${cleanText(err instanceof Error ? err.message : err)}`)
    process.exit(1)
  }
}

async function pollForClaim(claimToken: string, baseUrl: string, timeoutMs = 60_000): Promise<boolean> {
  const start = Date.now()
  const interval = 3_000

  while (Date.now() - start < timeoutMs) {
    const result = await getClaimStatus(claimToken, baseUrl)
    if (result.status === 'claimed') return true
    if (result.status === 'expired') return false
    await new Promise((r) => setTimeout(r, interval))
  }

  return false
}
