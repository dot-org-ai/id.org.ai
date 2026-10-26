import { execSync } from 'child_process'
import { writeClaimWorkflow } from '../claim/workflow-fs'
import { isClaimToken } from '../claim/workflow'
import { bindClaimRepository, getClaimStatus } from '../claim/client'
import type { ClaimStatusResult } from '../claim/client'
import { githubRepoFromRemote, isGitBranchName } from '../claim/policy'
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

/** Runs a git command; returns its output, or undefined when it fails. */
function tryGit(exec: GitExec, command: string): string | undefined {
  try {
    return exec(command) || undefined
  } catch {
    return undefined
  }
}

/** The remote's default branch as git last saw it (`origin/HEAD`), if known. */
function remoteDefaultBranch(exec: GitExec): string | undefined {
  const head = tryGit(exec, 'git symbolic-ref --short refs/remotes/origin/HEAD')
  const branch = head?.startsWith('origin/') ? head.slice('origin/'.length) : undefined
  return branch && isGitBranchName(branch) ? branch : undefined
}

function warnUnbound(repo: string, reason: string): void {
  console.log('')
  console.log(`  Warning: the claim is not bound to ${repo} (${reason}).`)
  console.log('  The claim token is public once pushed. Until your first push runs the claim')
  console.log('  workflow, anyone who copies it from the commit can claim this tenant first.')
  console.log('')
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

    // Refuse a malformed token before anything is sent, written or committed.
    if (!isClaimToken(claimToken)) {
      console.error('Invalid claim token: expected clm_ followed by letters, digits, - or _')
      process.exit(1)
    }

    // H1: the claim token is public once pushed, so bind it to this
    // repository first, over the session token, which is never committed.
    const remote = tryGit(exec, 'git remote get-url origin')
    const repo = remote ? githubRepoFromRemote(remote) : null
    if (!repo) {
      console.error(
        'No GitHub remote named origin. Add one (git remote add origin https://github.com/<owner>/<repo>) so the claim can be bound to that repository before the token is published.',
      )
      process.exit(1)
    }
    const defaultBranch = remoteDefaultBranch(exec)
    const sessionToken = provisionData && provisionData.claimToken === claimToken ? provisionData.sessionToken : undefined

    let bound = false
    if (!sessionToken) {
      warnUnbound(repo, 'no stored session for this claim token')
    } else {
      const result = await bindClaimRepository(sessionToken, repo, { defaultBranch, baseUrl: opts.baseUrl })
      if (result.success) {
        bound = true
        console.log(`  Bound the claim to ${repo}`)
      } else if (result.status === 400 || result.status === 409) {
        // The server refused this repository: a push would not claim either.
        console.error(`Cannot bind the claim to ${repo}: ${cleanText(result.error ?? `HTTP ${result.status}`)}`)
        process.exit(1)
      } else {
        // Expired session (401), a server without the endpoint (404), or the
        // network: fall back to binding on first use, and say so.
        warnUnbound(repo, cleanText(result.error ?? `HTTP ${result.status}`))
      }
    }

    const branch = tryGit(exec, 'git rev-parse --abbrev-ref HEAD')
    const target = defaultBranch ?? 'main'
    const onDefault = !!branch && (defaultBranch ? branch === defaultBranch : branch === 'main' || branch === 'master')
    if (branch && !onDefault) {
      console.log(`  On branch ${cleanText(branch)}, not ${cleanText(target)}: the push binds the claim (pending);`)
      console.log(`  merging it to ${cleanText(target)} finalises it.`)
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
      if (opts.json) console.log(terminalSafeJson({ claimToken, repo, bound, status: 'unclaimed', level: 1 }))
      return
    }

    exec('git push')
    console.log('  Pushed to origin')

    console.log('  Waiting for claim confirmation...')
    // Off the default branch the claim can only reach 'pending'.
    const status = await pollForClaim(claimToken, opts.baseUrl, onDefault ? ['claimed'] : ['claimed', 'pending'])

    if (status === 'claimed') {
      console.log('  Tenant claimed! Upgraded to Level 2')
      await opts.storage.removeProvisionData()
    } else if (status === 'pending') {
      console.log(`  Claim pending: bound to your GitHub account. Merge to ${cleanText(target)} to finalise it.`)
    } else {
      console.log('  Push succeeded but claim not confirmed yet. Check GitHub Actions tab.')
    }

    if (opts.json) {
      // JSON.stringify leaves C1 and bidi characters raw; the claim token may have come from a server.
      const confirmed = status === 'claimed'
      console.log(terminalSafeJson({ claimToken, repo, bound, status, confirmed, level: confirmed ? 2 : 1 }))
    }
  } catch (err) {
    if (err instanceof Error && err.message === 'exit') throw err
    console.error(`Claim failed: ${cleanText(err instanceof Error ? err.message : err)}`)
    process.exit(1)
  }
}

async function pollForClaim(
  claimToken: string,
  baseUrl: string,
  until: Array<ClaimStatusResult['status']>,
  timeoutMs = 60_000,
): Promise<ClaimStatusResult['status']> {
  const start = Date.now()
  const interval = 3_000
  let last: ClaimStatusResult['status'] = 'unclaimed'

  while (Date.now() - start < timeoutMs) {
    const result = await getClaimStatus(claimToken, baseUrl)
    last = result.status
    if (until.includes(result.status) || result.status === 'expired') return result.status
    await new Promise((r) => setTimeout(r, interval))
  }

  return last
}
