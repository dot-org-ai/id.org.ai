#!/usr/bin/env node
/**
 * id.org.ai CLI
 * Authenticate with id.org.ai using OAuth device flow
 *
 * Usage:
 *   id.org.ai login     - Login using device authorization flow
 *   id.org.ai logout    - Logout and remove stored credentials
 *   id.org.ai whoami    - Show current authenticated user
 *   id.org.ai token     - Display current authentication token
 *   id.org.ai status    - Show authentication and storage status
 */

import { hostname } from 'node:os'
import { deviceName } from './device.js'
import { getUser, logout as logoutFn, ensureValidToken } from './auth.js'
import { runLogin, parseLoginArgs, EXIT } from './login.js'
import { outputMode } from './login-output.js'
import { openInBrowser, copyToClipboard } from './desktop.js'
import { createStorage, SecureFileTokenStorage } from './storage.js'
import { provisionCommand } from './provision.js'
import { claimCommand } from './claim.js'
import { ProvisionStorage } from './provision-storage.js'
import { cleanText } from './untrusted'

const ANSI = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  dim: '\x1b[2m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  red: '\x1b[31m',
  cyan: '\x1b[36m',
  gray: '\x1b[90m',
  blue: '\x1b[34m',
}

// Plain text under NO_COLOR or when stdout is not a terminal, as login's output (spec/cli-output.md).
const colors: typeof ANSI = outputMode({ stdoutIsTTY: process.stdout.isTTY, env: process.env }).colour
  ? ANSI
  : (Object.fromEntries(Object.keys(ANSI).map((key) => [key, ''])) as typeof ANSI)

const CLIENT_ID = process.env.ID_ORG_AI_CLIENT_ID || 'id_org_ai_cli'
const APP = { name: 'id.org.ai', cli: 'id.org.ai' }
const storage = createStorage(process.env.ID_ORG_AI_STORAGE_PATH)

function printError(message: string, error?: Error) {
  console.error(`${colors.red}Error:${colors.reset} ${message}`)
  // Error text can carry a server's words; never print it raw.
  if (error?.message) console.error(cleanText(error.message))
  if (error?.stack && process.env.DEBUG) {
    console.error(`\n${colors.dim}Stack trace:${colors.reset}`)
    console.error(`${colors.dim}${error.stack}${colors.reset}`)
  }
}

function printSuccess(message: string) {
  console.log(`${colors.green}✓${colors.reset} ${message}`)
}

function printInfo(message: string) {
  console.log(`${colors.cyan}ℹ${colors.reset} ${message}`)
}

function printHelp() {
  console.log(`
${colors.bright}id.org.ai CLI${colors.reset} — Agent-First Identity

${colors.cyan}Usage:${colors.reset}
  id.org.ai <command> [options]

${colors.cyan}Commands:${colors.reset}
  login      Sign in with your browser (device flow)
             --account  sign in as another account
  logout     Logout and remove stored credentials
  whoami     Show current authenticated user
  token      Display current authentication token
  status     Show authentication and storage status
  provision  Create an anonymous sandbox for agents
  claim      Claim a provisioned sandbox via commit

${colors.cyan}Options:${colors.reset}
  --help, -h     Show this help message
  --version, -v  Show version
  --debug        Show debug information

${colors.cyan}Examples:${colors.reset}
  ${colors.gray}# Login to your account${colors.reset}
  id.org.ai login

  ${colors.gray}# Sign in as another account${colors.reset}
  id.org.ai login --account

  ${colors.gray}# Check who is logged in${colors.reset}
  id.org.ai whoami

  ${colors.gray}# Get your authentication token${colors.reset}
  id.org.ai token

  ${colors.gray}# Use token with curl${colors.reset}
  curl -H "Authorization: Bearer $(id.org.ai token)" https://crm.headless.ly/api/contacts

  ${colors.gray}# Create anonymous sandbox${colors.reset}
  id.org.ai provision

  ${colors.gray}# Create sandbox and get JSON output${colors.reset}
  id.org.ai provision --json

  ${colors.gray}# Logout${colors.reset}
  id.org.ai logout

${colors.cyan}Environment Variables:${colors.reset}
  ID_ORG_AI_URL            API base URL (default: https://id.org.ai)
  ID_ORG_AI_CLIENT_ID      Client ID for OAuth
  ID_ORG_AI_STORAGE_PATH   Custom token storage path
  NO_COLOR                 Print login output without styles
  DEBUG                    Enable debug output
`)
}

/**
 * Sign in with the device flow, printing the 4a screen
 * (docs/product-update/spec/cli-output.md). Exit code: 0 signed in, 1 denied,
 * expired or failed, 2 usage error, 130 interrupted.
 */
async function loginCommand(args: string[] = []) {
  const parsed = parseLoginArgs(args)
  if (!parsed.ok) {
    printError(parsed.error)
    console.error(`\nRun ${colors.cyan}id.org.ai --help${colors.reset} for usage information`)
    process.exit(EXIT.usage)
  }

  // Raw mode turns Ctrl-C into a key, which runLogin handles; without it, SIGINT.
  const interrupt = new AbortController()
  const onSigint = () => interrupt.abort()
  process.once('SIGINT', onSigint)
  try {
    process.exitCode = await runLogin({
      clientId: CLIENT_ID,
      app: APP,
      storage,
      deviceName: deviceName(process.platform, hostname()),
      signal: interrupt.signal,
      io: {
        stdout: process.stdout,
        stdin: process.stdin,
        env: process.env,
        openUrl: (url) => openInBrowser(url),
        copyText: (text) => copyToClipboard(text, { write: (chunk) => process.stdout.write(chunk) }),
      },
    })
  } finally {
    process.off('SIGINT', onSigint)
  }
}

async function logoutCommand() {
  try {
    const tokenData = await storage.getTokenData()

    if (!tokenData?.accessToken) {
      printInfo('Not logged in')
      return
    }

    await logoutFn(tokenData.accessToken, tokenData.refreshToken)
    await storage.removeToken()
    printSuccess('Logged out successfully')
  } catch (error) {
    printError('Logout failed', error instanceof Error ? error : undefined)
    process.exit(1)
  }
}

async function whoamiCommand() {
  try {
    const token = await ensureValidToken(storage)

    if (!token) {
      console.log(`${colors.dim}Not logged in${colors.reset}`)
      console.log(`\nRun ${colors.cyan}id.org.ai login${colors.reset} to authenticate`)
      return
    }

    const authResult = await getUser(token)

    if (!authResult.user) {
      console.log(`${colors.dim}Not authenticated${colors.reset}`)
      console.log(`\nRun ${colors.cyan}id.org.ai login${colors.reset} to authenticate`)
      return
    }

    console.log(`${colors.bright}Authenticated as:${colors.reset}`)
    if (authResult.user.name) console.log(`  ${colors.green}Name:${colors.reset} ${authResult.user.name}`)
    if (authResult.user.email) console.log(`  ${colors.green}Email:${colors.reset} ${authResult.user.email}`)
    if (authResult.user.id) console.log(`  ${colors.green}ID:${colors.reset} ${authResult.user.id}`)
    if (authResult.user.organizationId) console.log(`  ${colors.green}Org:${colors.reset} ${authResult.user.organizationId}`)
  } catch (error) {
    printError('Failed to get user info', error instanceof Error ? error : undefined)
    process.exit(1)
  }
}

async function tokenCommand() {
  try {
    const token = await ensureValidToken(storage)

    if (!token) {
      console.log(`${colors.dim}No token found${colors.reset}`)
      console.log(`\nRun ${colors.cyan}id.org.ai login${colors.reset} to authenticate`)
      return
    }

    // Output raw token (for piping to other commands)
    console.log(token)
  } catch (error) {
    printError('Failed to get token', error instanceof Error ? error : undefined)
    process.exit(1)
  }
}

async function statusCommand() {
  try {
    console.log(`${colors.bright}id.org.ai Status${colors.reset}\n`)

    const storagePath = await (storage as SecureFileTokenStorage).getStoragePath?.()
    if (storagePath) {
      console.log(`${colors.cyan}Storage:${colors.reset} ${colors.green}Secure File${colors.reset}`)
      console.log(`  ${colors.dim}${storagePath} (0600 permissions)${colors.reset}`)
    }

    const token = await ensureValidToken(storage)
    if (!token) {
      console.log(`\n${colors.cyan}Auth:${colors.reset} ${colors.dim}Not authenticated${colors.reset}`)
      console.log(`\nRun ${colors.cyan}id.org.ai login${colors.reset} to authenticate`)
      return
    }

    const tokenData = await storage.getTokenData()
    if (tokenData?.expiresAt) {
      const remaining = tokenData.expiresAt - Date.now()
      if (remaining > 0) {
        const minutes = Math.floor(remaining / 60000)
        console.log(`\n${colors.cyan}Token:${colors.reset} ${colors.green}Valid${colors.reset} (expires in ${minutes} min)`)
      } else {
        console.log(`\n${colors.cyan}Token:${colors.reset} ${colors.yellow}Expired${colors.reset}`)
      }
    }

    const authResult = await getUser(token)
    if (authResult.user) {
      console.log(`${colors.cyan}Auth:${colors.reset} ${colors.green}Authenticated${colors.reset}`)
      if (authResult.user.email) console.log(`  ${colors.dim}${authResult.user.email}${colors.reset}`)
    } else {
      console.log(`${colors.cyan}Auth:${colors.reset} ${colors.yellow}Token expired or invalid${colors.reset}`)
      console.log(`\nRun ${colors.cyan}id.org.ai login${colors.reset} to re-authenticate`)
    }
  } catch (error) {
    printError('Failed to get status', error instanceof Error ? error : undefined)
    process.exit(1)
  }
}

async function autoLoginOrShowUser() {
  try {
    const token = await ensureValidToken(storage)

    if (token) {
      const authResult = await getUser(token)

      if (authResult.user) {
        console.log(`${colors.green}✓${colors.reset} Already authenticated\n`)
        if (authResult.user.name) console.log(`  ${colors.bright}${authResult.user.name}${colors.reset}`)
        if (authResult.user.email) console.log(`  ${colors.gray}${authResult.user.email}${colors.reset}`)
        if (authResult.user.id) console.log(`  ${colors.dim}ID: ${authResult.user.id}${colors.reset}`)
        return
      }
      printInfo('Session expired, logging in again...\n')
    }

    await loginCommand()
  } catch {
    await loginCommand()
  }
}

async function main() {
  const args = process.argv.slice(2)

  if (args.includes('--help') || args.includes('-h')) {
    printHelp()
    process.exit(0)
  }

  if (args.includes('--version') || args.includes('-v')) {
    console.log('id.org.ai v0.0.1')
    process.exit(0)
  }

  if (args.includes('--debug')) {
    process.env.DEBUG = 'true'
  }

  const command = args.find((arg) => !arg.startsWith('--'))

  switch (command) {
    case 'login':
      await loginCommand(args.filter((_, i) => i !== args.indexOf('login')))
      break
    case undefined:
      await autoLoginOrShowUser()
      break
    case 'logout':
      await logoutCommand()
      break
    case 'whoami':
      await whoamiCommand()
      break
    case 'token':
      await tokenCommand()
      break
    case 'status':
      await statusCommand()
      break
    case 'provision': {
      const baseUrl = process.env.ID_ORG_AI_URL || 'https://id.org.ai'
      const json = args.includes('--json')
      const provisionStorage = new ProvisionStorage()
      await provisionCommand({ baseUrl, json, storage: provisionStorage })
      break
    }
    case 'claim': {
      const baseUrl = process.env.ID_ORG_AI_URL || 'https://id.org.ai'
      const json = args.includes('--json')
      const token = args.find((a) => a.startsWith('--token='))?.split('=')[1] || (args.includes('--token') ? args[args.indexOf('--token') + 1] : undefined)
      const noPush = args.includes('--no-push')
      const claimStorage = new ProvisionStorage()
      await claimCommand({ baseUrl, json, token, noPush, storage: claimStorage })
      break
    }
    default:
      printError(`Unknown command: ${command}`)
      console.log(`\nRun ${colors.cyan}id.org.ai --help${colors.reset} for usage information`)
      process.exit(EXIT.usage)
  }
}

main().catch((error) => {
  printError('Unexpected error', error)
  process.exit(1)
})

export { main }
