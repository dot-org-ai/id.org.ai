import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mkdtemp, rm, readFile } from 'fs/promises'
import { join } from 'path'
import { tmpdir } from 'os'

describe('writeClaimWorkflow', () => {
  let tempDir: string

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'id-claim-test-'))
  })

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true })
  })

  it('writes workflow file to .github/workflows/', async () => {
    const { writeClaimWorkflow } = await import('../src/sdk/claim/workflow-fs')

    const filePath = await writeClaimWorkflow('clm_test123', tempDir)

    expect(filePath).toBe(join(tempDir, '.github', 'workflows', 'headlessly.yml'))
    const content = await readFile(filePath, 'utf-8')
    expect(content).toContain("tenant: 'clm_test123'")
    expect(content).toContain('dot-org-ai/id@v1')
  })
})

describe('claimCommand error handling', () => {
  let tempDir: string
  let errors: string[]

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'id-claim-test-'))
    errors = []
    vi.spyOn(console, 'log').mockImplementation(() => {})
    vi.spyOn(console, 'error').mockImplementation((...args: unknown[]) => {
      errors.push(args.join(' '))
    })
  })

  afterEach(async () => {
    vi.restoreAllMocks()
    await rm(tempDir, { recursive: true, force: true })
  })

  it('errors when no claim token available', async () => {
    const { claimCommand } = await import('../src/sdk/cli/claim')
    const mockExit = vi.spyOn(process, 'exit').mockImplementation(() => {
      throw new Error('exit')
    })
    const mockStorage = {
      getProvisionData: vi.fn().mockResolvedValue(null),
      setProvisionData: vi.fn(),
      removeProvisionData: vi.fn(),
    }

    await expect(
      claimCommand({
        baseUrl: 'https://id.org.ai',
        json: false,
        noPush: true,
        storage: mockStorage as any,
      }),
    ).rejects.toThrow('exit')

    mockExit.mockRestore()
    expect(errors.join(' ')).toContain('No claim token found')
  })
})

// H1: the claim token is public once pushed, so the CLI binds it to the
// origin repository first, over the session token (never committed).
describe('claimCommand binds the claim before publishing the token', () => {
  let tempDir: string
  let logs: string[]
  let errors: string[]
  let commands: string[]
  let requests: Array<{ url: string; init?: RequestInit }>

  const DATA = { tenantId: 't', sessionToken: 'ses_owner', claimToken: 'clm_owner', createdAt: 1 }

  function storage(data: typeof DATA | null = DATA) {
    return { getProvisionData: vi.fn().mockResolvedValue(data), setProvisionData: vi.fn(), removeProvisionData: vi.fn() }
  }

  function fakeGit(overrides: Record<string, string | Error> = {}) {
    const answers: Record<string, string | Error> = {
      'git rev-parse --is-inside-work-tree': 'true',
      'git remote get-url origin': 'git@github.com:alice/app.git',
      'git symbolic-ref --short refs/remotes/origin/HEAD': 'origin/main',
      'git rev-parse --abbrev-ref HEAD': 'main',
      'git rev-parse --show-toplevel': tempDir,
      ...overrides,
    }
    return (command: string) => {
      commands.push(command)
      const answer = Object.entries(answers).find(([k]) => command === k)?.[1]
      if (answer instanceof Error) throw answer
      return answer ?? ''
    }
  }

  function stubFetch(bindStatus: number, bindBody: unknown, claimStatus = 'claimed') {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string, init?: RequestInit) => {
        requests.push({ url, init })
        commands.push(`fetch ${url}`)
        if (url.endsWith('/api/claim/bind')) return new Response(JSON.stringify(bindBody), { status: bindStatus })
        return new Response(JSON.stringify({ status: claimStatus, level: claimStatus === 'claimed' ? 2 : 1 }), { status: 200 })
      }),
    )
  }

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'id-claim-test-'))
    logs = []
    errors = []
    commands = []
    requests = []
    vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
      logs.push(args.join(' '))
    })
    vi.spyOn(console, 'error').mockImplementation((...args: unknown[]) => {
      errors.push(args.join(' '))
    })
    vi.spyOn(process, 'exit').mockImplementation(() => {
      throw new Error('exit')
    })
  })

  afterEach(async () => {
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
    await rm(tempDir, { recursive: true, force: true })
  })

  it('binds origin and its default branch with the session token, before committing', async () => {
    const { claimCommand } = await import('../src/sdk/cli/claim')
    stubFetch(200, { success: true, repo: 'alice/app', defaultBranch: 'main' })
    await claimCommand({ baseUrl: 'https://id.example', json: false, noPush: false, storage: storage() as any, exec: fakeGit() })

    const bindIndex = commands.indexOf('fetch https://id.example/api/claim/bind')
    expect(bindIndex).toBeGreaterThanOrEqual(0)
    expect(bindIndex).toBeLessThan(commands.indexOf('git commit -m "Claim headless.ly tenant"'))
    const bindReq = requests.find((r) => r.url.endsWith('/api/claim/bind'))!
    expect((bindReq.init!.headers as Record<string, string>).Authorization).toBe('Bearer ses_owner')
    expect(JSON.parse(String(bindReq.init!.body))).toEqual({ repo: 'alice/app', defaultBranch: 'main' })
    expect(logs.join('\n')).toContain('Bound the claim to alice/app')
    expect(logs.join('\n')).toContain('Tenant claimed')
  })

  it('refuses, without committing, when the server binds the token to another repository', async () => {
    const { claimCommand } = await import('../src/sdk/cli/claim')
    stubFetch(409, { success: false, error: 'Claim token is bound to another repository' })
    await expect(
      claimCommand({ baseUrl: 'https://id.example', json: false, noPush: false, storage: storage() as any, exec: fakeGit() }),
    ).rejects.toThrow('exit')
    expect(errors.join(' ')).toContain('bound to another repository')
    expect(commands.some((c) => c.startsWith('git commit') || c === 'git push')).toBe(false)
  })

  it('refuses without a GitHub origin remote, before writing anything', async () => {
    const { claimCommand } = await import('../src/sdk/cli/claim')
    stubFetch(200, { success: true })
    await expect(
      claimCommand({
        baseUrl: 'https://id.example',
        json: false,
        noPush: true,
        storage: storage() as any,
        exec: fakeGit({ 'git remote get-url origin': 'https://gitlab.com/alice/app.git' }),
      }),
    ).rejects.toThrow('exit')
    expect(errors.join(' ')).toContain('No GitHub remote')
    expect(requests).toEqual([])
    expect(commands.some((c) => c.startsWith('git commit'))).toBe(false)
  })

  it('warns that the token is unbound when it has no session for it (--token)', async () => {
    const { claimCommand } = await import('../src/sdk/cli/claim')
    stubFetch(200, { success: true })
    await claimCommand({ baseUrl: 'https://id.example', json: false, token: 'clm_other', noPush: true, storage: storage() as any, exec: fakeGit() })
    expect(requests.some((r) => r.url.endsWith('/api/claim/bind'))).toBe(false)
    expect(logs.join('\n')).toContain('not bound to alice/app')
  })

  it('warns and falls back when the session expired', async () => {
    const { claimCommand } = await import('../src/sdk/cli/claim')
    stubFetch(401, { error: 'unauthorized', error_description: 'Invalid or expired session token' })
    await claimCommand({ baseUrl: 'https://id.example', json: false, noPush: true, storage: storage() as any, exec: fakeGit() })
    expect(logs.join('\n')).toContain('not bound to alice/app (Invalid or expired session token)')
    expect(commands).toContain('git commit -m "Claim headless.ly tenant"')
  })

  it('says a feature-branch push only reaches pending, and stops waiting there', async () => {
    const { claimCommand } = await import('../src/sdk/cli/claim')
    stubFetch(200, { success: true, repo: 'alice/app' }, 'pending')
    await claimCommand({
      baseUrl: 'https://id.example',
      json: false,
      noPush: false,
      storage: storage() as any,
      exec: fakeGit({ 'git rev-parse --abbrev-ref HEAD': 'feature/x' }),
    })
    const out = logs.join('\n')
    expect(out).toContain('On branch feature/x, not main')
    expect(out).toContain('Claim pending')
  })
})
