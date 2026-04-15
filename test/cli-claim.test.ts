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
