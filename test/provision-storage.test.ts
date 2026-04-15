import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { ProvisionStorage } from '../src/sdk/cli/provision-storage'
import { mkdtemp, rm } from 'fs/promises'
import { join } from 'path'
import { tmpdir } from 'os'

describe('ProvisionStorage', () => {
  let tempDir: string
  let storage: ProvisionStorage

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'id-test-'))
    storage = new ProvisionStorage(join(tempDir, 'provision'))
  })

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true })
  })

  it('returns null when no provision data exists', async () => {
    const data = await storage.getProvisionData()
    expect(data).toBeNull()
  })

  it('stores and retrieves provision data', async () => {
    const data = {
      tenantId: 'tnt_abc',
      sessionToken: 'ses_xyz',
      claimToken: 'clm_def',
      createdAt: Date.now(),
    }
    await storage.setProvisionData(data)
    const retrieved = await storage.getProvisionData()
    expect(retrieved).toEqual(data)
  })

  it('removes provision data', async () => {
    await storage.setProvisionData({
      tenantId: 'tnt_abc',
      sessionToken: 'ses_xyz',
      claimToken: 'clm_def',
      createdAt: Date.now(),
    })
    await storage.removeProvisionData()
    const data = await storage.getProvisionData()
    expect(data).toBeNull()
  })

  it('creates parent directory if it does not exist', async () => {
    const nested = new ProvisionStorage(join(tempDir, 'nested', 'deep', 'provision'))
    await nested.setProvisionData({
      tenantId: 'tnt_abc',
      sessionToken: 'ses_xyz',
      claimToken: 'clm_def',
      createdAt: Date.now(),
    })
    const data = await nested.getProvisionData()
    expect(data?.tenantId).toBe('tnt_abc')
  })
})
