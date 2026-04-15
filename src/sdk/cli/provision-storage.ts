import { readFile, writeFile, unlink, mkdir } from 'fs/promises'
import { dirname } from 'path'
import { homedir } from 'os'
import { join } from 'path'

export interface ProvisionData {
  tenantId: string
  sessionToken: string
  claimToken: string
  createdAt: number
}

const DEFAULT_PATH = join(homedir(), '.id.org.ai', 'provision')

export class ProvisionStorage {
  private filePath: string

  constructor(filePath = DEFAULT_PATH) {
    this.filePath = filePath
  }

  async getProvisionData(): Promise<ProvisionData | null> {
    try {
      const raw = await readFile(this.filePath, 'utf-8')
      return JSON.parse(raw) as ProvisionData
    } catch {
      return null
    }
  }

  async setProvisionData(data: ProvisionData): Promise<void> {
    await mkdir(dirname(this.filePath), { recursive: true })
    await writeFile(this.filePath, JSON.stringify(data, null, 2), 'utf-8')
  }

  async removeProvisionData(): Promise<void> {
    try {
      await unlink(this.filePath)
    } catch {
      // File doesn't exist — that's fine
    }
  }
}
