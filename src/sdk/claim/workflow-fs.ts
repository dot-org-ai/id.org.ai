import { writeFile, mkdir } from 'fs/promises'
import { join, dirname } from 'path'
import { buildClaimWorkflow } from './workflow'

export async function writeClaimWorkflow(claimToken: string, repoRoot = process.cwd()): Promise<string> {
  const yaml = buildClaimWorkflow(claimToken)
  const filePath = join(repoRoot, '.github', 'workflows', 'headlessly.yml')
  await mkdir(dirname(filePath), { recursive: true })
  await writeFile(filePath, yaml, 'utf-8')
  return filePath
}
