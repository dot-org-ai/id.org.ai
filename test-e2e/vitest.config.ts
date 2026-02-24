import { defineConfig } from 'vitest/config'
import { resolve } from 'path'
import { existsSync, readFileSync } from 'fs'

// Load .env from test-e2e/, .org.ai/id/, or root project
const envFiles = [
  resolve(__dirname, '.env'),
  resolve(__dirname, '..', '.env'),
  resolve(__dirname, '..', '..', '..', '.env'),
].filter(existsSync)

// Parse .env file into key=value pairs (dotenv-compatible)
function parseEnvFile(filePath: string): Record<string, string> {
  const env: Record<string, string> = {}
  const content = readFileSync(filePath, 'utf-8')
  for (const line of content.split('\n')) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#')) continue
    const eqIdx = trimmed.indexOf('=')
    if (eqIdx === -1) continue
    const key = trimmed.slice(0, eqIdx).trim()
    let value = trimmed.slice(eqIdx + 1).trim()
    // Strip surrounding quotes
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1)
    }
    env[key] = value
  }
  return env
}

// Merge all found .env files (first file wins for conflicts)
const envVars: Record<string, string> = { NODE_ENV: 'test' }
for (const file of envFiles) {
  const parsed = parseEnvFile(file)
  for (const [key, value] of Object.entries(parsed)) {
    if (!(key in envVars)) envVars[key] = value
  }
}

export default defineConfig({
  test: {
    include: ['test-e2e/**/*.e2e.test.ts'],
    testTimeout: 120_000,
    hookTimeout: 60_000,
    pool: 'forks',
    retry: 1,
    sequence: { concurrent: false },
    reporters: ['verbose'],
    env: envVars,
  },
})
