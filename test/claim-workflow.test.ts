import { describe, it, expect } from 'vitest'
import { buildClaimWorkflow } from '../src/sdk/claim/workflow'

describe('buildClaimWorkflow', () => {
  it('generates valid workflow YAML with claim token', () => {
    const yaml = buildClaimWorkflow('clm_abc123')
    expect(yaml).toContain('name: Claim headless.ly tenant')
    expect(yaml).toContain("tenant: 'clm_abc123'")
    expect(yaml).toContain('uses: dot-org-ai/id@v1')
    expect(yaml).toContain('uses: actions/checkout@v4')
    expect(yaml).toContain('id-token: write')
    expect(yaml).toContain('branches: [main, master]')
  })

  it('throws on invalid claim token', () => {
    expect(() => buildClaimWorkflow('')).toThrow()
    expect(() => buildClaimWorkflow('invalid')).toThrow()
  })
})
