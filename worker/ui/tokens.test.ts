import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

describe('design tokens', () => {
  it('worker/ui/tokens.css is identical to docs/product-update/spec/tokens.css', () => {
    const shipped = readFileSync('worker/ui/tokens.css', 'utf8')
    const spec = readFileSync('docs/product-update/spec/tokens.css', 'utf8')
    expect(shipped).toBe(spec)
  })

  it('component CSS uses tokens, never colour literals', () => {
    const css = readFileSync('worker/ui/ui.css', 'utf8')
    expect(css).not.toMatch(/oklch\(|#[0-9a-f]{3,8}\b|rgba?\(/i)
  })
})
