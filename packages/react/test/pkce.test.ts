import { describe, it, expect, beforeEach } from 'vitest'
import { generateCodeVerifier, generateCodeChallenge, storeVerifier, getAndClearVerifier, storeNonce, getAndClearNonce } from '../src/pkce'

describe('PKCE', () => {
  beforeEach(() => {
    sessionStorage.clear()
  })

  it('generates a code verifier of correct length', () => {
    const verifier = generateCodeVerifier()
    expect(verifier.length).toBeGreaterThanOrEqual(43)
    expect(verifier.length).toBeLessThanOrEqual(128)
  })

  it('generates a code challenge from verifier', async () => {
    const verifier = generateCodeVerifier()
    const challenge = await generateCodeChallenge(verifier)
    expect(challenge).toBeTruthy()
    expect(challenge).not.toBe(verifier)
  })

  it('stores and retrieves verifier from sessionStorage', () => {
    storeVerifier('test_verifier_123')
    const retrieved = getAndClearVerifier()
    expect(retrieved).toBe('test_verifier_123')
  })

  it('clears verifier after retrieval', () => {
    storeVerifier('test_verifier_123')
    getAndClearVerifier()
    const second = getAndClearVerifier()
    expect(second).toBeNull()
  })

  it('stores and retrieves nonce from sessionStorage', () => {
    storeNonce('nonce_abc')
    const retrieved = getAndClearNonce()
    expect(retrieved).toBe('nonce_abc')
  })

  it('clears nonce after retrieval', () => {
    storeNonce('nonce_abc')
    getAndClearNonce()
    const second = getAndClearNonce()
    expect(second).toBeNull()
  })
})
