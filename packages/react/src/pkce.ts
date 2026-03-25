'use client'

const VERIFIER_KEY = 'id.org.ai:pkce_verifier'
const NONCE_KEY = 'id.org.ai:state_nonce'

export function generateCodeVerifier(): string {
  const array = new Uint8Array(32)
  crypto.getRandomValues(array)
  return base64UrlEncode(array)
}

export async function generateCodeChallenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder()
  const data = encoder.encode(verifier)
  const digest = await crypto.subtle.digest('SHA-256', data)
  return base64UrlEncode(new Uint8Array(digest))
}

export function storeVerifier(verifier: string): void {
  sessionStorage.setItem(VERIFIER_KEY, verifier)
}

export function getAndClearVerifier(): string | null {
  const verifier = sessionStorage.getItem(VERIFIER_KEY)
  sessionStorage.removeItem(VERIFIER_KEY)
  return verifier
}

export function storeNonce(nonce: string): void {
  sessionStorage.setItem(NONCE_KEY, nonce)
}

export function getAndClearNonce(): string | null {
  const nonce = sessionStorage.getItem(NONCE_KEY)
  sessionStorage.removeItem(NONCE_KEY)
  return nonce
}

function base64UrlEncode(bytes: Uint8Array): string {
  const str = String.fromCharCode(...bytes)
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
