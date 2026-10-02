/**
 * Client secrets at rest (docs/product-update/spec/backend.md#b13, item 5).
 *
 * Dynamic Client Registration used to store confidential clients' secrets in
 * plaintext and compare them with `!==`. Now a client record carries only
 * `secretHash` (SHA-256, hex) and secrets are compared in constant time. A
 * record from before carries the plaintext `secret`: it still verifies, and
 * the caller rewrites it hashed on that first successful use.
 */
import { constantTimeEqual } from './pkce'

export interface SecretHolder {
  /** Legacy: the plaintext secret, from before secrets were hashed. Rewritten on next use. */
  secret?: string
  /** SHA-256 (hex) of the client secret. */
  secretHash?: string
}

export async function hashClientSecret(secret: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(secret))
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('')
}

/** Whether the client is confidential (has a secret, hashed or legacy). */
export function clientHasSecret(client: SecretHolder | null | undefined): boolean {
  return !!(client?.secretHash || client?.secret)
}

/**
 * Check a presented secret. `hashed`: it matched the stored hash. `legacy`: it
 * matched a plaintext secret (rewrite the record with `withHashedSecret`).
 * `null`: no match, or the client has no secret.
 */
export async function checkClientSecret(client: SecretHolder | null | undefined, presented: string): Promise<'hashed' | 'legacy' | null> {
  if (!client || !presented) return null
  if (client.secretHash) {
    return (await constantTimeEqual(await hashClientSecret(presented), client.secretHash)) ? 'hashed' : null
  }
  if (client.secret) return (await constantTimeEqual(presented, client.secret)) ? 'legacy' : null
  return null
}

/** The record with its plaintext secret replaced by the hash. */
export async function withHashedSecret<T extends SecretHolder>(client: T): Promise<T> {
  if (!client.secret) return client
  const { secret, ...rest } = client
  return { ...(rest as T), secretHash: await hashClientSecret(secret) }
}
