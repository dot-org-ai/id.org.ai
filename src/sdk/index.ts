// src/sdk/index.ts
// Portable SDK exports — no cloudflare:workers dependency

export * from './oauth'
export * from './mcp'
export * from './auth'
export * from './claim'
export * from './github'
export * from './crypto'
export * from './jwt'
export * from './workos'
export * from './csrf'
export * from './audit'
export * from './errors'

// Identity types (portable RPC contract)
// Note: ClaimStatus excluded — already exported from ./claim with a different shape
export type { IdentityStub, Identity, IdentityType, CapabilityLevel, LinkedAccount, SessionData } from './types'

// Storage abstraction
export type { StorageAdapter } from './storage'
export { MemoryStorageAdapter } from './storage'

// Foundation
export { Ok, Err, isOk, isErr, map, flatMap, unwrapOr, toErrorResponse } from './foundation'
export type { Result, DomainError } from './foundation'
export { NotFoundError, AuthError, ConflictError, RateLimitError, ClaimError, KeyError } from './foundation'
