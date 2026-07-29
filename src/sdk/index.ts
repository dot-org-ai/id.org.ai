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
// Upstream federation (Microsoft Entra + email-code fallback). `verifyToken`
// is NOT re-exported from here — ./auth already owns that name.
export * from './federation'
// Credential verification (ADR 0016 C5 / ADR 0018). `verify` is re-exported
// as `verifyCredential` here because ./crypto already exports a `verify`;
// import { verify } from './credential' directly for the module-local name.
export * from './credential/types'
export * from './credential/freshness'
export * from './credential/gates'
export * from './credential/sources'
export { verify as verifyCredential } from './credential/verify'
export type { VerifyOptions } from './credential/verify'
export * from './errors'
export * from './payment'

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
