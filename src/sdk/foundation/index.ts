/**
 * Foundation — Shared primitives for id.org.ai domain services
 *
 * Provides:
 *   - Result<T, E> — typed success/failure for expected errors
 *   - Tagged error classes — _tag discrimination for exhaustive matching
 *   - toErrorResponse — bridge from domain errors to HTTP responses
 *
 * Depends on: nothing (leaf module)
 * Used by: all domain services in src/services/
 */

// Result type
export { Ok, Err, isOk, isErr, map, flatMap, unwrapOr } from './result'
export type { Result } from './result'

// Error classes
export {
  NotFoundError,
  ValidationError,
  AuthError,
  ConflictError,
  RateLimitError,
  OAuthError,
  ClaimError,
  KeyError,
  toErrorResponse,
} from './errors'
export type { DomainError } from './errors'
