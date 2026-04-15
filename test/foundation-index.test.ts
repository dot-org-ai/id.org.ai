import { describe, it, expect } from 'vitest'
import {
  Ok,
  Err,
  isOk,
  isErr,
  map,
  flatMap,
  unwrapOr,
  NotFoundError,
  ValidationError,
  AuthError,
  ConflictError,
  RateLimitError,
  OAuthError,
  ClaimError,
  KeyError,
  toErrorResponse,
} from '../src/sdk/foundation'
import type { Result, DomainError } from '../src/sdk/foundation'

describe('Foundation index re-exports', () => {
  it('exports all Result helpers', () => {
    expect(typeof Ok).toBe('function')
    expect(typeof Err).toBe('function')
    expect(typeof isOk).toBe('function')
    expect(typeof isErr).toBe('function')
    expect(typeof map).toBe('function')
    expect(typeof flatMap).toBe('function')
    expect(typeof unwrapOr).toBe('function')
  })

  it('exports all error classes', () => {
    expect(typeof NotFoundError).toBe('function')
    expect(typeof ValidationError).toBe('function')
    expect(typeof AuthError).toBe('function')
    expect(typeof ConflictError).toBe('function')
    expect(typeof RateLimitError).toBe('function')
    expect(typeof OAuthError).toBe('function')
    expect(typeof ClaimError).toBe('function')
    expect(typeof KeyError).toBe('function')
  })

  it('exports toErrorResponse bridge', () => {
    expect(typeof toErrorResponse).toBe('function')
  })

  it('Result and DomainError types work together', () => {
    const result: Result<string, DomainError> = Err(new NotFoundError('test', '1'))
    expect(result.success).toBe(false)
    if (!result.success) {
      const resp = toErrorResponse(result.error)
      expect(resp.status).toBe(404)
    }
  })
})
