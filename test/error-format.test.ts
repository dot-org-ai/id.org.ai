/**
 * Error Format Consistency Tests
 *
 * Verifies that ALL error responses across the id.org.ai codebase use the
 * standard OAuth 2.1-compatible format:
 *
 *   {
 *     error: string              // Machine-readable error code (snake_case)
 *     error_description?: string // Human-readable description
 *     error_uri?: string         // Link to documentation
 *   }
 *
 * These tests validate:
 *   1. The error helper functions produce the correct format
 *   2. All ErrorCode constants are valid snake_case strings
 *   3. errorJson() produces correct Response objects
 *   4. errorResponse() produces correct Hono-style responses
 *   5. No extra fields (like `message`, `valid`, `upgrade`) leak into error responses
 */

import { describe, it, expect } from 'vitest'
import { ErrorCode, errorJson, errorResponse } from '../src/errors'
import type { ErrorResponse, ErrorCodeValue } from '../src/errors'

// ── ErrorCode Constants ─────────────────────────────────────────────────

describe('ErrorCode constants', () => {
  it('all error codes are non-empty snake_case strings', () => {
    const snakeCaseRegex = /^[a-z][a-z0-9]*(_[a-z0-9]+)*$/

    for (const [key, value] of Object.entries(ErrorCode)) {
      expect(typeof value).toBe('string')
      expect(value.length).toBeGreaterThan(0)
      expect(value).toMatch(snakeCaseRegex)
    }
  })

  it('all error codes are unique', () => {
    const values = Object.values(ErrorCode)
    const unique = new Set(values)
    expect(unique.size).toBe(values.length)
  })

  it('all error code keys are PascalCase', () => {
    const pascalCaseRegex = /^[A-Z][a-zA-Z0-9]+$/

    for (const key of Object.keys(ErrorCode)) {
      expect(key).toMatch(pascalCaseRegex)
    }
  })

  it('includes required HTTP error codes', () => {
    // 400
    expect(ErrorCode.InvalidRequest).toBe('invalid_request')
    expect(ErrorCode.MissingParameter).toBe('missing_parameter')

    // 401
    expect(ErrorCode.Unauthorized).toBe('unauthorized')
    expect(ErrorCode.AuthenticationRequired).toBe('authentication_required')
    expect(ErrorCode.InvalidToken).toBe('invalid_token')
    expect(ErrorCode.InvalidSignature).toBe('invalid_signature')

    // 403
    expect(ErrorCode.Forbidden).toBe('forbidden')

    // 404
    expect(ErrorCode.NotFound).toBe('not_found')

    // 429
    expect(ErrorCode.RateLimitExceeded).toBe('rate_limit_exceeded')

    // 500
    expect(ErrorCode.ServerError).toBe('server_error')

    // 503
    expect(ErrorCode.ServiceUnavailable).toBe('service_unavailable')
  })

  it('includes OAuth 2.1 / RFC 6749 error codes', () => {
    expect(ErrorCode.InvalidClient).toBe('invalid_client')
    expect(ErrorCode.InvalidGrant).toBe('invalid_grant')
    expect(ErrorCode.UnauthorizedClient).toBe('unauthorized_client')
    expect(ErrorCode.UnsupportedGrantType).toBe('unsupported_grant_type')
    expect(ErrorCode.UnsupportedResponseType).toBe('unsupported_response_type')
    expect(ErrorCode.InvalidScope).toBe('invalid_scope')
    expect(ErrorCode.AccessDenied).toBe('access_denied')
  })

  it('includes RFC 8628 device flow error codes', () => {
    expect(ErrorCode.AuthorizationPending).toBe('authorization_pending')
    expect(ErrorCode.ExpiredToken).toBe('expired_token')
  })

  it('includes domain-specific error codes', () => {
    expect(ErrorCode.ProvisionFailed).toBe('provision_failed')
    expect(ErrorCode.VerificationFailed).toBe('verification_failed')
    expect(ErrorCode.FreezeFailed).toBe('freeze_failed')
    expect(ErrorCode.InvalidClaimToken).toBe('invalid_claim_token')
    expect(ErrorCode.InsufficientLevel).toBe('insufficient_level')
  })
})

// ── errorJson() — Durable Object Response helper ────────────────────────

describe('errorJson()', () => {
  it('returns a Response with correct status code', async () => {
    const res = errorJson('not_found', 'Resource not found', 404)

    expect(res).toBeInstanceOf(Response)
    expect(res.status).toBe(404)
  })

  it('returns JSON body with error field', async () => {
    const res = errorJson('unauthorized')
    const body = await res.json() as ErrorResponse

    expect(body.error).toBe('unauthorized')
  })

  it('includes error_description when provided', async () => {
    const res = errorJson('not_found', 'Identity not found')
    const body = await res.json() as ErrorResponse

    expect(body.error).toBe('not_found')
    expect(body.error_description).toBe('Identity not found')
  })

  it('omits error_description when not provided', async () => {
    const res = errorJson('unauthorized')
    const body = await res.json() as ErrorResponse

    expect(body.error).toBe('unauthorized')
    expect(body).not.toHaveProperty('error_description')
  })

  it('defaults to status 400 when status is not specified', async () => {
    const res = errorJson('invalid_request')

    expect(res.status).toBe(400)
  })

  it('uses the provided status code', async () => {
    const res401 = errorJson('unauthorized', undefined, 401)
    const res403 = errorJson('forbidden', undefined, 403)
    const res404 = errorJson('not_found', undefined, 404)
    const res500 = errorJson('server_error', undefined, 500)

    expect(res401.status).toBe(401)
    expect(res403.status).toBe(403)
    expect(res404.status).toBe(404)
    expect(res500.status).toBe(500)
  })

  it('body contains ONLY the allowed fields (no extra properties)', async () => {
    const res = errorJson('not_found', 'Test description', 404)
    const body = await res.json() as Record<string, unknown>

    const allowedKeys = new Set(['error', 'error_description', 'error_uri'])
    for (const key of Object.keys(body)) {
      expect(allowedKeys.has(key)).toBe(true)
    }
  })

  it('does not include message, valid, upgrade, or any non-standard fields', async () => {
    const res = errorJson(ErrorCode.Unauthorized, 'Session required', 401)
    const body = await res.json() as Record<string, unknown>

    expect(body).not.toHaveProperty('message')
    expect(body).not.toHaveProperty('valid')
    expect(body).not.toHaveProperty('upgrade')
    expect(body).not.toHaveProperty('code')
    expect(body).not.toHaveProperty('status')
    expect(body).not.toHaveProperty('statusCode')
  })

  it('works with ErrorCode constants', async () => {
    const res = errorJson(ErrorCode.NotFound, 'Identity not found', 404)
    const body = await res.json() as ErrorResponse

    expect(body.error).toBe('not_found')
    expect(body.error_description).toBe('Identity not found')
  })

  it('returns proper Content-Type header', () => {
    const res = errorJson('server_error', 'Something went wrong', 500)

    // Response.json() should set application/json
    expect(res.headers.get('content-type')).toContain('application/json')
  })
})

// ── errorResponse() — Hono context helper ───────────────────────────────

describe('errorResponse()', () => {
  /** Minimal mock of Hono's context.json() method */
  function createMockContext() {
    let capturedData: unknown = null
    let capturedStatus: number | undefined = undefined

    return {
      json(data: unknown, status?: number) {
        capturedData = data
        capturedStatus = status
        return { data, status }
      },
      getCaptured() {
        return { data: capturedData as Record<string, unknown>, status: capturedStatus }
      },
    }
  }

  it('calls c.json with error body and status code', () => {
    const c = createMockContext()
    errorResponse(c, 401, 'unauthorized', 'Session required')

    const { data, status } = c.getCaptured()
    expect(status).toBe(401)
    expect(data.error).toBe('unauthorized')
    expect(data.error_description).toBe('Session required')
  })

  it('omits error_description when not provided', () => {
    const c = createMockContext()
    errorResponse(c, 403, 'forbidden')

    const { data } = c.getCaptured()
    expect(data.error).toBe('forbidden')
    expect(data).not.toHaveProperty('error_description')
  })

  it('body contains ONLY the allowed fields', () => {
    const c = createMockContext()
    errorResponse(c, 500, ErrorCode.ServerError, 'Unexpected error')

    const { data } = c.getCaptured()
    const allowedKeys = new Set(['error', 'error_description', 'error_uri'])
    for (const key of Object.keys(data)) {
      expect(allowedKeys.has(key)).toBe(true)
    }
  })

  it('does not include message, valid, upgrade, or any non-standard fields', () => {
    const c = createMockContext()
    errorResponse(c, 401, ErrorCode.Unauthorized, 'Authentication required')

    const { data } = c.getCaptured()
    expect(data).not.toHaveProperty('message')
    expect(data).not.toHaveProperty('valid')
    expect(data).not.toHaveProperty('upgrade')
    expect(data).not.toHaveProperty('code')
    expect(data).not.toHaveProperty('status')
  })

  it('works with all common status codes', () => {
    const testCases: Array<[number, string, string?]> = [
      [400, ErrorCode.InvalidRequest, 'Missing required field'],
      [401, ErrorCode.Unauthorized, 'Session token required'],
      [403, ErrorCode.Forbidden, 'Can only freeze your own identity'],
      [404, ErrorCode.NotFound, 'Identity not found'],
      [405, ErrorCode.MethodNotAllowed],
      [429, ErrorCode.RateLimitExceeded, 'Too many requests'],
      [500, ErrorCode.ServerError, 'Internal server error'],
      [503, ErrorCode.ServiceUnavailable, 'GitHub App not configured'],
    ]

    for (const [statusCode, errorCode, description] of testCases) {
      const c = createMockContext()
      errorResponse(c, statusCode, errorCode, description)

      const { data, status } = c.getCaptured()
      expect(status).toBe(statusCode)
      expect(data.error).toBe(errorCode)
      if (description) {
        expect(data.error_description).toBe(description)
      } else {
        expect(data).not.toHaveProperty('error_description')
      }
    }
  })
})

// ── Format Contract Tests ───────────────────────────────────────────────

describe('Error format contract', () => {
  it('error field is always a string', async () => {
    const res = errorJson(ErrorCode.NotFound, 'test', 404)
    const body = await res.json() as ErrorResponse

    expect(typeof body.error).toBe('string')
  })

  it('error_description is a string when present', async () => {
    const res = errorJson(ErrorCode.Unauthorized, 'Session token required', 401)
    const body = await res.json() as ErrorResponse

    expect(typeof body.error_description).toBe('string')
  })

  it('error_description is undefined (not null, not empty) when omitted', async () => {
    const res = errorJson(ErrorCode.Unauthorized, undefined, 401)
    const body = await res.json() as Record<string, unknown>

    // The key should not exist at all in the JSON
    expect('error_description' in body).toBe(false)
  })

  it('the response body is a flat object (no nesting)', async () => {
    const res = errorJson(ErrorCode.ServerError, 'Something broke', 500)
    const body = await res.json() as Record<string, unknown>

    for (const [key, value] of Object.entries(body)) {
      expect(typeof value).not.toBe('object')
      expect(Array.isArray(value)).toBe(false)
    }
  })

  it('empty description string is treated as no description', async () => {
    // Empty string is falsy, so errorJson should omit error_description
    const res = errorJson(ErrorCode.NotFound, '')
    const body = await res.json() as Record<string, unknown>

    expect('error_description' in body).toBe(false)
  })
})

// ── ErrorCodeValue type tests ───────────────────────────────────────────

describe('ErrorCodeValue type', () => {
  it('all error code values satisfy ErrorCodeValue', () => {
    // This is primarily a compile-time check, but we can verify at runtime
    const allValues: ErrorCodeValue[] = Object.values(ErrorCode)
    expect(allValues.length).toBeGreaterThan(0)

    // Every value should be a string from the ErrorCode object
    for (const v of allValues) {
      expect(typeof v).toBe('string')
      expect(Object.values(ErrorCode)).toContain(v)
    }
  })
})
