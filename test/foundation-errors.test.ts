import { describe, it, expect } from 'vitest'
import {
  NotFoundError,
  ValidationError,
  AuthError,
  ConflictError,
  RateLimitError,
  OAuthError,
  ClaimError,
  KeyError,
  toErrorResponse,
  type DomainError,
} from '../src/sdk/foundation/errors'

describe('NotFoundError', () => {
  it('constructs with correct fields', () => {
    const err = new NotFoundError('identity', 'id_123')
    expect(err._tag).toBe('NotFoundError')
    expect(err.entity).toBe('identity')
    expect(err.id).toBe('id_123')
    expect(err.message).toBe('identity not found: id_123')
  })
})

describe('ValidationError', () => {
  it('constructs with correct fields', () => {
    const err = new ValidationError('email', 'must be valid')
    expect(err._tag).toBe('ValidationError')
    expect(err.field).toBe('email')
    expect(err.message).toBe('must be valid')
  })
})

describe('AuthError', () => {
  it('constructs unauthorized', () => {
    const err = new AuthError('unauthorized', 'Session expired')
    expect(err._tag).toBe('AuthError')
    expect(err.code).toBe('unauthorized')
    expect(err.message).toBe('Session expired')
  })

  it('constructs forbidden', () => {
    const err = new AuthError('forbidden', 'Access denied')
    expect(err.code).toBe('forbidden')
  })

  it('constructs expired', () => {
    const err = new AuthError('expired', 'Token expired')
    expect(err.code).toBe('expired')
  })
})

describe('ConflictError', () => {
  it('constructs with correct fields', () => {
    const err = new ConflictError('identity', 'Already claimed')
    expect(err._tag).toBe('ConflictError')
    expect(err.entity).toBe('identity')
    expect(err.message).toBe('Already claimed')
  })
})

describe('RateLimitError', () => {
  it('constructs with correct fields', () => {
    const err = new RateLimitError(60)
    expect(err._tag).toBe('RateLimitError')
    expect(err.retryAfter).toBe(60)
    expect(err.message).toBe('Rate limit exceeded, retry after 60s')
  })
})

describe('OAuthError', () => {
  it('constructs with correct fields', () => {
    const err = new OAuthError('invalid_grant', 'Expired')
    expect(err._tag).toBe('OAuthError')
    expect(err.code).toBe('invalid_grant')
    expect(err.message).toBe('Expired')
  })
})

describe('ClaimError', () => {
  it('constructs with correct fields', () => {
    const err = new ClaimError('already_claimed', 'Done')
    expect(err._tag).toBe('ClaimError')
    expect(err.code).toBe('already_claimed')
    expect(err.message).toBe('Done')
  })
})

describe('KeyError', () => {
  it('constructs with correct fields', () => {
    const err = new KeyError('duplicate_did', 'Exists')
    expect(err._tag).toBe('KeyError')
    expect(err.code).toBe('duplicate_did')
    expect(err.message).toBe('Exists')
  })
})

describe('_tag discrimination', () => {
  it('all 8 error types have unique _tag values', () => {
    const tags = [
      new NotFoundError('x', 'y')._tag,
      new ValidationError('f', 'm')._tag,
      new AuthError('unauthorized', 'm')._tag,
      new ConflictError('e', 'm')._tag,
      new RateLimitError(1)._tag,
      new OAuthError('invalid_grant', 'm')._tag,
      new ClaimError('already_claimed', 'm')._tag,
      new KeyError('duplicate_did', 'm')._tag,
    ]
    const unique = new Set(tags)
    expect(unique.size).toBe(8)
  })

  it('supports exhaustive switch with never in default', () => {
    function handleError(err: DomainError): string {
      switch (err._tag) {
        case 'NotFoundError': return 'not_found'
        case 'ValidationError': return 'validation'
        case 'AuthError': return 'auth'
        case 'ConflictError': return 'conflict'
        case 'RateLimitError': return 'rate_limit'
        case 'OAuthError': return 'oauth'
        case 'ClaimError': return 'claim'
        case 'KeyError': return 'key'
        default: {
          const _exhaustive: never = err
          return _exhaustive
        }
      }
    }

    expect(handleError(new NotFoundError('x', 'y'))).toBe('not_found')
    expect(handleError(new OAuthError('invalid_grant', 'm'))).toBe('oauth')
  })
})

describe('toErrorResponse', () => {
  it('NotFoundError → 404 not_found', () => {
    const res = toErrorResponse(new NotFoundError('identity', 'id_123'))
    expect(res.code).toBe('not_found')
    expect(res.status).toBe(404)
    expect(res.description).toBe('identity not found: id_123')
  })

  it('ValidationError → 400 invalid_request', () => {
    const res = toErrorResponse(new ValidationError('email', 'invalid'))
    expect(res.code).toBe('invalid_request')
    expect(res.status).toBe(400)
    expect(res.description).toBe('invalid')
  })

  it('AuthError(unauthorized) → 401 unauthorized', () => {
    const res = toErrorResponse(new AuthError('unauthorized', 'Session expired'))
    expect(res.code).toBe('unauthorized')
    expect(res.status).toBe(401)
  })

  it('AuthError(forbidden) → 403 forbidden', () => {
    const res = toErrorResponse(new AuthError('forbidden', 'Access denied'))
    expect(res.code).toBe('forbidden')
    expect(res.status).toBe(403)
  })

  it('AuthError(expired) → 401 expired_token', () => {
    const res = toErrorResponse(new AuthError('expired', 'Token expired'))
    expect(res.code).toBe('expired_token')
    expect(res.status).toBe(401)
  })

  it('ConflictError → 409 conflict', () => {
    const res = toErrorResponse(new ConflictError('identity', 'Already claimed'))
    expect(res.code).toBe('conflict')
    expect(res.status).toBe(409)
  })

  it('RateLimitError(30) → 429 rate_limit_exceeded with retryAfter in description', () => {
    const res = toErrorResponse(new RateLimitError(30))
    expect(res.code).toBe('rate_limit_exceeded')
    expect(res.status).toBe(429)
    expect(res.description).toContain('30')
  })

  it('OAuthError(invalid_grant) → 400', () => {
    const res = toErrorResponse(new OAuthError('invalid_grant', 'Expired'))
    expect(res.code).toBe('invalid_grant')
    expect(res.status).toBe(400)
  })

  it('OAuthError(invalid_client) → 401', () => {
    const res = toErrorResponse(new OAuthError('invalid_client', 'Bad client'))
    expect(res.code).toBe('invalid_client')
    expect(res.status).toBe(401)
  })

  it('OAuthError(access_denied) → 403', () => {
    const res = toErrorResponse(new OAuthError('access_denied', 'Denied'))
    expect(res.code).toBe('access_denied')
    expect(res.status).toBe(403)
  })

  it('OAuthError(unauthorized_client) → 403', () => {
    const res = toErrorResponse(new OAuthError('unauthorized_client', 'Not allowed'))
    expect(res.code).toBe('unauthorized_client')
    expect(res.status).toBe(403)
  })

  it('ClaimError(already_claimed) → 400', () => {
    const res = toErrorResponse(new ClaimError('already_claimed', 'Done'))
    expect(res.code).toBe('already_claimed')
    expect(res.status).toBe(400)
  })

  it('ClaimError(invalid_token) → 404 invalid_claim_token', () => {
    const res = toErrorResponse(new ClaimError('invalid_token', 'Bad token'))
    expect(res.code).toBe('invalid_claim_token')
    expect(res.status).toBe(404)
  })

  it('KeyError(duplicate_did) → 400 invalid_request', () => {
    const res = toErrorResponse(new KeyError('duplicate_did', 'Exists'))
    expect(res.code).toBe('invalid_request')
    expect(res.status).toBe(400)
  })

  it('KeyError(already_revoked) → 409 conflict', () => {
    const res = toErrorResponse(new KeyError('already_revoked', 'Already done'))
    expect(res.code).toBe('conflict')
    expect(res.status).toBe(409)
  })

  it('output type: code is string, status is number, description is string', () => {
    const res = toErrorResponse(new NotFoundError('x', 'y'))
    expect(typeof res.code).toBe('string')
    expect(typeof res.status).toBe('number')
    expect(typeof res.description).toBe('string')
  })
})
