/**
 * Typed error classes with _tag discrimination for id.org.ai
 *
 * Each class has a `readonly _tag` for exhaustive switch discrimination.
 * `toErrorResponse` bridges DomainError → { code, status, description }
 * compatible with OAuth 2.1 `error_description` naming.
 */

// ============================================================================
// Foundation Error Classes
// ============================================================================

export class NotFoundError {
  readonly _tag = 'NotFoundError' as const
  readonly message: string
  constructor(
    readonly entity: string,
    readonly id: string,
  ) {
    this.message = `${entity} not found: ${id}`
  }
}

export class ValidationError {
  readonly _tag = 'ValidationError' as const
  constructor(
    readonly field: string,
    readonly message: string,
  ) {}
}

export class AuthError {
  readonly _tag = 'AuthError' as const
  constructor(
    readonly code: 'unauthorized' | 'forbidden' | 'expired',
    readonly message: string,
  ) {}
}

export class ConflictError {
  readonly _tag = 'ConflictError' as const
  constructor(
    readonly entity: string,
    readonly message: string,
  ) {}
}

export class RateLimitError {
  readonly _tag = 'RateLimitError' as const
  readonly message: string
  constructor(readonly retryAfter: number) {
    this.message = `Rate limit exceeded, retry after ${retryAfter}s`
  }
}

// ============================================================================
// Domain Error Classes
// ============================================================================

export class OAuthError {
  readonly _tag = 'OAuthError' as const
  constructor(
    readonly code: string,
    readonly message: string,
  ) {}
}

export class ClaimError {
  readonly _tag = 'ClaimError' as const
  constructor(
    readonly code: string,
    readonly message: string,
  ) {}
}

export class KeyError {
  readonly _tag = 'KeyError' as const
  constructor(
    readonly code: string,
    readonly message: string,
  ) {}
}

// ============================================================================
// DomainError Union
// ============================================================================

export type DomainError =
  | NotFoundError
  | ValidationError
  | AuthError
  | ConflictError
  | RateLimitError
  | OAuthError
  | ClaimError
  | KeyError

// ============================================================================
// toErrorResponse Bridge
// ============================================================================

export interface ErrorResponseShape {
  code: string
  status: number
  description: string
}

export function toErrorResponse(error: DomainError): ErrorResponseShape {
  switch (error._tag) {
    case 'NotFoundError':
      return { code: 'not_found', status: 404, description: error.message }

    case 'ValidationError':
      return { code: 'invalid_request', status: 400, description: error.message }

    case 'AuthError': {
      const { code: authCode, message } = error
      if (authCode === 'unauthorized') return { code: 'unauthorized', status: 401, description: message }
      if (authCode === 'forbidden') return { code: 'forbidden', status: 403, description: message }
      return { code: 'expired_token', status: 401, description: message }
    }

    case 'ConflictError':
      return { code: 'conflict', status: 409, description: error.message }

    case 'RateLimitError':
      return { code: 'rate_limit_exceeded', status: 429, description: error.message }

    case 'OAuthError': {
      const { code, message } = error
      if (code === 'invalid_client') return { code: 'invalid_client', status: 401, description: message }
      if (code === 'access_denied') return { code: 'access_denied', status: 403, description: message }
      if (code === 'unauthorized_client') return { code: 'unauthorized_client', status: 403, description: message }
      return { code, status: 400, description: message }
    }

    case 'ClaimError': {
      const { code, message } = error
      if (code === 'invalid_token') return { code: 'invalid_claim_token', status: 404, description: message }
      return { code, status: 400, description: message }
    }

    case 'KeyError': {
      const { code, message } = error
      if (code === 'already_revoked') return { code: 'conflict', status: 409, description: message }
      return { code: 'invalid_request', status: 400, description: message }
    }
  }
}
