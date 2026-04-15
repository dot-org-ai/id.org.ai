/**
 * Standardized Error Responses for id.org.ai
 *
 * All error responses across the codebase MUST use this format,
 * which is compatible with OAuth 2.1 (RFC 6749 Section 5.2):
 *
 *   {
 *     error: string              // Machine-readable error code (snake_case)
 *     error_description?: string // Human-readable description
 *     error_uri?: string         // Link to documentation
 *   }
 *
 * Usage:
 *   // In Hono routes (worker/index.ts):
 *   return errorResponse(c, 401, ErrorCode.Unauthorized, 'Session token required')
 *
 *   // In Durable Object fetch handlers (Response.json):
 *   return errorJson(ErrorCode.NotFound, 'Identity not found', 404)
 *
 *   // In OAuth provider (already uses oauthError which returns this format):
 *   return oauthError('invalid_grant', 'Authorization code has expired')
 */

// ============================================================================
// Error Codes — Machine-readable, snake_case, stable API contract
// ============================================================================

/**
 * Standard error codes used across id.org.ai endpoints.
 *
 * These are grouped by HTTP status code family:
 *   - 400: Client errors (bad request, validation)
 *   - 401: Authentication errors
 *   - 403: Authorization errors
 *   - 404: Not found
 *   - 405: Method not allowed
 *   - 429: Rate limiting
 *   - 500: Server errors
 *   - 503: Service unavailable
 */
export const ErrorCode = {
  // ── 400 Bad Request ────────────────────────────────────────────────────
  InvalidRequest: 'invalid_request',
  InvalidClientMetadata: 'invalid_client_metadata',
  InvalidRedirectUri: 'invalid_redirect_uri',
  MissingParameter: 'missing_parameter',

  // ── 401 Unauthorized ──────────────────────────────────────────────────
  Unauthorized: 'unauthorized',
  AuthenticationRequired: 'authentication_required',
  InvalidToken: 'invalid_token',
  InvalidSignature: 'invalid_signature',
  InvalidClient: 'invalid_client',
  InvalidGrant: 'invalid_grant',

  // ── 403 Forbidden ─────────────────────────────────────────────────────
  Forbidden: 'forbidden',
  InsufficientLevel: 'insufficient_level',
  UnauthorizedClient: 'unauthorized_client',
  AccessDenied: 'access_denied',

  // ── 404 Not Found ─────────────────────────────────────────────────────
  NotFound: 'not_found',
  InvalidClaimToken: 'invalid_claim_token',

  // ── 405 Method Not Allowed ────────────────────────────────────────────
  MethodNotAllowed: 'method_not_allowed',

  // ── 429 Rate Limited ──────────────────────────────────────────────────
  RateLimitExceeded: 'rate_limit_exceeded',

  // ── 500 Server Error ──────────────────────────────────────────────────
  ServerError: 'server_error',
  ProvisionFailed: 'provision_failed',
  VerificationFailed: 'verification_failed',
  FreezeFailed: 'freeze_failed',

  // ── 503 Service Unavailable ───────────────────────────────────────────
  ServiceUnavailable: 'service_unavailable',

  // ── OAuth-specific (RFC 6749 / RFC 8628) ──────────────────────────────
  UnsupportedGrantType: 'unsupported_grant_type',
  UnsupportedResponseType: 'unsupported_response_type',
  InvalidScope: 'invalid_scope',
  AuthorizationPending: 'authorization_pending',
  ExpiredToken: 'expired_token',
} as const

export type ErrorCodeValue = (typeof ErrorCode)[keyof typeof ErrorCode]

// ============================================================================
// Error Response Interface (OAuth 2.1 compatible)
// ============================================================================

/**
 * Standard error response body.
 *
 * Compatible with OAuth 2.1 (RFC 6749 Section 5.2).
 * The `error` field is always present; `error_description` and `error_uri`
 * are optional but recommended for human/agent debugging.
 */
export interface ErrorResponse {
  /** Machine-readable error code (snake_case) */
  error: string
  /** Human-readable description of the error */
  error_description?: string
  /** URI to documentation about this error */
  error_uri?: string
}

// ============================================================================
// Error Response Helpers
// ============================================================================

/**
 * Create a standard error Response (for use in Durable Object fetch handlers
 * and anywhere that returns raw Response objects).
 *
 * @param error - Machine-readable error code
 * @param description - Optional human-readable description
 * @param status - HTTP status code (default 400)
 * @returns Response with JSON error body
 *
 * @example
 * ```ts
 * return errorJson(ErrorCode.NotFound, 'Identity not found', 404)
 * return errorJson(ErrorCode.Unauthorized, undefined, 403)
 * ```
 */
export function errorJson(
  error: string,
  description?: string,
  status = 400,
): Response {
  const body: ErrorResponse = { error }
  if (description) body.error_description = description
  return Response.json(body, { status })
}

/**
 * Create a standard error response using Hono's context.
 *
 * @param c - Hono context
 * @param status - HTTP status code
 * @param error - Machine-readable error code
 * @param description - Optional human-readable description
 * @returns Hono JSON response
 *
 * @example
 * ```ts
 * return errorResponse(c, 401, ErrorCode.Unauthorized, 'Session token required')
 * return errorResponse(c, 404, ErrorCode.NotFound)
 * ```
 */
export function errorResponse(
  c: { json: (data: unknown, status?: number) => unknown },
  status: number,
  error: string,
  description?: string,
): unknown {
  const body: ErrorResponse = { error }
  if (description) body.error_description = description
  return c.json(body, status)
}
