/**
 * Runtime type guards for JSON data validation
 *
 * These guards replace unsafe `as Type` assertions on data from
 * JSON.parse(), response.json(), and other untrusted sources
 * in the OAuth 2.1 server core.
 *
 * Ported from @dotdo/oauth core/src/guards.ts
 *
 * @module oauth/guards
 */

import type { SerializedSigningKey } from '../jwt'
import type { JWTHeader, JWTPayload } from './jwt-verify'

// ═══════════════════════════════════════════════════════════════════════════
// Stripe type (minimal, defined locally to avoid pulling in Stripe module)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Stripe webhook event (minimal shape for guard validation)
 */
export interface StripeWebhookEvent {
  id: string
  type: string
  data: {
    object: Record<string, unknown>
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function isString(value: unknown): value is string {
  return typeof value === 'string'
}

function isNumber(value: unknown): value is number {
  return typeof value === 'number' && !Number.isNaN(value)
}

// ═══════════════════════════════════════════════════════════════════════════
// Validation Error
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Error thrown when runtime JSON validation fails
 */
export class ValidationError extends Error {
  constructor(
    public readonly expectedType: string,
    public readonly details: string,
    public readonly data?: unknown,
  ) {
    super(`Invalid ${expectedType}: ${details}`)
    this.name = 'ValidationError'
  }
}

/**
 * Assert that data passes a type guard, throwing ValidationError if not
 */
export function assertValid<T>(data: unknown, guard: (value: unknown) => value is T, typeName: string): T {
  if (!guard(data)) {
    throw new ValidationError(typeName, 'failed runtime validation', data)
  }
  return data
}

// ═══════════════════════════════════════════════════════════════════════════
// Stripe Types
// ═══════════════════════════════════════════════════════════════════════════

const VALID_STRIPE_EVENT_TYPES = new Set<string>([
  'customer.created',
  'customer.updated',
  'customer.deleted',
  'customer.subscription.created',
  'customer.subscription.updated',
  'customer.subscription.deleted',
  'invoice.paid',
  'invoice.payment_failed',
])

/**
 * Check if data is a valid StripeWebhookEvent
 *
 * Required: id (string), type (valid event type), data.object (object)
 */
export function isStripeWebhookEvent(data: unknown): data is StripeWebhookEvent {
  if (!isObject(data)) return false
  if (!isString(data['id'])) return false
  if (!isString(data['type'])) return false
  if (!VALID_STRIPE_EVENT_TYPES.has(data['type'] as string)) return false
  if (!isObject(data['data'])) return false
  if (!isObject((data['data'] as Record<string, unknown>)['object'])) return false
  return true
}

/**
 * Check if data is a Stripe API error response
 */
export function isStripeApiError(data: unknown): data is { error?: { message?: string } } {
  if (!isObject(data)) return false
  if (data['error'] !== undefined) {
    if (!isObject(data['error'])) return false
    if ((data['error'] as Record<string, unknown>)['message'] !== undefined && !isString((data['error'] as Record<string, unknown>)['message'])) return false
  }
  return true
}

// ═══════════════════════════════════════════════════════════════════════════
// JWT Types
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Check if data is a valid JWTHeader
 *
 * Required: alg (string)
 * Optional: typ (string), kid (string)
 */
export function isJWTHeader(data: unknown): data is JWTHeader {
  if (!isObject(data)) return false
  if (!isString(data['alg'])) return false
  if (data['typ'] !== undefined && !isString(data['typ'])) return false
  if (data['kid'] !== undefined && !isString(data['kid'])) return false
  return true
}

/**
 * Check if data is a valid JWTPayload
 *
 * All standard fields are optional; additional claims allowed via index signature.
 */
export function isJWTPayload(data: unknown): data is JWTPayload {
  if (!isObject(data)) return false
  if (data['iss'] !== undefined && !isString(data['iss'])) return false
  if (data['sub'] !== undefined && !isString(data['sub'])) return false
  if (data['exp'] !== undefined && !isNumber(data['exp'])) return false
  if (data['nbf'] !== undefined && !isNumber(data['nbf'])) return false
  if (data['iat'] !== undefined && !isNumber(data['iat'])) return false
  if (data['jti'] !== undefined && !isString(data['jti'])) return false
  // aud can be string or string[]
  if (data['aud'] !== undefined) {
    if (!isString(data['aud']) && !Array.isArray(data['aud'])) return false
    if (Array.isArray(data['aud']) && !(data['aud'] as unknown[]).every((a: unknown) => isString(a))) return false
  }
  return true
}

// ═══════════════════════════════════════════════════════════════════════════
// Signing Key Types
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Check if data is a valid SerializedSigningKey
 *
 * Required: kid (string), alg ('RS256'), privateKeyJwk (object), publicKeyJwk (object), createdAt (number)
 */
export function isSerializedSigningKey(data: unknown): data is SerializedSigningKey {
  if (!isObject(data)) return false
  if (!isString(data['kid'])) return false
  if (data['alg'] !== 'RS256') return false
  if (!isObject(data['privateKeyJwk'])) return false
  if (!isObject(data['publicKeyJwk'])) return false
  if (!isNumber(data['createdAt'])) return false
  return true
}

// ═══════════════════════════════════════════════════════════════════════════
// Storage Types
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Check if data is a valid string array (e.g., parsed domains from SQLite JSON)
 */
export function isStringArray(data: unknown): data is string[] {
  return Array.isArray(data) && data.every((item) => isString(item))
}

// ═══════════════════════════════════════════════════════════════════════════
// Introspection Response
// ═══════════════════════════════════════════════════════════════════════════

/**
 * OAuth introspection response shape
 */
export interface IntrospectionResponseShape {
  active: boolean
  sub?: string
  client_id?: string
  scope?: string
  exp?: number
  iat?: number
  iss?: string
  aud?: string | string[]
  [key: string]: unknown
}

/**
 * Check if data is a valid introspection response
 *
 * Required: active (boolean)
 */
export function isIntrospectionResponse(data: unknown): data is IntrospectionResponseShape {
  if (!isObject(data)) return false
  if (typeof data['active'] !== 'boolean') return false
  if (data['sub'] !== undefined && !isString(data['sub'])) return false
  if (data['client_id'] !== undefined && !isString(data['client_id'])) return false
  if (data['scope'] !== undefined && !isString(data['scope'])) return false
  if (data['exp'] !== undefined && !isNumber(data['exp'])) return false
  if (data['iat'] !== undefined && !isNumber(data['iat'])) return false
  if (data['iss'] !== undefined && !isString(data['iss'])) return false
  return true
}
