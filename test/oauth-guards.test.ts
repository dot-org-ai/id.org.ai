import { describe, it, expect } from 'vitest'
import {
  assertValid,
  ValidationError,
  isStripeWebhookEvent,
  isStripeApiError,
  isJWTHeader,
  isJWTPayload,
  isSerializedSigningKey,
  isStringArray,
  isIntrospectionResponse,
} from '../src/oauth/guards'

describe('OAuth Guards', () => {
  describe('ValidationError', () => {
    it('has correct name and message', () => {
      const err = new ValidationError('TestType', 'something went wrong', { bad: 'data' })
      expect(err.name).toBe('ValidationError')
      expect(err.message).toBe('Invalid TestType: something went wrong')
      expect(err.expectedType).toBe('TestType')
      expect(err.details).toBe('something went wrong')
      expect(err.data).toEqual({ bad: 'data' })
    })
  })

  describe('assertValid', () => {
    const isNonEmptyString = (v: unknown): v is string => typeof v === 'string' && v.length > 0

    it('returns data when guard passes', () => {
      const result = assertValid('hello', isNonEmptyString, 'NonEmptyString')
      expect(result).toBe('hello')
    })

    it('throws ValidationError when guard fails', () => {
      expect(() => assertValid('', isNonEmptyString, 'NonEmptyString')).toThrow(ValidationError)
      expect(() => assertValid(null, isNonEmptyString, 'NonEmptyString')).toThrow(ValidationError)
    })

    it('includes type name in error message', () => {
      try {
        assertValid(42, isNonEmptyString, 'NonEmptyString')
        expect.fail('should have thrown')
      } catch (e) {
        expect(e).toBeInstanceOf(ValidationError)
        expect((e as ValidationError).expectedType).toBe('NonEmptyString')
      }
    })
  })

  describe('isStripeWebhookEvent', () => {
    it('returns true for valid event', () => {
      expect(
        isStripeWebhookEvent({
          id: 'evt_123',
          type: 'customer.created',
          data: { object: { id: 'cus_123' } },
        }),
      ).toBe(true)
    })

    it('returns false for non-object', () => {
      expect(isStripeWebhookEvent(null)).toBe(false)
      expect(isStripeWebhookEvent('string')).toBe(false)
    })

    it('returns false for missing id', () => {
      expect(isStripeWebhookEvent({ type: 'customer.created', data: { object: {} } })).toBe(false)
    })

    it('returns false for invalid event type', () => {
      expect(isStripeWebhookEvent({ id: 'evt_123', type: 'unknown.event', data: { object: {} } })).toBe(false)
    })

    it('returns false when data.object is missing', () => {
      expect(isStripeWebhookEvent({ id: 'evt_123', type: 'customer.created', data: {} })).toBe(false)
    })
  })

  describe('isStripeApiError', () => {
    it('returns true for valid error shape', () => {
      expect(isStripeApiError({ error: { message: 'bad request' } })).toBe(true)
    })

    it('returns true for empty object (no error field)', () => {
      expect(isStripeApiError({})).toBe(true)
    })

    it('returns false for non-object', () => {
      expect(isStripeApiError(null)).toBe(false)
      expect(isStripeApiError(42)).toBe(false)
    })
  })

  describe('isJWTHeader', () => {
    it('returns true for valid header', () => {
      expect(isJWTHeader({ alg: 'RS256' })).toBe(true)
      expect(isJWTHeader({ alg: 'RS256', typ: 'JWT', kid: 'key-1' })).toBe(true)
    })

    it('returns false for missing alg', () => {
      expect(isJWTHeader({})).toBe(false)
      expect(isJWTHeader({ typ: 'JWT' })).toBe(false)
    })

    it('returns false for non-object', () => {
      expect(isJWTHeader(null)).toBe(false)
      expect(isJWTHeader('header')).toBe(false)
    })

    it('returns false when typ is not a string', () => {
      expect(isJWTHeader({ alg: 'RS256', typ: 123 })).toBe(false)
    })
  })

  describe('isJWTPayload', () => {
    it('returns true for valid payload', () => {
      expect(isJWTPayload({})).toBe(true)
      expect(isJWTPayload({ iss: 'https://auth.example.com', sub: 'user_1', exp: 9999999999 })).toBe(true)
    })

    it('returns true with aud as string or string[]', () => {
      expect(isJWTPayload({ aud: 'client_1' })).toBe(true)
      expect(isJWTPayload({ aud: ['client_1', 'client_2'] })).toBe(true)
    })

    it('returns false for non-object', () => {
      expect(isJWTPayload(null)).toBe(false)
      expect(isJWTPayload([])).toBe(false)
    })

    it('returns false for invalid field types', () => {
      expect(isJWTPayload({ iss: 123 })).toBe(false)
      expect(isJWTPayload({ exp: 'not a number' })).toBe(false)
      expect(isJWTPayload({ aud: 123 })).toBe(false)
    })
  })

  describe('isSerializedSigningKey', () => {
    const validKey = {
      kid: 'key-1',
      alg: 'RS256',
      privateKeyJwk: { kty: 'RSA' },
      publicKeyJwk: { kty: 'RSA' },
      createdAt: Date.now(),
    }

    it('returns true for valid key', () => {
      expect(isSerializedSigningKey(validKey)).toBe(true)
    })

    it('returns false for wrong alg', () => {
      expect(isSerializedSigningKey({ ...validKey, alg: 'ES256' })).toBe(false)
    })

    it('returns false for missing fields', () => {
      expect(isSerializedSigningKey({ kid: 'key-1' })).toBe(false)
    })
  })

  describe('isStringArray', () => {
    it('returns true for string arrays', () => {
      expect(isStringArray([])).toBe(true)
      expect(isStringArray(['a', 'b'])).toBe(true)
    })

    it('returns false for non-arrays', () => {
      expect(isStringArray(null)).toBe(false)
      expect(isStringArray('string')).toBe(false)
    })

    it('returns false for mixed arrays', () => {
      expect(isStringArray(['a', 1])).toBe(false)
    })
  })

  describe('isIntrospectionResponse', () => {
    it('returns true for valid response', () => {
      expect(isIntrospectionResponse({ active: true })).toBe(true)
      expect(isIntrospectionResponse({ active: false, sub: 'user_1', scope: 'openid' })).toBe(true)
    })

    it('returns false for missing active field', () => {
      expect(isIntrospectionResponse({})).toBe(false)
    })

    it('returns false for non-boolean active', () => {
      expect(isIntrospectionResponse({ active: 'yes' })).toBe(false)
    })

    it('returns false for invalid field types', () => {
      expect(isIntrospectionResponse({ active: true, sub: 123 })).toBe(false)
      expect(isIntrospectionResponse({ active: true, exp: 'not a number' })).toBe(false)
    })
  })
})
