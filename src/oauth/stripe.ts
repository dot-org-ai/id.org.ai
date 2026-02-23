/**
 * Stripe Identity Linkage
 *
 * Minimal Stripe integration for customer management and webhooks.
 * This module provides helpers for linking OAuth users to Stripe customers.
 *
 * Ported from @dotdo/oauth core/src/stripe.ts
 *
 * @module oauth/stripe
 */

import type { OAuthUser } from './types'
import { isStripeWebhookEvent, isStripeApiError, ValidationError } from './guards'

/**
 * Stripe customer data
 */
export interface StripeCustomer {
  id: string
  email: string | null
  name: string | null
  metadata: Record<string, string>
}

/**
 * Stripe subscription data
 */
export interface StripeSubscription {
  id: string
  customerId: string
  status: 'active' | 'past_due' | 'canceled' | 'trialing' | 'unpaid' | 'incomplete' | 'incomplete_expired' | 'paused'
  priceId: string
  currentPeriodEnd: number
}

/**
 * Stripe webhook event types we handle
 */
export type StripeWebhookEventType =
  | 'customer.created'
  | 'customer.updated'
  | 'customer.deleted'
  | 'customer.subscription.created'
  | 'customer.subscription.updated'
  | 'customer.subscription.deleted'
  | 'invoice.paid'
  | 'invoice.payment_failed'

/**
 * Stripe webhook event
 */
export interface StripeWebhookEvent {
  id: string
  type: StripeWebhookEventType
  data: {
    object: Record<string, unknown>
  }
}

/**
 * Storage interface for Stripe-related operations
 */
export interface StripeStorage {
  getUserByStripeCustomerId(stripeCustomerId: string): Promise<OAuthUser | null>
  updateUserStripeCustomerId(userId: string, stripeCustomerId: string): Promise<void>
  getUser(id: string): Promise<OAuthUser | null>
  saveUser(user: OAuthUser): Promise<void>
}

/**
 * Extended user type with Stripe fields
 */
export interface OAuthUserWithStripe extends OAuthUser {
  stripeCustomerId?: string
  stripeSubscriptionId?: string
  stripeSubscriptionStatus?: StripeSubscription['status']
}

/**
 * Stripe client interface (compatible with stripe npm package)
 */
export interface StripeClient {
  customers: {
    create(params: { email?: string; name?: string; metadata?: Record<string, string> }): Promise<{ id: string }>
    retrieve(id: string): Promise<StripeCustomer>
    update(id: string, params: { metadata?: Record<string, string> }): Promise<StripeCustomer>
  }
  subscriptions: {
    retrieve(id: string): Promise<{
      id: string
      customer: string
      status: StripeSubscription['status']
      items: { data: Array<{ price: { id: string } }> }
      current_period_end: number
    }>
  }
  webhooks: {
    constructEvent(payload: string, signature: string, secret: string): Promise<StripeWebhookEvent>
  }
}

/**
 * Ensure a user has a Stripe customer ID, creating one if needed
 */
export async function ensureStripeCustomer(user: OAuthUserWithStripe, stripe: StripeClient, storage: StripeStorage): Promise<string> {
  // Already has a customer ID
  if (user.stripeCustomerId) {
    return user.stripeCustomerId
  }

  // Create a new Stripe customer
  const createParams: { email?: string; name?: string; metadata?: Record<string, string> } = {
    metadata: {
      userId: user.id,
      ...(user.organizationId && { organizationId: user.organizationId }),
    },
  }
  if (user.email) createParams.email = user.email
  if (user.name) createParams.name = user.name

  const customer = await stripe.customers.create(createParams)

  // Update the user with the Stripe customer ID
  await storage.updateUserStripeCustomerId(user.id, customer.id)

  return customer.id
}

/**
 * Get Stripe customer for a user, or null if not linked
 */
export async function getStripeCustomer(user: OAuthUserWithStripe, stripe: StripeClient): Promise<StripeCustomer | null> {
  if (!user.stripeCustomerId) {
    return null
  }

  try {
    return await stripe.customers.retrieve(user.stripeCustomerId)
  } catch {
    return null
  }
}

/**
 * Link an existing Stripe customer to a user
 */
export async function linkStripeCustomer(userId: string, stripeCustomerId: string, stripe: StripeClient, storage: StripeStorage): Promise<void> {
  // Update Stripe customer metadata
  await stripe.customers.update(stripeCustomerId, {
    metadata: { userId },
  })

  // Update our user record
  await storage.updateUserStripeCustomerId(userId, stripeCustomerId)
}

/**
 * Handle Stripe webhook events
 */
export async function handleStripeWebhook(event: StripeWebhookEvent, storage: StripeStorage): Promise<{ handled: boolean; action?: string }> {
  switch (event.type) {
    case 'customer.created':
    case 'customer.updated': {
      const customer = event.data.object as {
        id: string
        metadata?: { userId?: string }
      }

      // If we have a userId in metadata, ensure the link exists
      if (customer.metadata?.userId) {
        const user = await storage.getUser(customer.metadata.userId)
        if (user) {
          await storage.updateUserStripeCustomerId(user.id, customer.id)
          return { handled: true, action: 'linked_customer' }
        }
      }
      return { handled: true, action: 'customer_event_no_user' }
    }

    case 'customer.deleted': {
      const customer = event.data.object as { id: string }
      const user = await storage.getUserByStripeCustomerId(customer.id)
      if (user) {
        // Clear the stripe customer ID
        await storage.updateUserStripeCustomerId(user.id, '')
        return { handled: true, action: 'unlinked_customer' }
      }
      return { handled: true, action: 'customer_deleted_no_user' }
    }

    case 'customer.subscription.created':
    case 'customer.subscription.updated':
    case 'customer.subscription.deleted': {
      const subscription = event.data.object as {
        id: string
        customer: string
        status: StripeSubscription['status']
      }

      const user = (await storage.getUserByStripeCustomerId(subscription.customer)) as OAuthUserWithStripe | null
      if (user) {
        // Update subscription info in user metadata
        const isDeleted = event.type === 'customer.subscription.deleted'
        const updatedUser: OAuthUserWithStripe = {
          ...user,
          updatedAt: Date.now(),
        }
        if (!isDeleted) {
          updatedUser.stripeSubscriptionId = subscription.id
          updatedUser.stripeSubscriptionStatus = subscription.status
        }
        await storage.saveUser(updatedUser)
        return { handled: true, action: `subscription_${event.type.split('.').pop()}` }
      }
      return { handled: true, action: 'subscription_event_no_user' }
    }

    case 'invoice.paid':
    case 'invoice.payment_failed': {
      // These can be used for additional billing logic
      // For now, just acknowledge them
      return { handled: true, action: event.type.replace('.', '_') }
    }

    default:
      return { handled: false }
  }
}

/**
 * Verify Stripe webhook signature
 */
export async function verifyStripeWebhook(payload: string, signature: string, webhookSecret: string, stripe: StripeClient): Promise<StripeWebhookEvent> {
  return stripe.webhooks.constructEvent(payload, signature, webhookSecret)
}

/**
 * Create a minimal Stripe client for Cloudflare Workers
 * (alternative to the full stripe npm package)
 */
export function createStripeClient(secretKey: string): StripeClient {
  const baseUrl = 'https://api.stripe.com/v1'

  async function stripeRequest<T>(method: 'GET' | 'POST', path: string, body?: Record<string, unknown>): Promise<T> {
    const headers: Record<string, string> = {
      Authorization: `Bearer ${secretKey}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    }

    const fetchOptions: RequestInit = {
      method,
      headers,
    }
    if (body) {
      fetchOptions.body = new URLSearchParams(flattenObject(body)).toString()
    }

    const response = await fetch(`${baseUrl}${path}`, fetchOptions)

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}))
      const errorMsg = isStripeApiError(errorData) ? errorData.error?.message : undefined
      throw new Error(`Stripe API error: ${errorMsg || response.statusText}`)
    }

    return response.json() as Promise<T>
  }

  return {
    customers: {
      create: (params) => stripeRequest('POST', '/customers', params),
      retrieve: (id) => stripeRequest('GET', `/customers/${id}`),
      update: (id, params) => stripeRequest('POST', `/customers/${id}`, params),
    },
    subscriptions: {
      retrieve: (id) => stripeRequest('GET', `/subscriptions/${id}`),
    },
    webhooks: {
      constructEvent: async (payload, signature, secret) => {
        const parsed = JSON.parse(payload)
        if (!isStripeWebhookEvent(parsed)) {
          throw new ValidationError('StripeWebhookEvent', 'invalid webhook payload', parsed)
        }
        const event = parsed

        // Parse the signature header
        const signatureHeader = parseStripeSignature(signature)

        // Check timestamp to prevent replay attacks (5 minute tolerance)
        const tolerance = 5 * 60
        const now = Math.floor(Date.now() / 1000)
        if (Math.abs(now - signatureHeader.timestamp) > tolerance) {
          throw new Error('Webhook timestamp too old')
        }

        // Verify HMAC-SHA256 signature
        const expectedSignature = await computeStripeSignature(signatureHeader.timestamp, payload, secret)

        if (!timingSafeEqual(signatureHeader.v1, expectedSignature)) {
          throw new Error('Invalid webhook signature')
        }

        return event
      },
    },
  }
}

/**
 * Flatten nested object for URL encoding
 */
function flattenObject(obj: Record<string, unknown>, prefix = ''): Record<string, string> {
  const result: Record<string, string> = {}

  for (const [key, value] of Object.entries(obj)) {
    const fullKey = prefix ? `${prefix}[${key}]` : key

    if (value === null || value === undefined) {
      continue
    } else if (typeof value === 'object' && !Array.isArray(value)) {
      Object.assign(result, flattenObject(value as Record<string, unknown>, fullKey))
    } else {
      result[fullKey] = String(value)
    }
  }

  return result
}

/**
 * Parse Stripe webhook signature header
 */
export function parseStripeSignature(header: string): { timestamp: number; v1: string } {
  const parts = header.split(',')
  let timestamp = 0
  let v1 = ''

  for (const part of parts) {
    const [key, value] = part.split('=')
    if (key === 't') {
      timestamp = parseInt(value!, 10)
    } else if (key === 'v1') {
      v1 = value!
    }
  }

  if (!timestamp || !v1) {
    throw new Error('Invalid webhook signature format')
  }

  return { timestamp, v1 }
}

/**
 * Compute expected Stripe webhook signature
 */
export async function computeStripeSignature(timestamp: number, payload: string, secret: string): Promise<string> {
  const signedPayload = `${timestamp}.${payload}`
  const encoder = new TextEncoder()

  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])

  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(signedPayload))

  return Array.from(new Uint8Array(signature))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

/**
 * Timing-safe string comparison
 */
export function timingSafeEqual(a: string, b: string): boolean {
  const maxLen = Math.max(a.length, b.length)
  let result = a.length ^ b.length
  for (let i = 0; i < maxLen; i++) {
    result |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0)
  }

  return result === 0
}

/**
 * Verify Stripe webhook with async signature verification
 * Use this for proper cryptographic verification
 */
export async function verifyStripeWebhookAsync(payload: string, signature: string, webhookSecret: string): Promise<StripeWebhookEvent> {
  const parsed = JSON.parse(payload)
  if (!isStripeWebhookEvent(parsed)) {
    throw new ValidationError('StripeWebhookEvent', 'invalid webhook payload', parsed)
  }
  const event = parsed

  // Parse and verify the signature
  const signatureHeader = parseStripeSignature(signature)
  const expectedSignature = await computeStripeSignature(signatureHeader.timestamp, payload, webhookSecret)

  if (!timingSafeEqual(signatureHeader.v1, expectedSignature)) {
    throw new Error('Invalid webhook signature')
  }

  // Check timestamp to prevent replay attacks (5 minute tolerance)
  const tolerance = 5 * 60
  const now = Math.floor(Date.now() / 1000)
  if (Math.abs(now - signatureHeader.timestamp) > tolerance) {
    throw new Error('Webhook timestamp too old')
  }

  return event
}
