import { describe, it, expect } from 'vitest'
import {
  createStripeClient,
  ensureStripeCustomer,
  getStripeCustomer,
  linkStripeCustomer,
  handleStripeWebhook,
  parseStripeSignature,
  computeStripeSignature,
  timingSafeEqual,
} from '../src/oauth/stripe'
import type {
  StripeCustomer,
  StripeSubscription,
  StripeWebhookEvent,
  StripeWebhookEventType,
  StripeStorage,
  OAuthUserWithStripe,
  StripeClient,
} from '../src/oauth/stripe'

describe('OAuth Stripe Identity Linkage', () => {
  describe('createStripeClient', () => {
    it('returns object with expected methods', () => {
      const client = createStripeClient('sk_test_fake')
      expect(client).toBeDefined()
      expect(client.customers).toBeDefined()
      expect(typeof client.customers.create).toBe('function')
      expect(typeof client.customers.retrieve).toBe('function')
      expect(typeof client.customers.update).toBe('function')
      expect(client.subscriptions).toBeDefined()
      expect(typeof client.subscriptions.retrieve).toBe('function')
      expect(client.webhooks).toBeDefined()
      expect(typeof client.webhooks.constructEvent).toBe('function')
    })
  })

  describe('parseStripeSignature', () => {
    it('parses valid signature header', () => {
      const result = parseStripeSignature('t=1234567890,v1=abc123def')
      expect(result.timestamp).toBe(1234567890)
      expect(result.v1).toBe('abc123def')
    })

    it('throws on invalid signature format', () => {
      expect(() => parseStripeSignature('invalid')).toThrow('Invalid webhook signature format')
    })

    it('throws when timestamp is missing', () => {
      expect(() => parseStripeSignature('v1=abc123')).toThrow('Invalid webhook signature format')
    })

    it('throws when v1 is missing', () => {
      expect(() => parseStripeSignature('t=1234567890')).toThrow('Invalid webhook signature format')
    })
  })

  describe('computeStripeSignature', () => {
    it('produces a hex string', async () => {
      const sig = await computeStripeSignature(1234567890, '{"test": true}', 'whsec_test')
      expect(typeof sig).toBe('string')
      expect(sig).toMatch(/^[0-9a-f]+$/)
    })

    it('produces deterministic output', async () => {
      const sig1 = await computeStripeSignature(1000, 'payload', 'secret')
      const sig2 = await computeStripeSignature(1000, 'payload', 'secret')
      expect(sig1).toBe(sig2)
    })

    it('different inputs produce different signatures', async () => {
      const sig1 = await computeStripeSignature(1000, 'payload1', 'secret')
      const sig2 = await computeStripeSignature(1000, 'payload2', 'secret')
      expect(sig1).not.toBe(sig2)
    })
  })

  describe('timingSafeEqual', () => {
    it('returns true for equal strings', () => {
      expect(timingSafeEqual('abc', 'abc')).toBe(true)
    })

    it('returns false for different strings', () => {
      expect(timingSafeEqual('abc', 'def')).toBe(false)
    })

    it('returns false for different lengths', () => {
      expect(timingSafeEqual('abc', 'abcd')).toBe(false)
    })

    it('returns true for empty strings', () => {
      expect(timingSafeEqual('', '')).toBe(true)
    })
  })

  describe('type exports are accessible', () => {
    it('StripeCustomer shape is correct', () => {
      const customer: StripeCustomer = {
        id: 'cus_test',
        email: 'test@example.com',
        name: 'Test User',
        metadata: { key: 'value' },
      }
      expect(customer.id).toBe('cus_test')
    })

    it('StripeSubscription shape is correct', () => {
      const sub: StripeSubscription = {
        id: 'sub_test',
        customerId: 'cus_test',
        status: 'active',
        priceId: 'price_test',
        currentPeriodEnd: 1234567890,
      }
      expect(sub.status).toBe('active')
    })

    it('OAuthUserWithStripe extends OAuthUser', () => {
      const user: OAuthUserWithStripe = {
        id: 'user_test',
        email: 'test@example.com',
        createdAt: Date.now(),
        updatedAt: Date.now(),
        stripeCustomerId: 'cus_test',
        stripeSubscriptionId: 'sub_test',
        stripeSubscriptionStatus: 'active',
      }
      expect(user.stripeCustomerId).toBe('cus_test')
    })

    it('StripeWebhookEventType is a valid string union', () => {
      const eventType: StripeWebhookEventType = 'customer.created'
      expect(eventType).toBe('customer.created')
    })
  })

  describe('ensureStripeCustomer', () => {
    function createMockStripe(): StripeClient {
      return {
        customers: {
          create: async () => ({ id: 'cus_new' }),
          retrieve: async () => ({ id: 'cus_new', email: null, name: null, metadata: {} }),
          update: async () => ({ id: 'cus_new', email: null, name: null, metadata: {} }),
        },
        subscriptions: {
          retrieve: async () => ({
            id: 'sub_1',
            customer: 'cus_1',
            status: 'active' as const,
            items: { data: [{ price: { id: 'price_1' } }] },
            current_period_end: 9999999999,
          }),
        },
        webhooks: {
          constructEvent: async () => ({ id: 'evt_1', type: 'customer.created' as const, data: { object: {} } }),
        },
      }
    }

    function createMockStorage(): StripeStorage {
      const users = new Map<string, OAuthUserWithStripe>()
      return {
        getUserByStripeCustomerId: async (stripeId) => {
          for (const u of users.values()) {
            if ((u as OAuthUserWithStripe).stripeCustomerId === stripeId) return u
          }
          return null
        },
        updateUserStripeCustomerId: async (userId, stripeId) => {
          const user = users.get(userId)
          if (user) {
            ;(user as OAuthUserWithStripe).stripeCustomerId = stripeId
          }
        },
        getUser: async (id) => users.get(id) ?? null,
        saveUser: async (user) => {
          users.set(user.id, user as OAuthUserWithStripe)
        },
      }
    }

    it('returns existing customer ID if already linked', async () => {
      const user: OAuthUserWithStripe = {
        id: 'user_1',
        email: 'test@example.com',
        createdAt: Date.now(),
        updatedAt: Date.now(),
        stripeCustomerId: 'cus_existing',
      }
      const result = await ensureStripeCustomer(user, createMockStripe(), createMockStorage())
      expect(result).toBe('cus_existing')
    })

    it('creates new customer if not linked', async () => {
      const user: OAuthUserWithStripe = {
        id: 'user_1',
        email: 'test@example.com',
        name: 'Test',
        createdAt: Date.now(),
        updatedAt: Date.now(),
      }
      const storage = createMockStorage()
      await storage.saveUser(user)
      const result = await ensureStripeCustomer(user, createMockStripe(), storage)
      expect(result).toBe('cus_new')
    })
  })

  describe('getStripeCustomer', () => {
    it('returns null when user has no stripeCustomerId', async () => {
      const user: OAuthUserWithStripe = {
        id: 'user_1',
        createdAt: Date.now(),
        updatedAt: Date.now(),
      }
      const stripe: StripeClient = {
        customers: {
          create: async () => ({ id: '' }),
          retrieve: async () => ({ id: '', email: null, name: null, metadata: {} }),
          update: async () => ({ id: '', email: null, name: null, metadata: {} }),
        },
        subscriptions: { retrieve: async () => ({ id: '', customer: '', status: 'active' as const, items: { data: [] }, current_period_end: 0 }) },
        webhooks: { constructEvent: async () => ({ id: '', type: 'customer.created' as const, data: { object: {} } }) },
      }
      const result = await getStripeCustomer(user, stripe)
      expect(result).toBeNull()
    })
  })

  describe('handleStripeWebhook', () => {
    function createMockStorage(): StripeStorage & { users: Map<string, OAuthUserWithStripe> } {
      const users = new Map<string, OAuthUserWithStripe>()
      return {
        users,
        getUserByStripeCustomerId: async (stripeId) => {
          for (const u of users.values()) {
            if (u.stripeCustomerId === stripeId) return u
          }
          return null
        },
        updateUserStripeCustomerId: async (userId, stripeId) => {
          const user = users.get(userId)
          if (user) {
            user.stripeCustomerId = stripeId
          }
        },
        getUser: async (id) => users.get(id) ?? null,
        saveUser: async (user) => {
          users.set(user.id, user as OAuthUserWithStripe)
        },
      }
    }

    it('handles customer.created with userId in metadata', async () => {
      const storage = createMockStorage()
      storage.users.set('user_1', {
        id: 'user_1',
        createdAt: Date.now(),
        updatedAt: Date.now(),
      })

      const event: StripeWebhookEvent = {
        id: 'evt_1',
        type: 'customer.created',
        data: {
          object: { id: 'cus_1', metadata: { userId: 'user_1' } },
        },
      }

      const result = await handleStripeWebhook(event, storage)
      expect(result.handled).toBe(true)
      expect(result.action).toBe('linked_customer')
    })

    it('handles invoice.paid event', async () => {
      const storage = createMockStorage()
      const event: StripeWebhookEvent = {
        id: 'evt_1',
        type: 'invoice.paid',
        data: { object: {} },
      }

      const result = await handleStripeWebhook(event, storage)
      expect(result.handled).toBe(true)
      expect(result.action).toBe('invoice_paid')
    })
  })
})
