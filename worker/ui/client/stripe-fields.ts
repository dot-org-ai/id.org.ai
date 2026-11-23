/** Stripe's Payment Element mount for 19a: see lib/stripe-fields.ts. */
import { enhance } from './lib/dom'
import { initStripeFields } from './lib/stripe-fields'

enhance('stripe-fields', (el) => initStripeFields(el))
