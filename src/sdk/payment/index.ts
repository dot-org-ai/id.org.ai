/**
 * Payment domain — types and broker interface for the pay-per-call (x402 /
 * MPP) settlement layer. See ./types.ts for the wire-shape primitives and
 * ./broker.ts for the consumer-facing PaymentBroker.
 */
export type {
  PaymentProtocol,
  PaymentMethod,
  PaymentRail,
  PaymentInstrument,
  PaymentRequired,
  SessionRequired,
  RailQuote,
  PaymentReceipt,
  PaymentRejection,
  PaymentOutcome,
  PaymentSession,
  ContactChannel,
} from './types'

export type { PaymentBroker } from './broker'
