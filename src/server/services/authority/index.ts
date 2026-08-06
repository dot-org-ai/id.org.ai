/**
 * Domain 11 — Authority. `grant · introspect · revoke · refuse`.
 *
 * See `types.ts` for the contract and the four load-bearing properties, and
 * `service.ts` for the enforcement. `act-chain.ts` is the RFC 8693 `act` claim
 * and the reason our ledger verifies what the specification leaves
 * informational.
 */

export * from './types'
export * from './act-chain'
export { AuthorityServiceImpl, MemoryActionSink, NON_RETROACTIVE_DISCLOSURE } from './service'
export type { AuthorityServiceConfig } from './service'
